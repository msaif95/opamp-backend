package alert

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebhookDeliversSlackCompatiblePayload(t *testing.T) {
	got := make(chan map[string]string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		got <- body
	}))
	defer srv.Close()

	w := NewWebhook(srv.URL, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	w.Notify("rollout paused")

	select {
	case body := <-got:
		if body["text"] != "rollout paused" {
			t.Fatalf("payload = %v", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("webhook not called")
	}
}

func TestAlertsAreRecordedWithDeliveryOutcome(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()
	ok := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ok.Close()

	for url, want := range map[string]string{"": DeliveryNotConfigured, failing.URL: DeliveryFailed, ok.URL: DeliverySent} {
		w := NewWebhook(url, slog.New(slog.NewTextHandler(io.Discard, nil)))
		recorded := make(chan Alert, 1)
		w.Record = func(_ context.Context, a Alert) { recorded <- a }
		ctx, cancel := context.WithCancel(context.Background())
		go w.Run(ctx)
		w.Notify("push paused")
		select {
		case a := <-recorded:
			if a.Delivery != want || a.Text != "push paused" || a.At.IsZero() {
				t.Errorf("url %q: recorded %+v, want delivery %q", url, a, want)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("url %q: alert not recorded", url)
		}
		cancel()
	}
}

func TestFullQueueNeverBlocks(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	w := NewWebhook("http://127.0.0.1:1", log) // nothing is draining the queue
	done := make(chan struct{})
	go func() {
		for range queueSize + 10 {
			w.Notify("x")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Notify blocked on a full queue")
	}
}
