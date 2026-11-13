// Package alert sends operational notifications to a webhook. The payload
// is {"text": "..."}, which Slack incoming webhooks accept as is.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const queueSize = 100

// Delivery outcomes recorded for an alert.
const (
	DeliverySent          = "sent"
	DeliveryFailed        = "failed"
	DeliveryNotConfigured = "not_configured"
	// DeliveryDisabled means an administrator switched alert delivery off.
	DeliveryDisabled = "disabled"
)

// Alert is one notification and what became of it.
type Alert struct {
	At       time.Time `json:"at"`
	Text     string    `json:"text"`
	Delivery string    `json:"delivery"`
}

// Webhook delivers notifications asynchronously so a slow or failing
// webhook never holds up the caller.
type Webhook struct {
	url    string
	client *http.Client
	log    *slog.Logger
	queue  chan string

	// Record, if set, is called with every alert after its delivery
	// attempt, including when no webhook is configured, so alerts stay
	// visible in the console either way.
	Record func(ctx context.Context, a Alert)
	// Enabled, if set, is consulted before each delivery; false skips the
	// webhook (the alert is still recorded).
	Enabled func() bool
}

// Configured reports whether alerts are delivered to a webhook.
func (w *Webhook) Configured() bool { return w.url != "" }

// NewWebhook creates a Webhook. With an empty url alerts are recorded but not delivered.
func NewWebhook(url string, log *slog.Logger) *Webhook {
	return &Webhook{url: url, log: log, client: &http.Client{Timeout: 10 * time.Second}, queue: make(chan string, queueSize)}
}

// Notify queues a message. It never blocks; if the queue is full the
// message is dropped and logged.
func (w *Webhook) Notify(text string) {
	select {
	case w.queue <- text:
	default:
		w.log.Warn("alert queue full; notification dropped", "text", text)
	}
}

// Run delivers queued messages until ctx is cancelled.
func (w *Webhook) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case text := <-w.queue:
			a := Alert{At: time.Now().UTC(), Text: text, Delivery: DeliveryNotConfigured}
			if w.Configured() && w.Enabled != nil && !w.Enabled() {
				a.Delivery = DeliveryDisabled
			} else if w.Configured() {
				a.Delivery = DeliverySent
				if err := w.send(ctx, text); err != nil {
					w.log.Error("alert delivery failed", "err", err, "text", text)
					a.Delivery = DeliveryFailed
				}
			}
			if w.Record != nil {
				w.Record(ctx, a)
			}
		}
	}
}

func (w *Webhook) send(ctx context.Context, text string) error {
	body, _ := json.Marshal(map[string]string{"text": text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}
