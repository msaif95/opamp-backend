// Package events fans agent change notifications from Redis pub/sub out to
// UI clients over Server-Sent Events, so any replica can serve any UI session.
package events

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	subscriberBuffer = 256
	keepAlive        = 20 * time.Second
)

// Hub relays messages from one Redis channel to many SSE subscribers.
type Hub struct {
	log    *slog.Logger
	mu     sync.Mutex
	subs   map[chan string]struct{}
	closed bool
}

// NewHub creates a Hub.
func NewHub(log *slog.Logger) *Hub {
	return &Hub{log: log, subs: make(map[chan string]struct{})}
}

// Run subscribes to channel and relays until ctx is cancelled.
func (h *Hub) Run(ctx context.Context, rdb *redis.Client, channel string) {
	sub := rdb.Subscribe(ctx, channel)
	defer sub.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-sub.Channel():
			if !ok {
				return
			}
			h.broadcast(msg.Payload)
		}
	}
}

// Close ends every open event stream and refuses new ones. Streams never
// finish on their own, so a graceful HTTP shutdown would otherwise wait for
// them until its deadline.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for ch := range h.subs {
		delete(h.subs, ch)
		close(ch)
	}
}

func (h *Hub) broadcast(payload string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- payload:
		default:
			// Slow consumer: drop it rather than block the fleet's event stream.
			// The client reconnects and refetches.
			delete(h.subs, ch)
			close(ch)
		}
	}
}

func (h *Hub) subscribe() chan string {
	ch := make(chan string, subscriberBuffer)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		close(ch)
	} else {
		h.subs[ch] = struct{}{}
	}
	return ch
}

func (h *Hub) unsubscribe(ch chan string) {
	h.mu.Lock()
	if _, ok := h.subs[ch]; ok {
		delete(h.subs, ch)
		close(ch)
	}
	h.mu.Unlock()
}

// ServeHTTP streams events to one client as text/event-stream.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		h.log.Error("sse unsupported by response writer", "err", err)
		return
	}

	ch := h.subscribe()
	defer h.unsubscribe(ch)
	tick := time.NewTicker(keepAlive)
	defer tick.Stop()

	for {
		var err error
		select {
		case <-r.Context().Done():
			return
		case payload, ok := <-ch:
			if !ok {
				return
			}
			_, err = fmt.Fprintf(w, "data: %s\n\n", payload)
		case <-tick.C:
			_, err = fmt.Fprint(w, ": keepalive\n\n")
		}
		if err != nil || rc.Flush() != nil {
			return
		}
	}
}
