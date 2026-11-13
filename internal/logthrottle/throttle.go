// Package logthrottle keeps repeated log lines from flooding the output
// during an outage, when every agent message can fail the same way.
package logthrottle

import (
	"sync/atomic"
	"time"
)

// Throttle lets one call through per interval and counts the rest.
type Throttle struct {
	every      time.Duration
	last       atomic.Int64
	suppressed atomic.Int64
}

// New creates a Throttle that allows one call per interval.
func New(every time.Duration) *Throttle { return &Throttle{every: every} }

// Do runs fn at most once per interval. fn receives the number of calls
// suppressed since it last ran, so the log line can say how much was hidden.
func (t *Throttle) Do(fn func(suppressed int64)) {
	now := time.Now().UnixNano()
	last := t.last.Load()
	if now-last < int64(t.every) || !t.last.CompareAndSwap(last, now) {
		t.suppressed.Add(1)
		return
	}
	fn(t.suppressed.Swap(0))
}
