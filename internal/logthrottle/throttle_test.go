package logthrottle

import (
	"testing"
	"time"
)

func TestThrottle(t *testing.T) {
	th := New(50 * time.Millisecond)
	var ran int
	var lastSuppressed int64
	for range 100 {
		th.Do(func(s int64) { ran++; lastSuppressed = s })
	}
	if ran != 1 || lastSuppressed != 0 {
		t.Fatalf("burst: ran %d times (suppressed %d), want once", ran, lastSuppressed)
	}
	time.Sleep(60 * time.Millisecond)
	th.Do(func(s int64) { ran++; lastSuppressed = s })
	if ran != 2 || lastSuppressed != 99 {
		t.Fatalf("after interval: ran %d, suppressed %d, want 2 and 99", ran, lastSuppressed)
	}
}
