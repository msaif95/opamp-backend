package ratelimit

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/msaif95/opamp-backend/internal/testdb"
)

func TestDecide(t *testing.T) {
	for _, tc := range []struct {
		name      string
		prev, cur int64
		elapsed   float64
		limit     int
		allowed   bool
		remaining int
		retry     time.Duration
	}{
		{"first request", 0, 1, 0.5, 10, true, 9, 0},
		{"exactly at the limit", 0, 10, 0.5, 10, true, 0, 0},
		{"one over", 0, 11, 0.5, 10, false, 0, 30 * time.Second},
		{"previous window still counts early on", 10, 1, 0.0, 10, false, 0, 6 * time.Second},
		{"previous window has faded", 10, 1, 0.95, 10, true, 8, 0},
		{"half of the previous window counts", 10, 5, 0.5, 10, true, 0, 0},
		{"waits only until enough of the previous window fades", 10, 6, 0.5, 10, false, 0, 6 * time.Second},
		{"never less than a second", 100, 1, 0.999, 1, false, 0, time.Second},
	} {
		d := decide(tc.prev, tc.cur, tc.elapsed, tc.limit)
		if d.Allowed != tc.allowed || d.Remaining != tc.remaining || d.RetryAfter != tc.retry || d.Limit != tc.limit {
			t.Errorf("%s: got %+v, want allowed=%v remaining=%d retry=%v", tc.name, d, tc.allowed, tc.remaining, tc.retry)
		}
	}
}

func TestMiddleware(t *testing.T) {
	_, rdb := testdb.Open(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	l := New(rdb, 5, 2, log)
	// A fixed instant early in a window, so the test never straddles two windows.
	at := time.Unix(1_800_000_000, 0).Truncate(time.Minute).Add(10 * time.Second)
	l.now = func() time.Time { return at }
	on := true
	l.Enabled = func() bool { return on }
	// "vip" has its own budgets: three changes a minute and no limit on requests.
	three, unlimited := 3, 0
	h := l.Middleware(func(r *http.Request) Caller {
		if c := r.Header.Get("X-Caller"); c == "vip" {
			return Caller{Key: c, Requests: &unlimited, Writes: &three}
		} else {
			return Caller{Key: c}
		}
	})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	call := func(method, caller string) *http.Response {
		req := httptest.NewRequest(method, "/x", nil)
		req.Header.Set("X-Caller", caller)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Result()
	}

	// Writes run out first; reads are still served, and both count against the request budget.
	for i, want := range []int{204, 204, 429} {
		if got := call("POST", "alice").StatusCode; got != want {
			t.Fatalf("write %d: HTTP %d, want %d", i+1, got, want)
		}
	}
	res := call("GET", "alice")
	if res.StatusCode != 204 || res.Header.Get("RateLimit-Limit") != "5" || res.Header.Get("RateLimit-Remaining") != "1" {
		t.Errorf("read after writes: HTTP %d, headers %v", res.StatusCode, res.Header)
	}
	call("GET", "alice")
	res = call("GET", "alice")
	if res.StatusCode != 429 || res.Header.Get("Retry-After") != "50" || res.Header.Get("RateLimit-Remaining") != "0" {
		t.Errorf("read over the budget: HTTP %d, headers %v", res.StatusCode, res.Header)
	}
	if body, _ := io.ReadAll(res.Body); len(body) == 0 || body[0] != '{' {
		t.Errorf("refusal body = %q", body)
	}

	// Budgets are per caller, callers without an identity are not counted, and the switch turns it all off.
	if got := call("POST", "bob").StatusCode; got != 204 {
		t.Errorf("another caller: HTTP %d", got)
	}
	for range 10 {
		if got := call("GET", "").StatusCode; got != 204 {
			t.Fatalf("no identity: HTTP %d", got)
		}
	}
	for i, want := range []int{204, 204, 204, 429} {
		if res := call("POST", "vip"); res.StatusCode != want || res.Header.Get("RateLimit-Limit") != "3" {
			t.Fatalf("vip write %d: HTTP %d (limit %s), want %d", i+1, res.StatusCode, res.Header.Get("RateLimit-Limit"), want)
		}
	}
	for range 20 {
		if res := call("GET", "vip"); res.StatusCode != 204 || res.Header.Get("RateLimit-Limit") != "" {
			t.Fatalf("vip read with no request limit: HTTP %d, headers %v", res.StatusCode, res.Header)
		}
	}
	on = false
	if got := call("POST", "alice").StatusCode; got != 204 {
		t.Errorf("switched off: HTTP %d", got)
	}
	on = true

	// A minute and a half later the budget is back.
	at = at.Add(90 * time.Second)
	if got := call("GET", "alice").StatusCode; got != 204 {
		t.Errorf("after the window: HTTP %d", got)
	}

	// A nil limiter (not configured) passes everything through.
	var none *Limiter
	rec := httptest.NewRecorder()
	none.Middleware(func(*http.Request) Caller { return Caller{Key: "x"} })(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })).
		ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 204 {
		t.Errorf("nil limiter: HTTP %d", rec.Code)
	}
}
