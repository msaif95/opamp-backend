// Package ratelimit throttles the console API per caller. Counts live in
// Redis, so a caller's budget is shared by every replica.
package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/msaif95/opamp-backend/internal/logthrottle"
)

const (
	window    = time.Minute
	keyPrefix = "opamp:ratelimit:"
)

// Decision is the outcome for one request.
type Decision struct {
	Allowed bool
	// Limit is the budget per minute, Remaining what is left of it.
	Limit, Remaining int
	// RetryAfter is how long a refused caller should wait.
	RetryAfter time.Duration
}

// decide judges a request against a sliding one-minute window, estimated
// from two fixed windows: the count in the current one (this request
// included) plus the share of the previous one that still falls inside
// the last minute. elapsed is how far into the current window we are, 0..1.
func decide(prev, cur int64, elapsed float64, limit int) Decision {
	used := float64(prev)*(1-elapsed) + float64(cur)
	d := Decision{Limit: limit, Remaining: max(0, limit-int(math.Ceil(used)))}
	if used <= float64(limit) {
		d.Allowed = true
		return d
	}
	// Room appears as the previous window's share fades, or at the latest when the current window ends.
	wait := 1 - elapsed
	if prev > 0 {
		if need := (used - float64(limit)) / float64(prev); need < wait {
			wait = need
		}
	}
	// The small allowance keeps a wait of exactly n seconds from being rounded up to n+1.
	d.RetryAfter = max(time.Second, time.Duration(math.Ceil(wait*window.Seconds()-1e-6))*time.Second)
	return d
}

// Limiter enforces per-caller budgets: one for all requests and a smaller
// one for requests that change something. A budget of 0 is not enforced.
type Limiter struct {
	rdb *redis.Client
	// Requests and Writes are the budgets per caller per minute.
	Requests, Writes int
	// Enabled is the runtime switch; nil means on.
	Enabled func() bool
	Log     *slog.Logger

	redisDown *logthrottle.Throttle
	refused   *logthrottle.Throttle
	now       func() time.Time
}

// New creates a Limiter.
func New(rdb *redis.Client, requests, writes int, log *slog.Logger) *Limiter {
	return &Limiter{rdb: rdb, Requests: requests, Writes: writes, Log: log,
		redisDown: logthrottle.New(time.Minute), refused: logthrottle.New(time.Minute), now: time.Now}
}

// Allow counts one request for caller against the named budget. Refused
// requests count too, so hammering a spent budget does not win it back. If Redis
// cannot be reached the request is allowed: throttling is a protection,
// and losing it must not take the console down with Redis.
func (l *Limiter) Allow(ctx context.Context, budget, caller string, limit int) Decision {
	now := l.now()
	n := now.UnixNano() / int64(window)
	elapsed := float64(now.UnixNano()%int64(window)) / float64(window)
	base := keyPrefix + budget + ":" + caller + ":"
	curKey, prevKey := base+strconv.FormatInt(n, 10), base+strconv.FormatInt(n-1, 10)

	pipe := l.rdb.Pipeline()
	cur := pipe.Incr(ctx, curKey)
	pipe.Expire(ctx, curKey, 2*window)
	prev := pipe.Get(ctx, prevKey)
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		l.redisDown.Do(func(suppressed int64) {
			l.Log.WarnContext(ctx, "rate limit not enforced: Redis unavailable", "err", err, "suppressed", suppressed)
		})
		return Decision{Allowed: true, Limit: limit, Remaining: limit}
	}
	p, _ := prev.Int64()
	return decide(p, cur.Val(), elapsed, limit)
}

// Caller is who a request is counted against.
type Caller struct {
	// Key identifies the caller; requests with an empty key are not counted.
	Key string
	// Requests and Writes are the caller's own budgets, where it has any:
	// nil uses the limiter's, 0 means no limit.
	Requests, Writes *int
}

func budget(own *int, def int) int {
	if own != nil {
		return *own
	}
	return def
}

// Middleware throttles requests by the caller that identity returns. It
// must run after authentication. Reads count against the request budget;
// anything else also counts against the write budget. Responses carry
// RateLimit-* headers, and a refusal is a 429 with Retry-After.
func (l *Limiter) Middleware(identity func(*http.Request) Caller) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			who := identity(r)
			caller := who.Key
			if l == nil || caller == "" || (l.Enabled != nil && !l.Enabled()) {
				next.ServeHTTP(w, r)
				return
			}
			write := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
			var (
				shown *Decision
				what  = "requests"
			)
			for _, b := range []struct {
				name  string
				limit int
				on    bool
			}{{"req", budget(who.Requests, l.Requests), true}, {"write", budget(who.Writes, l.Writes), write}} {
				if !b.on || b.limit <= 0 {
					continue
				}
				d := l.Allow(r.Context(), b.name, caller, b.limit)
				// Report the budget that is closest to running out.
				if shown == nil || !d.Allowed || d.Remaining < shown.Remaining {
					shown = &d
				}
				if !d.Allowed {
					if b.name == "write" {
						what = "changes"
					}
					break
				}
			}
			if shown == nil {
				next.ServeHTTP(w, r)
				return
			}
			h := w.Header()
			h.Set("RateLimit-Limit", strconv.Itoa(shown.Limit))
			h.Set("RateLimit-Remaining", strconv.Itoa(shown.Remaining))
			if shown.Allowed {
				next.ServeHTTP(w, r)
				return
			}
			secs := int(shown.RetryAfter.Seconds())
			h.Set("Retry-After", strconv.Itoa(secs))
			h.Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, `{"error":"too many requests: this account is limited to %d %s a minute; try again in %d seconds"}`+"\n",
				shown.Limit, what, secs)
			l.refused.Do(func(suppressed int64) {
				l.Log.WarnContext(r.Context(), "api request refused by rate limit", "caller", caller, "limit", shown.Limit, "path", r.URL.Path, "suppressed", suppressed)
			})
		})
	}
}
