package auth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	maxLoginFailures   = 10
	loginFailureWindow = 5 * time.Minute
	loginFailPrefix    = "opamp:login-fail:"
)

// LoginLimiter slows password guessing against the local admin login. It
// counts failures per client address in Redis, so the limit holds across replicas.
type LoginLimiter struct{ rdb *redis.Client }

// NewLoginLimiter creates a LoginLimiter.
func NewLoginLimiter(rdb *redis.Client) *LoginLimiter { return &LoginLimiter{rdb: rdb} }

// Blocked returns how long the client must wait, or 0 if it may try. If
// Redis is unavailable it allows the attempt: the local login is the
// break-glass path and must keep working during an outage.
func (l *LoginLimiter) Blocked(ctx context.Context, client string) time.Duration {
	n, err := l.rdb.Get(ctx, loginFailPrefix+client).Int()
	if err != nil || n < maxLoginFailures {
		return 0
	}
	ttl, err := l.rdb.TTL(ctx, loginFailPrefix+client).Result()
	if err != nil || ttl <= 0 {
		return 0
	}
	return ttl
}

// Fail records a failed attempt. The window starts at the first failure.
func (l *LoginLimiter) Fail(ctx context.Context, client string) {
	pipe := l.rdb.TxPipeline()
	pipe.Incr(ctx, loginFailPrefix+client)
	pipe.ExpireNX(ctx, loginFailPrefix+client, loginFailureWindow)
	_, _ = pipe.Exec(ctx)
}
