package auth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// SessionStore tracks live console sessions so they can expire when idle
// and be ended before their token runs out.
type SessionStore interface {
	// Start records a new session for subject.
	Start(ctx context.Context, id, subject string, idle time.Duration) error
	// Touch reports whether the session is still live and, if so, restarts its idle timer.
	Touch(ctx context.Context, id string, idle time.Duration) (bool, error)
	// End ends one session.
	End(ctx context.Context, id string) error
	// EndAll ends every session of subject and returns how many there were.
	EndAll(ctx context.Context, subject string) (int, error)
}

const (
	sessionKey     = "opamp:session:"
	subjectSessKey = "opamp:sessions-of:"
)

// RedisSessions is a SessionStore in Redis, shared by all replicas.
type RedisSessions struct{ rdb *redis.Client }

// NewRedisSessions creates a RedisSessions.
func NewRedisSessions(rdb *redis.Client) *RedisSessions { return &RedisSessions{rdb: rdb} }

func (r *RedisSessions) Start(ctx context.Context, id, subject string, idle time.Duration) error {
	pipe := r.rdb.TxPipeline()
	pipe.Set(ctx, sessionKey+id, subject, idle)
	pipe.SAdd(ctx, subjectSessKey+subject, id)
	// The index only needs to outlive the longest possible session.
	pipe.Expire(ctx, subjectSessKey+subject, 24*time.Hour)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisSessions) Touch(ctx context.Context, id string, idle time.Duration) (bool, error) {
	return r.rdb.Expire(ctx, sessionKey+id, idle).Result()
}

func (r *RedisSessions) End(ctx context.Context, id string) error {
	return r.rdb.Del(ctx, sessionKey+id).Err()
}

func (r *RedisSessions) EndAll(ctx context.Context, subject string) (int, error) {
	ids, err := r.rdb.SMembers(ctx, subjectSessKey+subject).Result()
	if err != nil {
		return 0, err
	}
	keys := []string{subjectSessKey + subject}
	for _, id := range ids {
		keys = append(keys, sessionKey+id)
	}
	n, err := r.rdb.Del(ctx, keys...).Result()
	if n > 0 {
		n-- // the index itself
	}
	return int(n), err
}
