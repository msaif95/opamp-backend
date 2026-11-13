package alert

import (
	"context"
	"encoding/json"

	"github.com/redis/go-redis/v9"
)

const (
	storeKey = "opamp:alerts"
	storeMax = 100
)

// Store keeps the most recent alerts in Redis for display in the console.
// It is a convenience view, not a durable record: the audit log is.
type Store struct{ rdb *redis.Client }

// NewStore creates a Store.
func NewStore(rdb *redis.Client) *Store { return &Store{rdb: rdb} }

// Add records an alert, dropping the oldest beyond the cap.
func (s *Store) Add(ctx context.Context, a Alert) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	pipe := s.rdb.TxPipeline()
	pipe.LPush(ctx, storeKey, b)
	pipe.LTrim(ctx, storeKey, 0, storeMax-1)
	_, err = pipe.Exec(ctx)
	return err
}

// List returns the recorded alerts, newest first.
func (s *Store) List(ctx context.Context) ([]Alert, error) {
	vals, err := s.rdb.LRange(ctx, storeKey, 0, storeMax-1).Result()
	if err != nil {
		return nil, err
	}
	alerts := make([]Alert, 0, len(vals))
	for _, v := range vals {
		var a Alert
		if json.Unmarshal([]byte(v), &a) == nil {
			alerts = append(alerts, a)
		}
	}
	return alerts, nil
}
