// Package ownlogs receives collectors' own logs (OpAMP "own logs") over
// OTLP/HTTP and keeps the most recent lines per collector for the console.
// It is a troubleshooting aid, not a log store: a few hundred lines per
// collector, for a day, in Redis.
package ownlogs

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/redis/go-redis/v9"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"
)

const (
	// IntakePath is served on the agent listener, next to the OpAMP endpoint.
	IntakePath = "/v1/logs"

	keyPrefix = "opamp:own-logs:"
	// Keep is how many lines are kept per collector, and TTL for how long
	// after the last line arrived.
	Keep        = 500
	TTL         = 24 * time.Hour
	maxBody     = 4 << 20
	maxLineLen  = 2000
	maxAttrs    = 12
	maxAttrSize = 300
)

// Line is one log record from a collector.
type Line struct {
	At time.Time `json:"at"`
	// Severity is debug, info, warn or error.
	Severity string `json:"severity"`
	Message  string `json:"message"`
	// Attributes are the record's fields, such as the component that logged it.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Service is the intake and the reader.
type Service struct {
	rdb      *redis.Client
	key      []byte
	endpoint string
	// Redact, if set, hides secret values in text before it is stored.
	Redact func(ctx context.Context, uid uuid.UUID, text string) (string, error)
}

// New creates a Service. agentEndpointURL is the public OpAMP URL
// (ws[s]://host/v1/opamp); the intake lives on the same host and port. An
// empty URL means collectors are not asked to send logs.
func New(rdb *redis.Client, signingKey []byte, agentEndpointURL string) *Service {
	s := &Service{rdb: rdb, key: signingKey}
	if u, err := url.Parse(agentEndpointURL); err == nil && (u.Scheme == "ws" || u.Scheme == "wss") {
		s.endpoint = "http" + strings.TrimPrefix(u.Scheme, "ws") + "://" + u.Host + IntakePath
	}
	return s
}

// token proves the backend told this agent to report, without storing anything per agent.
func (s *Service) token(uid uuid.UUID) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("own-logs:" + uid.String()))
	return uid.String() + "." + hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) verify(token string) (uuid.UUID, bool) {
	id, _, ok := strings.Cut(token, ".")
	uid, err := uuid.Parse(id)
	if !ok || err != nil || !hmac.Equal([]byte(token), []byte(s.token(uid))) {
		return uuid.Nil, false
	}
	return uid, true
}

// Settings tells an agent where to send its own logs, or nil when the intake has no public address.
func (s *Service) Settings(uid uuid.UUID) *protobufs.TelemetryConnectionSettings {
	if s.endpoint == "" {
		return nil
	}
	return &protobufs.TelemetryConnectionSettings{
		DestinationEndpoint: s.endpoint,
		Headers:             &protobufs.Headers{Headers: []*protobufs.Header{{Key: "Authorization", Value: "Bearer " + s.token(uid)}}},
	}
}

// ServeHTTP is the OTLP/HTTP logs intake.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	uid, ok := s.verify(token)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var body io.Reader = http.MaxBytesReader(w, r.Body, maxBody)
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer zr.Close()
		body = io.LimitReader(zr, maxBody)
	}
	raw, err := io.ReadAll(body)
	var req collectorlogs.ExportLogsServiceRequest
	if err != nil || proto.Unmarshal(raw, &req) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store(r.Context(), uid, extract(&req, time.Now().UTC())); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	// An empty ExportLogsServiceResponse.
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
}

func severity(number int32, text string) string {
	switch {
	case number >= 17:
		return "error"
	case number >= 13:
		return "warn"
	case number >= 9:
		return "info"
	case number >= 1:
		return "debug"
	}
	switch t := strings.ToLower(text); {
	case strings.HasPrefix(t, "err"), t == "fatal", t == "panic", t == "dpanic":
		return "error"
	case strings.HasPrefix(t, "warn"):
		return "warn"
	case t == "debug", t == "trace":
		return "debug"
	}
	return "info"
}

func text(v *commonpb.AnyValue) string {
	if v == nil {
		return ""
	}
	if s, ok := v.Value.(*commonpb.AnyValue_StringValue); ok {
		return s.StringValue
	}
	// Numbers, booleans, lists and maps: their protobuf text form is readable enough.
	b, _ := json.Marshal(anyToGo(v))
	return string(b)
}

func anyToGo(v *commonpb.AnyValue) any {
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_BoolValue:
		return x.BoolValue
	case *commonpb.AnyValue_IntValue:
		return x.IntValue
	case *commonpb.AnyValue_DoubleValue:
		return x.DoubleValue
	case *commonpb.AnyValue_ArrayValue:
		out := []any{}
		for _, e := range x.ArrayValue.GetValues() {
			out = append(out, anyToGo(e))
		}
		return out
	case *commonpb.AnyValue_KvlistValue:
		out := map[string]any{}
		for _, kv := range x.KvlistValue.GetValues() {
			out[kv.Key] = anyToGo(kv.Value)
		}
		return out
	}
	return nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// extract flattens a request into lines, oldest first.
func extract(req *collectorlogs.ExportLogsServiceRequest, now time.Time) []Line {
	var lines []Line
	for _, rl := range req.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			for _, rec := range sl.LogRecords {
				at := now
				if ns := rec.TimeUnixNano; ns != 0 {
					at = time.Unix(0, int64(ns)).UTC()
				} else if ns := rec.ObservedTimeUnixNano; ns != 0 {
					at = time.Unix(0, int64(ns)).UTC()
				}
				l := Line{At: at, Severity: severity(int32(rec.SeverityNumber), rec.SeverityText), Message: clip(text(rec.Body), maxLineLen)}
				for i, kv := range rec.Attributes {
					if i == maxAttrs {
						break
					}
					if l.Attributes == nil {
						l.Attributes = map[string]string{}
					}
					l.Attributes[kv.Key] = clip(text(kv.Value), maxAttrSize)
				}
				lines = append(lines, l)
			}
		}
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].At.Before(lines[j].At) })
	return lines
}

func (s *Service) store(ctx context.Context, uid uuid.UUID, lines []Line) error {
	if len(lines) == 0 {
		return nil
	}
	if len(lines) > Keep {
		lines = lines[len(lines)-Keep:]
	}
	encoded := make([]string, len(lines))
	for i, l := range lines {
		b, _ := json.Marshal(l)
		encoded[i] = string(b)
	}
	if s.Redact != nil {
		// One pass over the whole batch: lines are JSON, so a newline never occurs inside one.
		clean, err := s.Redact(ctx, uid, strings.Join(encoded, "\n"))
		if err != nil {
			return fmt.Errorf("hide secrets in logs: %w", err)
		}
		encoded = strings.Split(clean, "\n")
	}
	values := make([]any, len(encoded))
	for i, e := range encoded {
		values[i] = e
	}
	key := keyPrefix + uid.String()
	pipe := s.rdb.TxPipeline()
	pipe.RPush(ctx, key, values...)
	pipe.LTrim(ctx, key, -Keep, -1)
	pipe.Expire(ctx, key, TTL)
	_, err := pipe.Exec(ctx)
	return err
}

// Recent returns up to limit of a collector's most recent lines, newest first.
func (s *Service) Recent(ctx context.Context, uid uuid.UUID, limit int) ([]Line, error) {
	if limit <= 0 || limit > Keep {
		limit = Keep
	}
	raw, err := s.rdb.LRange(ctx, keyPrefix+uid.String(), int64(-limit), -1).Result()
	if err != nil {
		return nil, err
	}
	lines := make([]Line, 0, len(raw))
	for i := len(raw) - 1; i >= 0; i-- {
		var l Line
		if json.Unmarshal([]byte(raw[i]), &l) == nil {
			lines = append(lines, l)
		}
	}
	return lines, nil
}
