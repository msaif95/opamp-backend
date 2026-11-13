// Package owntraces receives the traces collectors produce about their own
// work (OpAMP "own traces") over OTLP/HTTP. It keeps the most recent spans
// per collector for the console and, if configured, forwards every request
// unchanged to a tracing backend. Like the logs intake it is a
// troubleshooting view, not a trace store.
package owntraces

import (
	"bytes"
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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/redis/go-redis/v9"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

const (
	// IntakePath is served on the agent listener, next to the OpAMP endpoint.
	IntakePath = "/v1/traces"

	keyPrefix = "opamp:own-traces:"
	// Keep is how many spans are kept per collector, and TTL for how long
	// after the last one arrived.
	Keep        = 300
	TTL         = 24 * time.Hour
	maxBody     = 4 << 20
	maxAttrs    = 12
	maxAttrSize = 300
)

// Span is one span from a collector.
type Span struct {
	TraceID  string    `json:"trace_id"`
	SpanID   string    `json:"span_id"`
	ParentID string    `json:"parent_id,omitempty"`
	Name     string    `json:"name"`
	Scope    string    `json:"scope,omitempty"`
	Kind     string    `json:"kind,omitempty"`
	Start    time.Time `json:"start"`
	// DurationMS is how long the span took, in milliseconds.
	DurationMS float64 `json:"duration_ms"`
	// Status is ok, error or unset.
	Status        string            `json:"status"`
	StatusMessage string            `json:"status_message,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

// Service is the intake and the reader.
type Service struct {
	rdb      *redis.Client
	key      []byte
	endpoint string
	// Redact, if set, hides secret values in text before it is stored.
	Redact func(ctx context.Context, uid uuid.UUID, text string) (string, error)
	// Forward, if set, is handed every accepted request exactly as received
	// (body and its Content-Encoding) to pass on to a tracing backend. It
	// must not block.
	Forward func(contentEncoding string, body []byte)
}

// New creates a Service. agentEndpointURL is the public OpAMP URL
// (ws[s]://host/v1/opamp); the intake lives on the same host and port. An
// empty URL means collectors are not asked to send traces.
func New(rdb *redis.Client, signingKey []byte, agentEndpointURL string) *Service {
	s := &Service{rdb: rdb, key: signingKey}
	if u, err := url.Parse(agentEndpointURL); err == nil && (u.Scheme == "ws" || u.Scheme == "wss") {
		s.endpoint = "http" + strings.TrimPrefix(u.Scheme, "ws") + "://" + u.Host + IntakePath
	}
	return s
}

func (s *Service) token(uid uuid.UUID) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("own-traces:" + uid.String()))
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

// Settings tells an agent where to send its own traces, or nil when the intake has no public address.
func (s *Service) Settings(uid uuid.UUID) *protobufs.TelemetryConnectionSettings {
	if s.endpoint == "" {
		return nil
	}
	return &protobufs.TelemetryConnectionSettings{
		DestinationEndpoint: s.endpoint,
		Headers:             &protobufs.Headers{Headers: []*protobufs.Header{{Key: "Authorization", Value: "Bearer " + s.token(uid)}}},
	}
}

// ServeHTTP is the OTLP/HTTP traces intake.
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
	received, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	encoding := r.Header.Get("Content-Encoding")
	raw := received
	if encoding == "gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(received))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		raw, err = io.ReadAll(io.LimitReader(zr, maxBody))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	var req collectortrace.ExportTraceServiceRequest
	if proto.Unmarshal(raw, &req) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if s.Forward != nil {
		s.Forward(encoding, received)
	}
	if err := s.store(r.Context(), uid, extract(&req)); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
}

func text(v *commonpb.AnyValue) string {
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(x.IntValue, 10)
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(x.BoolValue)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(x.DoubleValue, 'g', -1, 64)
	case nil:
		return ""
	}
	return fmt.Sprint(v.GetValue())
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// extract flattens a request into spans, oldest first.
func extract(req *collectortrace.ExportTraceServiceRequest) []Span {
	var spans []Span
	for _, rs := range req.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				out := Span{
					TraceID: hex.EncodeToString(sp.TraceId), SpanID: hex.EncodeToString(sp.SpanId), Name: clip(sp.Name, maxAttrSize),
					Scope: ss.GetScope().GetName(), Start: time.Unix(0, int64(sp.StartTimeUnixNano)).UTC(),
					DurationMS: float64(sp.EndTimeUnixNano-sp.StartTimeUnixNano) / 1e6, Status: "unset",
					StatusMessage: clip(sp.GetStatus().GetMessage(), maxAttrSize),
				}
				if len(sp.ParentSpanId) > 0 {
					out.ParentID = hex.EncodeToString(sp.ParentSpanId)
				}
				if sp.Kind != tracepb.Span_SPAN_KIND_UNSPECIFIED {
					out.Kind = strings.ToLower(strings.TrimPrefix(sp.Kind.String(), "SPAN_KIND_"))
				}
				switch sp.GetStatus().GetCode() {
				case tracepb.Status_STATUS_CODE_OK:
					out.Status = "ok"
				case tracepb.Status_STATUS_CODE_ERROR:
					out.Status = "error"
				}
				for i, kv := range sp.Attributes {
					if i == maxAttrs {
						break
					}
					if out.Attributes == nil {
						out.Attributes = map[string]string{}
					}
					out.Attributes[kv.Key] = clip(text(kv.Value), maxAttrSize)
				}
				spans = append(spans, out)
			}
		}
	}
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].Start.Before(spans[j].Start) })
	return spans
}

func (s *Service) store(ctx context.Context, uid uuid.UUID, spans []Span) error {
	if len(spans) == 0 {
		return nil
	}
	if len(spans) > Keep {
		spans = spans[len(spans)-Keep:]
	}
	encoded := make([]string, len(spans))
	for i, sp := range spans {
		b, _ := json.Marshal(sp)
		encoded[i] = string(b)
	}
	if s.Redact != nil {
		clean, err := s.Redact(ctx, uid, strings.Join(encoded, "\n"))
		if err != nil {
			return fmt.Errorf("hide secrets in spans: %w", err)
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

// Recent returns a collector's most recent spans, newest first.
func (s *Service) Recent(ctx context.Context, uid uuid.UUID) ([]Span, error) {
	raw, err := s.rdb.LRange(ctx, keyPrefix+uid.String(), -Keep, -1).Result()
	if err != nil {
		return nil, err
	}
	spans := make([]Span, 0, len(raw))
	for i := len(raw) - 1; i >= 0; i-- {
		var sp Span
		if json.Unmarshal([]byte(raw[i]), &sp) == nil {
			spans = append(spans, sp)
		}
	}
	return spans, nil
}
