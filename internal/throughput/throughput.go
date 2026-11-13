// Package throughput receives the collectors' own pipeline counters (how
// much each received, sent and failed to send) and turns them into rates.
// Collectors are told where to send them through OpAMP's own-metrics
// connection settings; only the latest sample per agent is kept, in Redis.
package throughput

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/redis/go-redis/v9"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

const (
	// IntakePath is served on the agent listener, next to the OpAMP endpoint.
	IntakePath = "/v1/metrics"
	keyPrefix  = "opamp:throughput:"
	sampleTTL  = 5 * time.Minute
	// History: collectors report about once a minute, so this is roughly three hours.
	historyPrefix = "opamp:history:"
	historyPoints = 180
	historyTTL    = 4 * time.Hour
	maxBody       = 4 << 20
)

// counters maps the collector's internal metric names (without the
// "otelcol_" prefix and any "_total" suffix) to a direction and a signal.
var counters = map[string][2]string{
	"receiver_accepted_log_records":      {"received", "logs"},
	"receiver_accepted_metric_points":    {"received", "metrics"},
	"receiver_accepted_spans":            {"received", "traces"},
	"receiver_refused_log_records":       {"refused", "logs"},
	"receiver_refused_metric_points":     {"refused", "metrics"},
	"receiver_refused_spans":             {"refused", "traces"},
	"exporter_sent_log_records":          {"sent", "logs"},
	"exporter_sent_metric_points":        {"sent", "metrics"},
	"exporter_sent_spans":                {"sent", "traces"},
	"exporter_send_failed_log_records":   {"failed", "logs"},
	"exporter_send_failed_metric_points": {"failed", "metrics"},
	"exporter_send_failed_spans":         {"failed", "traces"},
}

// processMetrics maps the collector's own process metrics to the names used here.
var processMetrics = map[string]string{
	"process_cpu_seconds":        "cpu", // cumulative CPU seconds; its rate is cores in use
	"process_memory_rss":         "rss",
	"process_runtime_heap_alloc": "heap",
}

// Point is one history sample for charts. CPU and memory are nil when the
// collector did not report them.
type Point struct {
	At       time.Time `json:"at"`
	CPUPct   *float64  `json:"cpu_pct"`
	RSS      *float64  `json:"rss_bytes"`
	Heap     *float64  `json:"heap_bytes"`
	Received float64   `json:"received"`
	Sent     float64   `json:"sent"`
	Failed   float64   `json:"failed"`
}

// Sample is an agent's latest throughput. Rates are records per second,
// keyed by direction (received, sent, failed, refused) then signal.
type Sample struct {
	At    time.Time                     `json:"at"`
	Rates map[string]map[string]float64 `json:"rates"`
	// Totals are the raw cumulative counters the rates were derived from.
	Totals map[string]map[string]float64 `json:"-"`
}

type stored struct {
	At     time.Time                     `json:"at"`
	Totals map[string]map[string]float64 `json:"totals"`
	Rates  map[string]map[string]float64 `json:"rates"`
}

// Service offers the intake to collectors and serves it.
type Service struct {
	rdb *redis.Client
	key []byte
	// endpoint is the intake URL as collectors reach it.
	endpoint string
}

// New creates a Service. agentEndpointURL is the public OpAMP URL
// (ws[s]://host/v1/opamp); the intake lives on the same host and port. An
// empty URL disables offering.
func New(rdb *redis.Client, signingKey []byte, agentEndpointURL string) *Service {
	s := &Service{rdb: rdb, key: signingKey}
	// ws://host:port/v1/opamp -> http://host:port/v1/metrics (wss -> https).
	if u, err := url.Parse(agentEndpointURL); err == nil && (u.Scheme == "ws" || u.Scheme == "wss") {
		s.endpoint = "http" + strings.TrimPrefix(u.Scheme, "ws") + "://" + u.Host + IntakePath
	}
	return s
}

// token is what a collector presents to the intake: it proves the backend
// told this agent to report, without the backend storing anything per agent.
func (s *Service) token(uid uuid.UUID) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("own-metrics:" + uid.String()))
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

// Offer returns the connection settings telling an agent where to send its
// own metrics, or nil when the intake has no public address.
func (s *Service) Offer(uid uuid.UUID) *protobufs.ConnectionSettingsOffers {
	if s.endpoint == "" {
		return nil
	}
	hash := sha256.Sum256([]byte(s.endpoint + "|" + uid.String()))
	return &protobufs.ConnectionSettingsOffers{
		Hash: hash[:],
		OwnMetrics: &protobufs.TelemetryConnectionSettings{
			DestinationEndpoint: s.endpoint,
			Headers:             &protobufs.Headers{Headers: []*protobufs.Header{{Key: "Authorization", Value: "Bearer " + s.token(uid)}}},
		},
	}
}

// ServeHTTP is the OTLP/HTTP metrics intake.
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
	var req collectormetrics.ExportMetricsServiceRequest
	if err != nil || proto.Unmarshal(raw, &req) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	// Everything the collector reported, for the per-metric charts.
	if err := s.recordAll(r.Context(), uid, now, extractAll(&req)); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	totals, gauges, delta := extract(&req)
	if len(totals) > 0 {
		if err := s.record(r.Context(), uid, now, totals, gauges, delta); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
}

// extract sums the pipeline counters in a request by direction and signal.
// delta reports whether the collector sent per-interval values rather than
// running totals.
func extract(req *collectormetrics.ExportMetricsServiceRequest) (totals map[string]map[string]float64, gauges map[string]float64, delta bool) {
	totals, gauges = map[string]map[string]float64{}, map[string]float64{}
	for _, rm := range req.ResourceMetrics {
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				name := strings.TrimSuffix(strings.TrimPrefix(m.Name, "otelcol_"), "_total")
				if p, ok := processMetrics[strings.TrimSuffix(name, "_bytes")]; ok {
					var v float64
					for _, dp := range append(m.GetGauge().GetDataPoints(), m.GetSum().GetDataPoints()...) {
						v += dp.GetAsDouble() + float64(dp.GetAsInt())
					}
					if p == "cpu" {
						totals["process"] = map[string]float64{"cpu": v}
					} else {
						gauges[p] = v
					}
					continue
				}
				c, ok := counters[name]
				sum := m.GetSum()
				if !ok || sum == nil {
					continue
				}
				delta = delta || sum.AggregationTemporality == metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA
				if totals[c[0]] == nil {
					totals[c[0]] = map[string]float64{}
				}
				for _, dp := range sum.DataPoints {
					totals[c[0]][c[1]] += dp.GetAsDouble() + float64(dp.GetAsInt())
				}
			}
		}
	}
	return totals, gauges, delta
}

// record stores the sample and derives rates from the previous one.
func (s *Service) record(ctx context.Context, uid uuid.UUID, now time.Time, totals map[string]map[string]float64, gauges map[string]float64, delta bool) error {
	var prev stored
	if raw, err := s.rdb.Get(ctx, keyPrefix+uid.String()).Bytes(); err == nil {
		_ = json.Unmarshal(raw, &prev)
	} else if !errors.Is(err, redis.Nil) {
		return err
	}
	cur := stored{At: now, Totals: totals, Rates: rates(prev, now, totals, delta)}
	raw, _ := json.Marshal(cur)
	point, _ := json.Marshal(point(now, cur.Rates, gauges))
	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, keyPrefix+uid.String(), raw, sampleTTL)
	pipe.LPush(ctx, historyPrefix+uid.String(), point)
	pipe.LTrim(ctx, historyPrefix+uid.String(), 0, historyPoints-1)
	pipe.Expire(ctx, historyPrefix+uid.String(), historyTTL)
	_, err := pipe.Exec(ctx)
	return err
}

func point(now time.Time, rates map[string]map[string]float64, gauges map[string]float64) Point {
	p := Point{At: now}
	if cores, ok := rates["process"]["cpu"]; ok {
		pct := cores * 100
		p.CPUPct = &pct
	}
	if v, ok := gauges["rss"]; ok {
		p.RSS = &v
	}
	if v, ok := gauges["heap"]; ok {
		p.Heap = &v
	}
	for dir, dst := range map[string]*float64{"received": &p.Received, "sent": &p.Sent, "failed": &p.Failed} {
		for _, v := range rates[dir] {
			*dst += v
		}
	}
	return p
}

// History returns the agent's recent samples, oldest first.
func (s *Service) History(ctx context.Context, uid uuid.UUID) ([]Point, error) {
	raw, err := s.rdb.LRange(ctx, historyPrefix+uid.String(), 0, historyPoints-1).Result()
	if err != nil {
		return nil, err
	}
	points := make([]Point, 0, len(raw))
	for i := len(raw) - 1; i >= 0; i-- {
		var p Point
		if json.Unmarshal([]byte(raw[i]), &p) == nil {
			points = append(points, p)
		}
	}
	return points, nil
}

func rates(prev stored, now time.Time, totals map[string]map[string]float64, delta bool) map[string]map[string]float64 {
	out := map[string]map[string]float64{}
	dt := now.Sub(prev.At).Seconds()
	if prev.At.IsZero() || dt <= 0 {
		return out // first sample: no rate yet
	}
	for dir, bySignal := range totals {
		out[dir] = map[string]float64{}
		for signal, v := range bySignal {
			d := v
			if !delta {
				d = v - prev.Totals[dir][signal]
			}
			// A counter that went down means the collector restarted; skip that interval.
			if d >= 0 {
				out[dir][signal] = d / dt
			}
		}
	}
	return out
}

// Latest returns the agent's most recent sample, or nil if it has not
// reported within the last few minutes.
func (s *Service) Latest(ctx context.Context, uid uuid.UUID) (*Sample, error) {
	raw, err := s.rdb.Get(ctx, keyPrefix+uid.String()).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st stored
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &Sample{At: st.At, Rates: st.Rates}, nil
}
