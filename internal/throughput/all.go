package throughput

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
)

// Besides the headline charts, every metric a collector reports about
// itself is kept as a short history so the console can chart all of them.
const (
	allMetaPrefix    = "opamp:metrics:meta:"
	allSamplesPrefix = "opamp:metrics:samples:"
	allPrevPrefix    = "opamp:metrics:prev:"
	// MaxSeries bounds what one collector can make the backend keep.
	MaxSeries = 300
)

// Series describes one line on a chart: a metric and one set of attribute values.
type Series struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	Unit        string            `json:"unit,omitempty"`
	Description string            `json:"description,omitempty"`
	// Kind says how values were derived: "gauge" is the reported value,
	// "rate" is a counter's increase per second, "average" is a histogram's
	// mean over the interval.
	Kind string `json:"kind"`
}

// MetricSample holds the value of every series at one moment, by series ID.
type MetricSample struct {
	At     time.Time          `json:"at"`
	Values map[string]float64 `json:"values"`
}

// observation is one data point as reported, before rates are derived.
type observation struct {
	key    string
	series Series
	// cumulative: value is a running total; delta: an amount for the last interval.
	cumulative, delta bool
	value             float64
	// For histograms: the count the average is taken over.
	count      float64
	hasAverage bool
}

func attrs(kvs []*commonpb.KeyValue) (map[string]string, string) {
	if len(kvs) == 0 {
		return nil, ""
	}
	m := make(map[string]string, len(kvs))
	keys := make([]string, 0, len(kvs))
	for _, kv := range kvs {
		v := kv.GetValue().GetStringValue()
		if v == "" && kv.GetValue() != nil {
			switch x := kv.Value.Value.(type) {
			case *commonpb.AnyValue_IntValue:
				v = strconv.FormatInt(x.IntValue, 10)
			case *commonpb.AnyValue_BoolValue:
				v = strconv.FormatBool(x.BoolValue)
			case *commonpb.AnyValue_DoubleValue:
				v = strconv.FormatFloat(x.DoubleValue, 'g', -1, 64)
			}
		}
		m[kv.Key] = v
		keys = append(keys, kv.Key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString("|" + k + "=" + m[k])
	}
	return m, b.String()
}

// extractAll turns a request into observations, one per series.
func extractAll(req *collectormetrics.ExportMetricsServiceRequest) []observation {
	var out []observation
	for _, rm := range req.ResourceMetrics {
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				name := strings.TrimPrefix(m.Name, "otelcol_")
				base := Series{Name: name, Unit: m.Unit, Description: m.Description}
				number := func(dp *metricspb.NumberDataPoint) float64 { return dp.GetAsDouble() + float64(dp.GetAsInt()) }
				switch {
				case m.GetGauge() != nil:
					for _, dp := range m.GetGauge().DataPoints {
						a, k := attrs(dp.Attributes)
						s := base
						s.Attributes, s.Kind = a, "gauge"
						out = append(out, observation{key: name + k, series: s, value: number(dp)})
					}
				case m.GetSum() != nil:
					sum := m.GetSum()
					isDelta := sum.AggregationTemporality == metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA
					for _, dp := range sum.DataPoints {
						a, k := attrs(dp.Attributes)
						s := base
						s.Attributes, s.Kind = a, "gauge"
						o := observation{key: name + k, series: s, value: number(dp)}
						if sum.IsMonotonic {
							// A counter is only meaningful as a rate.
							o.series.Kind, o.cumulative, o.delta = "rate", !isDelta, isDelta
						}
						out = append(out, o)
					}
				case m.GetHistogram() != nil:
					h := m.GetHistogram()
					isDelta := h.AggregationTemporality == metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA
					for _, dp := range h.DataPoints {
						a, k := attrs(dp.Attributes)
						count := base
						count.Name, count.Attributes, count.Kind, count.Unit = name+" (count)", a, "rate", ""
						out = append(out, observation{key: count.Name + k, series: count, value: float64(dp.Count), cumulative: !isDelta, delta: isDelta})
						if dp.Sum != nil {
							avg := base
							avg.Name, avg.Attributes, avg.Kind = name+" (average)", a, "average"
							out = append(out, observation{key: avg.Name + k, series: avg, value: *dp.Sum, count: float64(dp.Count),
								cumulative: !isDelta, delta: isDelta, hasAverage: true})
						}
					}
				}
			}
		}
	}
	return out
}

// previous is what the last report left behind, for turning totals into rates.
type previous struct {
	At     time.Time          `json:"at"`
	Totals map[string]float64 `json:"totals"`
	// Counts holds histogram counts by series ID, for averages.
	Counts map[string]float64 `json:"counts"`
}

// recordAll stores one sample covering every series in the report.
func (s *Service) recordAll(ctx context.Context, uid uuid.UUID, now time.Time, obs []observation) error {
	if len(obs) == 0 {
		return nil
	}
	id := uid.String()
	known, err := s.rdb.HGetAll(ctx, allMetaPrefix+id).Result()
	if err != nil {
		return err
	}
	ids := make(map[string]string, len(known))
	for key, raw := range known {
		var meta Series
		if json.Unmarshal([]byte(raw), &meta) == nil {
			ids[key] = meta.ID
		}
	}
	var prev previous
	if raw, err := s.rdb.Get(ctx, allPrevPrefix+id).Bytes(); err == nil {
		_ = json.Unmarshal(raw, &prev)
	} else if !errors.Is(err, redis.Nil) {
		return err
	}
	elapsed := now.Sub(prev.At).Seconds()
	havePrev := !prev.At.IsZero() && elapsed > 0 && elapsed < sampleTTL.Seconds()

	cur := previous{At: now, Totals: map[string]float64{}, Counts: map[string]float64{}}
	sample := MetricSample{At: now, Values: map[string]float64{}}
	added := map[string]any{}
	for _, o := range obs {
		sid, ok := ids[o.key]
		if !ok {
			if len(ids) >= MaxSeries {
				continue
			}
			sid = strconv.Itoa(len(ids) + 1)
			ids[o.key] = sid
			o.series.ID = sid
			meta, _ := json.Marshal(o.series)
			added[o.key] = string(meta)
		}
		switch {
		case o.hasAverage:
			// Mean of what was observed since the last report.
			sum, count := o.value, o.count
			if o.cumulative {
				cur.Totals[sid], cur.Counts[sid] = o.value, o.count
				before, seen := prev.Totals[sid]
				if !havePrev || !seen || o.count < prev.Counts[sid] {
					continue
				}
				sum, count = o.value-before, o.count-prev.Counts[sid]
			}
			if count > 0 {
				sample.Values[sid] = sum / count
			}
		case o.cumulative:
			cur.Totals[sid] = o.value
			// No previous total, or a smaller one (the collector restarted): no rate yet.
			if before, seen := prev.Totals[sid]; havePrev && seen && o.value >= before {
				sample.Values[sid] = (o.value - before) / elapsed
			}
		case o.delta:
			if havePrev {
				sample.Values[sid] = o.value / elapsed
			}
		default:
			sample.Values[sid] = o.value
		}
	}
	rawPrev, _ := json.Marshal(cur)
	rawSample, _ := json.Marshal(sample)
	pipe := s.rdb.TxPipeline()
	if len(added) > 0 {
		pipe.HSet(ctx, allMetaPrefix+id, added)
	}
	pipe.Expire(ctx, allMetaPrefix+id, historyTTL)
	pipe.Set(ctx, allPrevPrefix+id, rawPrev, sampleTTL)
	pipe.LPush(ctx, allSamplesPrefix+id, rawSample)
	pipe.LTrim(ctx, allSamplesPrefix+id, 0, historyPoints-1)
	pipe.Expire(ctx, allSamplesPrefix+id, historyTTL)
	_, err = pipe.Exec(ctx)
	return err
}

// All returns every series a collector reports and its samples, oldest first.
func (s *Service) All(ctx context.Context, uid uuid.UUID) ([]Series, []MetricSample, error) {
	id := uid.String()
	meta, err := s.rdb.HGetAll(ctx, allMetaPrefix+id).Result()
	if err != nil {
		return nil, nil, err
	}
	series := make([]Series, 0, len(meta))
	for _, raw := range meta {
		var m Series
		if json.Unmarshal([]byte(raw), &m) == nil {
			series = append(series, m)
		}
	}
	sort.Slice(series, func(i, j int) bool {
		if series[i].Name != series[j].Name {
			return series[i].Name < series[j].Name
		}
		a, _ := strconv.Atoi(series[i].ID)
		b, _ := strconv.Atoi(series[j].ID)
		return a < b
	})
	raw, err := s.rdb.LRange(ctx, allSamplesPrefix+id, 0, -1).Result()
	if err != nil {
		return nil, nil, err
	}
	samples := make([]MetricSample, 0, len(raw))
	for i := len(raw) - 1; i >= 0; i-- {
		var p MetricSample
		if json.Unmarshal([]byte(raw[i]), &p) == nil {
			samples = append(samples, p)
		}
	}
	return series, samples, nil
}
