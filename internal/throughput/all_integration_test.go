package throughput

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"

	"github.com/msaif95/opamp-backend/internal/testdb"
)

func TestEveryReportedMetricIsKept(t *testing.T) {
	_, rdb := testdb.Open(t)
	ctx := context.Background()
	s := New(rdb, []byte("k"), "")
	uid := uuid.New()
	attr := func(k, v string) []*commonpb.KeyValue {
		return []*commonpb.KeyValue{{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}}
	}
	sum := 30.0
	report := func(sent int64, queue, histSum float64, histCount uint64) *collectormetrics.ExportMetricsServiceRequest {
		sum = histSum
		return &collectormetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{
			{Name: "otelcol_exporter_sent_spans_total", Unit: "{spans}", Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{IsMonotonic: true,
				AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
				DataPoints: []*metricspb.NumberDataPoint{
					{Attributes: attr("exporter", "otlp"), Value: &metricspb.NumberDataPoint_AsInt{AsInt: sent}},
					{Attributes: attr("exporter", "debug"), Value: &metricspb.NumberDataPoint_AsInt{AsInt: 0}},
				}}}},
			{Name: "otelcol_exporter_queue_size", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{
				DataPoints: []*metricspb.NumberDataPoint{{Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: queue}}}}}},
			{Name: "otelcol_processor_batch_send_size", Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{
				AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
				DataPoints:             []*metricspb.HistogramDataPoint{{Count: histCount, Sum: &sum}}}}},
		}}}}}}
	}
	t0 := time.Now().UTC().Add(-time.Minute)
	if err := s.recordAll(ctx, uid, t0, extractAll(report(100, 3, 30, 3))); err != nil {
		t.Fatal(err)
	}
	if err := s.recordAll(ctx, uid, t0.Add(60*time.Second), extractAll(report(700, 5, 130, 8))); err != nil {
		t.Fatal(err)
	}
	series, samples, err := s.All(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Series{}
	for _, sr := range series {
		byName[sr.Name+"/"+sr.Attributes["exporter"]] = sr
	}
	if len(series) != 5 || len(samples) != 2 {
		t.Fatalf("%d series, %d samples: %+v", len(series), len(samples), series)
	}
	last := samples[1].Values
	// A counter becomes a per-second rate, per attribute set: (700-100)/60.
	if sr := byName["exporter_sent_spans_total/otlp"]; sr.Kind != "rate" || last[sr.ID] != 10 {
		t.Errorf("counter: %+v = %v", sr, last[sr.ID])
	}
	if sr := byName["exporter_queue_size/"]; sr.Kind != "gauge" || last[sr.ID] != 5 {
		t.Errorf("gauge: %+v = %v", sr, last[sr.ID])
	}
	// A histogram gives the average over the interval: (130-30)/(8-3).
	if sr := byName["processor_batch_send_size (average)/"]; sr.Kind != "average" || last[sr.ID] != 20 {
		t.Errorf("histogram average: %+v = %v", sr, last[sr.ID])
	}
	// The first report has no rate for counters yet, only the gauge.
	if first := samples[0].Values; len(first) != 1 {
		t.Errorf("first sample = %v", first)
	}
	// A restarted collector (totals drop) yields no negative rate.
	if err := s.recordAll(ctx, uid, t0.Add(120*time.Second), extractAll(report(5, 1, 10, 1))); err != nil {
		t.Fatal(err)
	}
	_, samples, _ = s.All(ctx, uid)
	if v, ok := samples[2].Values[byName["exporter_sent_spans_total/otlp"].ID]; ok {
		t.Errorf("rate after a counter reset = %v, want none", v)
	}
}
