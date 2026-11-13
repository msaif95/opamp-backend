package throughput

import (
	"testing"
	"time"

	"github.com/google/uuid"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
)

func sum(name string, temporality metricspb.AggregationTemporality, values ...int64) *metricspb.Metric {
	var dps []*metricspb.NumberDataPoint
	for _, v := range values {
		dps = append(dps, &metricspb.NumberDataPoint{Value: &metricspb.NumberDataPoint_AsInt{AsInt: v}})
	}
	return &metricspb.Metric{Name: name, Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{DataPoints: dps, AggregationTemporality: temporality}}}
}

func TestExtractAndRates(t *testing.T) {
	cum := metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE
	req := &collectormetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{
		sum("otelcol_receiver_accepted_log_records", cum, 600, 400), // two receivers
		sum("otelcol_exporter_sent_log_records_total", cum, 700),
		sum("otelcol_exporter_send_failed_spans", cum, 5),
		sum("otelcol_process_uptime", cum, 99), // not a pipeline counter
	}}}}}}
	totals, delta := extract(req)
	if delta || totals["received"]["logs"] != 1000 || totals["sent"]["logs"] != 700 || totals["failed"]["traces"] != 5 || len(totals) != 3 {
		t.Fatalf("totals = %v, delta %v", totals, delta)
	}

	t0 := time.Now()
	if r := rates(stored{}, t0, totals, false); len(r) != 0 {
		t.Fatalf("first sample produced rates: %v", r)
	}
	prev := stored{At: t0, Totals: map[string]map[string]float64{"received": {"logs": 400}, "sent": {"logs": 900}}}
	r := rates(prev, t0.Add(10*time.Second), totals, false)
	if r["received"]["logs"] != 60 {
		t.Errorf("received rate = %v, want 60/s", r["received"]["logs"])
	}
	// The sent counter went down (collector restart): no rate rather than a negative one.
	if _, ok := r["sent"]["logs"]; ok {
		t.Errorf("rate reported across a counter reset: %v", r["sent"])
	}
	// Delta temporality: the value is already the interval's count.
	if r := rates(prev, t0.Add(10*time.Second), totals, true); r["received"]["logs"] != 100 {
		t.Errorf("delta rate = %v, want 100/s", r["received"]["logs"])
	}
}

func TestTokenAndOffer(t *testing.T) {
	s := New(nil, []byte("0123456789abcdef0123456789abcdef"), "wss://opamp.example.com:4320/v1/opamp")
	uid := uuid.New()
	if got, ok := s.verify(s.token(uid)); !ok || got != uid {
		t.Fatal("own token rejected")
	}
	other := uuid.New()
	forged := other.String() + s.token(uid)[36:]
	for _, bad := range []string{"", "x.y", forged, s.token(uid) + "0"} {
		if _, ok := s.verify(bad); ok {
			t.Errorf("token %q accepted", bad)
		}
	}
	offer := s.Offer(uid)
	if offer.OwnMetrics.DestinationEndpoint != "https://opamp.example.com:4320/v1/metrics" || len(offer.Hash) == 0 {
		t.Fatalf("offer = %+v", offer.OwnMetrics)
	}
	if New(nil, nil, "").Offer(uid) != nil {
		t.Error("offer made without a public endpoint")
	}
}
