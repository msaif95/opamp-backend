package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel"
)

// Setup must succeed when export is enabled: a resource schema mismatch
// here once made the backend refuse to start with telemetry turned on.
func TestSetupEnabled(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer srv.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)

	// Shutdown flushes whatever was collected, so it shows whether the switch gates the export.
	for _, on := range []bool{false, true} {
		requests.Store(0)
		shutdown, _, err := Setup(context.Background(), "replica-test", false, func() bool { return on })
		if err != nil {
			t.Fatal(err)
		}
		counter, _ := otel.Meter("test").Int64Counter("test.counter")
		counter.Add(context.Background(), 1)
		_, span := otel.Tracer("test").Start(context.Background(), "test-span")
		span.End()
		if err := shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := requests.Load() > 0; got != on {
			t.Errorf("export switched on=%v: endpoint received %d requests", on, requests.Load())
		}
	}
}

func TestSetupDisabled(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, metrics, err := Setup(context.Background(), "replica-test", false, func() bool { return true })
	if err != nil || shutdown(context.Background()) != nil || metrics != nil {
		t.Fatalf("disabled setup failed: %v (metrics handler %v)", err, metrics != nil)
	}
}

// With scraping on, the backend's instruments are served in the Prometheus
// format without any OTLP endpoint, and the runtime switch closes the page.
func TestPrometheusScrape(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	on := true
	shutdown, metrics, err := Setup(context.Background(), "replica-test", true, func() bool { return on })
	if err != nil || metrics == nil {
		t.Fatalf("setup: %v, handler %v", err, metrics != nil)
	}
	defer shutdown(context.Background())
	counter, _ := otel.Meter("test").Int64Counter("opamp.test.events")
	counter.Add(context.Background(), 3)

	scrape := func() (int, string) {
		rec := httptest.NewRecorder()
		metrics.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
		return rec.Code, rec.Body.String()
	}
	code, body := scrape()
	if code != 200 || !strings.Contains(body, "opamp_test_events_total") || !strings.Contains(body, "go_goroutines") || !strings.Contains(body, `service_name="opamp-backend"`) {
		t.Errorf("scrape: HTTP %d\n%.600s", code, body)
	}
	on = false
	if code, _ := scrape(); code != 503 {
		t.Errorf("scrape while switched off: HTTP %d", code)
	}
}
