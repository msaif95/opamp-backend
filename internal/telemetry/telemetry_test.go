package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
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
		shutdown, err := Setup(context.Background(), "replica-test", func() bool { return on })
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
	shutdown, err := Setup(context.Background(), "replica-test", func() bool { return true })
	if err != nil || shutdown(context.Background()) != nil {
		t.Fatalf("disabled setup failed: %v", err)
	}
}
