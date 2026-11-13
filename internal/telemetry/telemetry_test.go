package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Setup must succeed when export is enabled: a resource schema mismatch
// here once made the backend refuse to start with telemetry turned on.
func TestSetupEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)

	shutdown, err := Setup(context.Background(), "replica-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSetupDisabled(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := Setup(context.Background(), "replica-test")
	if err != nil || shutdown(context.Background()) != nil {
		t.Fatalf("disabled setup failed: %v", err)
	}
}
