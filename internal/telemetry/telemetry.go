// Package telemetry exports the backend's own metrics and traces over OTLP.
package telemetry

import (
	"context"
	"errors"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// Enabled reports whether an OTLP endpoint is configured through the
// standard OTEL_EXPORTER_OTLP_* environment variables.
func Enabled() bool {
	for _, k := range []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// Setup installs global meter and tracer providers that export over
// OTLP/HTTP, configured by the standard OTEL_* environment variables. When
// no endpoint is configured it does nothing and instruments stay no-ops.
// The returned function flushes and stops the exporters.
//
// enabled is consulted on every export; while it returns false, collected
// metrics and spans are dropped instead of sent, so export can be switched
// off and on at runtime.
func Setup(ctx context.Context, replicaID string, enabled func() bool) (shutdown func(context.Context) error, err error) {
	if !Enabled() {
		return func(context.Context) error { return nil }, nil
	}
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName("opamp-backend"), semconv.ServiceInstanceID(replicaID)))
	if err != nil {
		return nil, err
	}

	metricExp, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, err
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(gatedMetrics{metricExp, enabled}, sdkmetric.WithInterval(30*time.Second))))
	otel.SetMeterProvider(mp)

	traceExp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, errors.Join(err, mp.Shutdown(ctx))
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(gatedSpans{traceExp, enabled}))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return func(ctx context.Context) error { return errors.Join(mp.Shutdown(ctx), tp.Shutdown(ctx)) }, nil
}

// gatedMetrics drops metric exports while enabled returns false.
type gatedMetrics struct {
	sdkmetric.Exporter
	enabled func() bool
}

func (g gatedMetrics) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	if !g.enabled() {
		return nil
	}
	return g.Exporter.Export(ctx, rm)
}

// gatedSpans drops span exports while enabled returns false.
type gatedSpans struct {
	sdktrace.SpanExporter
	enabled func() bool
}

func (g gatedSpans) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if !g.enabled() {
		return nil
	}
	return g.SpanExporter.ExportSpans(ctx, spans)
}
