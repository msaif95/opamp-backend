// Package telemetry exports the backend's own metrics and traces: pushed
// over OTLP, and/or served for Prometheus to scrape.
package telemetry

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
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

// Setup installs the global meter and tracer providers. Metrics and traces
// are pushed over OTLP/HTTP when an endpoint is configured by the standard
// OTEL_* environment variables; with scrape set, metrics are also offered
// in the Prometheus format through the returned handler (nil otherwise).
// With neither, it does nothing and instruments stay no-ops. The returned
// function flushes and stops the exporters.
//
// enabled is consulted on every export and scrape; while it returns false,
// collected metrics and spans are dropped instead of sent and scrapes are
// refused, so export can be switched off and on at runtime.
func Setup(ctx context.Context, replicaID string, scrape bool, enabled func() bool) (shutdown func(context.Context) error, metrics http.Handler, err error) {
	if !Enabled() && !scrape {
		return func(context.Context) error { return nil }, nil, nil
	}
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName("opamp-backend"), semconv.ServiceInstanceID(replicaID)))
	if err != nil {
		return nil, nil, err
	}

	options := []sdkmetric.Option{sdkmetric.WithResource(res)}
	if Enabled() {
		metricExp, err := otlpmetrichttp.New(ctx)
		if err != nil {
			return nil, nil, err
		}
		options = append(options, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(gatedMetrics{metricExp, enabled}, sdkmetric.WithInterval(30*time.Second))))
	}
	if scrape {
		// A registry of its own, with the Go runtime and process metrics alongside the backend's.
		registry := prometheus.NewRegistry()
		registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		exp, err := promexporter.New(promexporter.WithRegisterer(registry))
		if err != nil {
			return nil, nil, err
		}
		options = append(options, sdkmetric.WithReader(exp))
		scraped := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		metrics = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enabled() {
				http.Error(w, "monitoring export is switched off", http.StatusServiceUnavailable)
				return
			}
			scraped.ServeHTTP(w, r)
		})
	}
	mp := sdkmetric.NewMeterProvider(options...)
	otel.SetMeterProvider(mp)
	shutdown = mp.Shutdown

	if Enabled() {
		traceExp, err := otlptracehttp.New(ctx)
		if err != nil {
			return nil, nil, errors.Join(err, mp.Shutdown(ctx))
		}
		tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(gatedSpans{traceExp, enabled}))
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.TraceContext{})
		shutdown = func(ctx context.Context) error { return errors.Join(mp.Shutdown(ctx), tp.Shutdown(ctx)) }
	}
	return shutdown, metrics, nil
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
