package observe

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/go-logr/logr"
	otelpyroscope "github.com/grafana/otel-profiling-go"
	"go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
	traceapi "go.opentelemetry.io/otel/trace"
)

// Configure sets up OpenTelemetry according to the configuration. If it does
// not return an error, make sure to call the returned shutdown function to
// properly stop the services and publish any unpublished batches of metrics.
func Configure(ctx context.Context, cfg config.ObserveConfig) (shutdown func(context.Context) error, err error) {
	if !cfg.Enabled {
		slog.Info("telemetry disabled: enable with OBSERVE_ENABLED to send telemetry data to an OpenTelemetry collector")
		return func(context.Context) error { return nil }, nil
	}

	configureLogging(cfg)

	var shutdownFuncs []func(context.Context) error

	// Allow clean up functions to be executed for the various subsystems that
	// have been started. Errors are chained, nil returns are ignored.
	shutdown = func(ctx context.Context) error {
		var err error
		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}
		shutdownFuncs = nil
		return err
	}

	// any error that occurs during configuration needs to ensure cleanup occurs
	// before returning
	handleErr := func(inErr error) {
		err = errors.Join(inErr, shutdown(ctx))
	}

	prop := newPropagator()
	otel.SetTextMapPropagator(prop)

	exporters := configuredExporters(cfg)

	tracerProvider, err := newTraceProvider(ctx, cfg, exporters)
	if err != nil {
		handleErr(err)
		return
	}
	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)

	var tp traceapi.TracerProvider = tracerProvider
	if cfg.PyroscopeEnabled {
		tp = otelpyroscope.NewTracerProvider(tp)
	}
	otel.SetTracerProvider(tp)

	if cfg.MetricsEnabled {
		meterProvider, err := newMeterProvider(ctx, cfg, exporters)
		if err != nil {
			handleErr(err)
			return shutdown, err
		}
		shutdownFuncs = append(shutdownFuncs, meterProvider.Shutdown)
		otel.SetMeterProvider(meterProvider)
	}

	return
}

func HTTPTransport(wrapped http.RoundTripper, cfg config.ObserveConfig) http.RoundTripper {
	if !cfg.Enabled || !cfg.HTTPTransportEnabled {
		return wrapped
	}

	var clientTraceOptionFunc func(context.Context) *httptrace.ClientTrace

	if cfg.HTTPConnectionTraceEnabled {
		clientTraceOptionFunc = clientHTTPTrace
	}

	return otelhttp.NewTransport(
		wrapped,
		otelhttp.WithClientTrace(clientTraceOptionFunc),
	)
}

func clientHTTPTrace(ctx context.Context) *httptrace.ClientTrace {
	return otelhttptrace.NewClientTrace(
		ctx,
		otelhttptrace.WithoutSubSpans(),
		otelhttptrace.WithoutHeaders(),
	)
}

func configuredExporters(cfg config.ObserveConfig) exporters {
	switch cfg.Type {
	case "stdout":
		return stdoutExporters{}

	case "grpc":
		fallthrough
	default:
		return grpcExporters{}
	}
}

func newPropagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}

func newTraceProvider(ctx context.Context, cfg config.ObserveConfig, e exporters) (*trace.TracerProvider, error) {
	traceExporter, err := e.Trace(ctx)
	if err != nil {
		return nil, err
	}

	r, err := resourceWithServiceName(resource.Default(), cfg.ServiceName)
	if err != nil {
		return nil, err
	}

	traceProvider := trace.NewTracerProvider(
		trace.WithBatcher(traceExporter,
			trace.WithBatchTimeout(time.Duration(cfg.TraceBatchTimeoutSeconds)*time.Second),
		),
		trace.WithResource(r),
	)
	return traceProvider, nil
}

func resourceWithServiceName(base *resource.Resource, serviceName string) (*resource.Resource, error) {
	return resource.Merge(
		base,
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)
}

func newMeterProvider(ctx context.Context, cfg config.ObserveConfig, e exporters) (*metric.MeterProvider, error) {
	metricExporter, err := e.Metric(ctx)
	if err != nil {
		return nil, err
	}

	r, err := resourceWithServiceName(resource.Default(), cfg.ServiceName)
	if err != nil {
		return nil, err
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(metricExporter,
			metric.WithInterval(time.Duration(cfg.MetricReadIntervalSeconds)*time.Second))),
		metric.WithResource(r),
	)

	return meterProvider, nil
}

// otelHandler wraps a slog.Handler, overriding its level filter to allow
// sub-Info OTel events through while delegating output to the underlying handler.
type otelHandler struct {
	slog.Handler
	minLevel slog.Level
}

func (h *otelHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.minLevel
}

func (h *otelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &otelHandler{Handler: h.Handler.WithAttrs(attrs), minLevel: h.minLevel}
}

func (h *otelHandler) WithGroup(name string) slog.Handler {
	return &otelHandler{Handler: h.Handler.WithGroup(name), minLevel: h.minLevel}
}

func configureLogging(cfg config.ObserveConfig) {
	// Map configured level string to a slog.Level threshold.
	// logr.FromSlogHandler maps V(1)→slog.Level(-1), V(4)→SlogOTelInfoLevel (-4), V(8)→SlogOTelDebugLevel (-8).
	var minLevel slog.Level
	var enabled bool

	switch cfg.SDKLogLevel {
	case "warn":
		minLevel = slog.Level(-1)
		enabled = true
	case "info":
		minLevel = SlogOTelInfoLevel
		enabled = true
	case "debug":
		minLevel = SlogOTelDebugLevel
		enabled = true
	case "":
		// disabled
	default:
		slog.Warn("invalid configuration for OBSERVE_OTEL_LOG_LEVEL, internal OTel logging disabled", "configured", cfg.SDKLogLevel)
	}

	if !enabled {
		return
	}

	// Wrap the global handler so sub-Info OTel events pass through, and tag
	// all OTel events with source=otel for identification in log output.
	handler := &otelHandler{
		Handler:  slog.Default().Handler().WithAttrs([]slog.Attr{slog.String("source", "otel")}),
		minLevel: minLevel,
	}

	otel.SetLogger(logr.FromSlogHandler(handler))
}

type exporters interface {
	Trace(ctx context.Context) (trace.SpanExporter, error)
	Metric(ctx context.Context) (metric.Exporter, error)
}

type grpcExporters struct{}

func (e grpcExporters) Trace(ctx context.Context) (trace.SpanExporter, error) {
	return otlptracegrpc.New(ctx)
}
func (e grpcExporters) Metric(ctx context.Context) (metric.Exporter, error) {
	return otlpmetricgrpc.New(ctx)
}

type stdoutExporters struct{}

func (e stdoutExporters) Trace(ctx context.Context) (trace.SpanExporter, error) {
	return stdouttrace.New()
}
func (e stdoutExporters) Metric(ctx context.Context) (metric.Exporter, error) {
	return stdoutmetric.New()
}
