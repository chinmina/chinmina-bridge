package observe

import (
	"context"
	"errors"
	"time"

	"github.com/jamestelfer/ghauth/internal/config"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// Configure sets up OpenTelemetry according to the configuration. If it does
// not return an error, make sure to call the returned shutdown function to
// properly stop the services and publish any unpublished batches of metrics.
func Configure(ctx context.Context, cfg config.ObserveConfig) (shutdown func(context.Context) error, err error) {
	if !cfg.Enabled {
		zerolog.Ctx(ctx).Info().Msg(
			"telemetry disabled: enable with OBSERVE_ENABLED to send telemetry data to an OpenTelemetry collector",
		)
		return func(context.Context) error { return nil }, nil
	}

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

	tracerProvider, err := newTraceProvider(ctx, exporters)
	if err != nil {
		handleErr(err)
		return
	}
	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)
	otel.SetTracerProvider(tracerProvider)

	meterProvider, err := newMeterProvider(ctx, exporters)
	if err != nil {
		handleErr(err)
		return
	}
	shutdownFuncs = append(shutdownFuncs, meterProvider.Shutdown)
	otel.SetMeterProvider(meterProvider)

	return
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

func newTraceProvider(ctx context.Context, e exporters) (*trace.TracerProvider, error) {

	traceExporter, err := e.Trace(ctx)
	if err != nil {
		return nil, err
	}

	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("github-buildkite-oidc-bridge"), //CONFIGURE
		),
	)
	if err != nil {
		return nil, err
	}

	traceProvider := trace.NewTracerProvider(
		trace.WithBatcher(traceExporter,
			// FIXME this should be configurable with 1m default
			trace.WithBatchTimeout(time.Second),
		),
		trace.WithResource(r),
	)
	return traceProvider, nil
}

func newMeterProvider(ctx context.Context, e exporters) (*metric.MeterProvider, error) {
	metricExporter, err := e.Metric(ctx)
	if err != nil {
		return nil, err
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(metricExporter,
			// FIXME this should be configurable with 1m default
			metric.WithInterval(20*time.Second))),
	)
	return meterProvider, nil
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
