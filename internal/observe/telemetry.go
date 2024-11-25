package observe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/go-logr/logr"
	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
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
	otel.SetTracerProvider(tracerProvider)

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

func HttpTransport(wrapped http.RoundTripper, cfg config.ObserveConfig) http.RoundTripper {
	if !cfg.Enabled || !cfg.HttpTransportEnabled {
		return wrapped
	}

	var clientTraceOptionFunc func(context.Context) *httptrace.ClientTrace

	if cfg.HttpConnectionTraceEnabled {
		clientTraceOptionFunc = clientHttpTrace
	}

	return otelhttp.NewTransport(
		wrapped,
		otelhttp.WithClientTrace(clientTraceOptionFunc),
	)
}

func clientHttpTrace(ctx context.Context) *httptrace.ClientTrace {
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

	meterProvider := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(metricExporter,
			metric.WithInterval(time.Duration(cfg.MetricReadIntervalSeconds)*time.Second))),
	)

	return meterProvider, nil
}

func configureLogging(cfg config.ObserveConfig) {
	// configure console logger to handle the otel tracing levels
	otelInfLvl := zerolog.Level(-3)
	otelDbgLvl := zerolog.Level(-7)

	level := zerolog.Disabled

	// convert the configured string value to one appropriate for zerolog
	switch cfg.SDKLogLevel {
	case "debug":
		level = otelDbgLvl
	case "info":
		level = otelInfLvl
	case "warn":
		level = zerolog.DebugLevel
	case "":
		// disabled
	default:
		log.Warn().
			Str("configured", cfg.SDKLogLevel).
			Msg("invalid configuration for OBSERVE_OTEL_LOG_LEVEL, internal OTel logging disabled.")
	}

	// don't bother to configure when disabled
	if level == zerolog.Disabled {
		return
	}

	// The otel internal logger (logr) uses V levels of 1, 4 and 8 respectively,
	// which corresponds to zerolog levels of 0 (Debug), -3 and -7. Since these
	// levels are non-standard for zerolog, configuration for the ConsoleLogger is
	// added.
	zerolog.FormattedLevels[otelInfLvl] = "OINF"
	zerolog.LevelColors[otelInfLvl] = 90 // grey
	zerolog.FormattedLevels[otelDbgLvl] = "ODBG"
	zerolog.LevelColors[otelDbgLvl] = 90 // grey

	// The zerolog logger that otel will write to, using its own level, and
	// marking all events with the "otel" source.
	otelLogger := log.Logger.
		Level(level).
		With().
		Str("source", "otel").
		Logger()

	// bridge the logger to the logr library used by otel
	l := logr.New(zerologr.NewLogSink(&otelLogger))
	otel.SetLogger(l)
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
