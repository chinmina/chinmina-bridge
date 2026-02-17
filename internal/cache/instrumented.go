package cache

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

var (
	metricsOnce     sync.Once
	cacheOperations metric.Int64Counter
	cacheDuration   metric.Float64Histogram
)

func initMetrics() {
	metricsOnce.Do(func() {
		meter := otel.Meter("github.com/chinmina/chinmina-bridge/internal/cache")

		var err error
		cacheOperations, err = meter.Int64Counter(
			"cache.operations",
			metric.WithDescription("Total cache operations"),
		)
		if err != nil {
			otel.Handle(err)
		}

		cacheDuration, err = meter.Float64Histogram(
			"cache.operation.duration",
			metric.WithDescription("Cache operation duration"),
			metric.WithUnit("s"),
		)
		if err != nil {
			otel.Handle(err)
		}
	})
}

// Instrumented wraps a TokenCache with metrics instrumentation.
type Instrumented[T any] struct {
	wrapped   TokenCache[T]
	cacheType string
}

// NewInstrumented creates an instrumented cache wrapper.
func NewInstrumented[T any](cache TokenCache[T], cacheType string) *Instrumented[T] {
	initMetrics()
	return &Instrumented[T]{
		wrapped:   cache,
		cacheType: cacheType,
	}
}

// Get retrieves a token from the cache.
func (i *Instrumented[T]) Get(ctx context.Context, key string) (T, bool, error) {
	start := time.Now()

	value, found, err := i.wrapped.Get(ctx, key)

	duration := time.Since(start)
	i.recordDuration(ctx, "get", duration)

	status := "miss"
	if err != nil {
		status = "error"
	} else if found {
		status = "hit"
	}
	i.recordOperation(ctx, "get", status)
	i.setSpanAttributes(ctx, "get", status, duration)

	return value, found, err
}

// Set stores a token in the cache.
func (i *Instrumented[T]) Set(ctx context.Context, key string, value T) error {
	start := time.Now()

	err := i.wrapped.Set(ctx, key, value)

	duration := time.Since(start)
	i.recordDuration(ctx, "set", duration)

	status := "success"
	if err != nil {
		status = "error"
	}
	i.recordOperation(ctx, "set", status)
	i.setSpanAttributes(ctx, "set", status, duration)

	return err
}

// Invalidate removes a token from the cache.
func (i *Instrumented[T]) Invalidate(ctx context.Context, key string) error {
	start := time.Now()

	err := i.wrapped.Invalidate(ctx, key)

	duration := time.Since(start)
	i.recordDuration(ctx, "invalidate", duration)

	status := "success"
	if err != nil {
		status = "error"
	}
	i.recordOperation(ctx, "invalidate", status)
	i.setSpanAttributes(ctx, "invalidate", status, duration)

	return err
}

// Close releases any resources held by the cache.
func (i *Instrumented[T]) Close() error {
	return i.wrapped.Close()
}

func (i *Instrumented[T]) recordOperation(ctx context.Context, operation, status string) {
	if cacheOperations == nil {
		return
	}
	cacheOperations.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("cache.type", i.cacheType),
			attribute.String("cache.operation", operation),
			attribute.String("cache.status", status),
		),
	)
}

func (i *Instrumented[T]) recordDuration(ctx context.Context, operation string, duration time.Duration) {
	if cacheDuration == nil {
		return
	}
	cacheDuration.Record(ctx, duration.Seconds(),
		metric.WithAttributes(
			attribute.String("cache.type", i.cacheType),
			attribute.String("cache.operation", operation),
		),
	)
}

func (i *Instrumented[T]) setSpanAttributes(ctx context.Context, operation, status string, duration time.Duration) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("cache.type", i.cacheType),
		attribute.String("cache."+operation+".status", status),
		attribute.Float64("cache."+operation+".duration", duration.Seconds()),
	)
}
