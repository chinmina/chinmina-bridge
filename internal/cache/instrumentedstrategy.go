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
	strategyMetricsOnce  sync.Once
	encryptionDuration   metric.Float64Histogram
	encryptionOperations metric.Int64Counter
)

func initStrategyMetrics() {
	strategyMetricsOnce.Do(func() {
		meter := otel.Meter("github.com/chinmina/chinmina-bridge/internal/cache")

		var err error
		encryptionDuration, err = meter.Float64Histogram(
			"cache.encryption.duration",
			metric.WithDescription("Cache encryption operation duration"),
			metric.WithUnit("s"),
		)
		if err != nil {
			otel.Handle(err)
		}

		encryptionOperations, err = meter.Int64Counter(
			"cache.encryption.total",
			metric.WithDescription("Total cache encryption operations"),
		)
		if err != nil {
			otel.Handle(err)
		}
	})
}

// InstrumentedStrategy wraps an EncryptionStrategy with metrics instrumentation
// for encrypt and decrypt operations.
type InstrumentedStrategy struct {
	wrapped EncryptionStrategy
}

// NewInstrumentedStrategy creates an instrumented encryption strategy wrapper.
func NewInstrumentedStrategy(strategy EncryptionStrategy) *InstrumentedStrategy {
	initStrategyMetrics()
	return &InstrumentedStrategy{wrapped: strategy}
}

func (s *InstrumentedStrategy) EncryptValue(ctx context.Context, token []byte, key string) (string, error) {
	start := time.Now()

	result, err := s.wrapped.EncryptValue(ctx, token, key)

	duration := time.Since(start)
	recordEncryptionDuration(ctx, "encrypt", duration)
	recordEncryptionOutcome(ctx, "encrypt", err)
	setEncryptionSpanAttributes(ctx, "encrypt", duration, err)

	return result, err
}

func (s *InstrumentedStrategy) DecryptValue(ctx context.Context, value string, key string) ([]byte, error) {
	start := time.Now()

	result, err := s.wrapped.DecryptValue(ctx, value, key)

	duration := time.Since(start)
	recordEncryptionDuration(ctx, "decrypt", duration)
	recordEncryptionOutcome(ctx, "decrypt", err)
	setEncryptionSpanAttributes(ctx, "decrypt", duration, err)

	return result, err
}

func (s *InstrumentedStrategy) StorageKey(key string) string {
	return s.wrapped.StorageKey(key)
}

func (s *InstrumentedStrategy) Close() error {
	return s.wrapped.Close()
}

func setEncryptionSpanAttributes(ctx context.Context, operation string, duration time.Duration, err error) {
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.Float64("cache."+operation+".duration", duration.Seconds()),
		attribute.String("cache."+operation+".outcome", outcome),
	)
}

func recordEncryptionDuration(ctx context.Context, operation string, duration time.Duration) {
	if encryptionDuration == nil {
		return
	}
	encryptionDuration.Record(ctx, duration.Seconds(),
		metric.WithAttributes(
			attribute.String("encryption.operation", operation),
		),
	)
}

func recordEncryptionOutcome(ctx context.Context, operation string, err error) {
	if encryptionOperations == nil {
		return
	}
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	encryptionOperations.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("encryption.operation", operation),
			attribute.String("encryption.outcome", outcome),
		),
	)
}
