package cache

import (
	"context"
	"time"

	"github.com/maypok86/otter/v2"
	"github.com/maypok86/otter/v2/stats"
)

// Memory is an in-memory cache implementation using otter.
// The generic type T represents the token type being cached.
type Memory[T any] struct {
	cache   *otter.Cache[string, T]
	ttl     time.Duration
	counter *stats.Counter
}

// NewMemory creates a new in-memory cache with the specified TTL and max size.
func NewMemory[T any](ttl time.Duration, maxSize int) (*Memory[T], error) {
	counter := stats.NewCounter()
	cache := otter.Must(&otter.Options[string, T]{
		MaximumSize:      maxSize,
		StatsRecorder:    counter,
		ExpiryCalculator: otter.ExpiryCreating[string, T](ttl),
	})

	return &Memory[T]{
		cache:   cache,
		ttl:     ttl,
		counter: counter,
	}, nil
}

// Get retrieves a token from the cache.
// Returns the token, whether it was found, and any error.
func (m *Memory[T]) Get(ctx context.Context, key string) (T, bool, error) {
	entry, ok := m.cache.GetEntry(key)
	if !ok {
		var zero T
		return zero, false, nil
	}

	return entry.Value, true, nil
}

// Set stores a token in the cache.
func (m *Memory[T]) Set(ctx context.Context, key string, token T) error {
	m.cache.Set(key, token)
	return nil
}

// Invalidate removes a token from the cache.
func (m *Memory[T]) Invalidate(ctx context.Context, key string) error {
	m.cache.Invalidate(key)
	return nil
}
