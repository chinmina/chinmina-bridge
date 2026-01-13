package cache

import (
	"context"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/maypok86/otter/v2"
	"github.com/maypok86/otter/v2/stats"
)

// Memory is an in-memory cache implementation using otter.
type Memory struct {
	cache   *otter.Cache[string, vendor.ProfileToken]
	ttl     time.Duration
	counter *stats.Counter
}

// NewMemory creates a new in-memory cache with the specified TTL and max size.
func NewMemory(ttl time.Duration, maxSize int) (*Memory, error) {
	counter := stats.NewCounter()
	cache := otter.Must(&otter.Options[string, vendor.ProfileToken]{
		MaximumSize:      maxSize,
		StatsRecorder:    counter,
		ExpiryCalculator: otter.ExpiryCreating[string, vendor.ProfileToken](ttl),
	})

	return &Memory{
		cache:   cache,
		ttl:     ttl,
		counter: counter,
	}, nil
}

// Get retrieves a token from the cache.
// Returns the token, whether it was found, and any error.
func (m *Memory) Get(ctx context.Context, key string) (vendor.ProfileToken, bool, error) {
	entry, ok := m.cache.GetEntry(key)
	if !ok {
		return vendor.ProfileToken{}, false, nil
	}

	return entry.Value, true, nil
}

// Set stores a token in the cache.
func (m *Memory) Set(ctx context.Context, key string, token vendor.ProfileToken) error {
	m.cache.Set(key, token)
	return nil
}

// Invalidate removes a token from the cache.
func (m *Memory) Invalidate(ctx context.Context, key string) error {
	m.cache.Invalidate(key)
	return nil
}
