package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/valkey-io/valkey-go"
)

// Distributed implements TokenCache using Valkey with server-assisted
// client-side caching.
// The generic type T represents the token type being cached.
type Distributed[T any] struct {
	client   valkey.Client
	ttl      time.Duration
	strategy EncryptionStrategy
}

// NewDistributed creates a new Valkey-backed cache with server-assisted client-side caching.
// The ttl parameter specifies how long tokens remain valid in the cache.
// The strategy parameter controls encryption of cached values; nil defaults to NoEncryptionStrategy.
func NewDistributed[T any](valkeyClient valkey.Client, ttl time.Duration, strategy EncryptionStrategy) (*Distributed[T], error) {
	if strategy == nil {
		strategy = &NoEncryptionStrategy{}
	}
	return &Distributed[T]{
		client:   valkeyClient,
		ttl:      ttl,
		strategy: strategy,
	}, nil
}

// Get retrieves a token from the cache using server-assisted client-side caching.
// Returns the token, whether it was found, and any error.
// Decryption failures are returned as errors (the Instrumented wrapper records
// these as "error" status for observability). The corrupted entry is
// invalidated on a best-effort basis.
func (d *Distributed[T]) Get(ctx context.Context, key string) (T, bool, error) {
	var zero T

	storageKey := d.strategy.StorageKey(key)

	// Use DoCache for server-assisted client-side caching
	// The .Cache() method enables client-side caching with server tracking
	cmd := d.client.B().Get().Key(storageKey).Cache()
	result := d.client.DoCache(ctx, cmd, d.ttl)

	if err := result.Error(); err != nil {
		// Key not found is not an error in our semantics
		if valkey.IsValkeyNil(err) {
			return zero, false, nil
		}
		return zero, false, fmt.Errorf("failed to get cached value: %w", err)
	}

	val, err := result.ToString()
	if err != nil {
		return zero, false, fmt.Errorf("failed to convert cached value to string: %w", err)
	}

	data, err := d.strategy.DecryptValue(val, key)
	if err != nil {
		// Best-effort invalidation of the corrupted entry.
		_ = d.client.Do(ctx, d.client.B().Del().Key(storageKey).Build()).Error()

		return zero, false, fmt.Errorf("cache decryption failure for key %q: %w", key, err)
	}

	var token T
	if err := json.Unmarshal(data, &token); err != nil {
		return zero, false, fmt.Errorf("failed to unmarshal cached token: %w", err)
	}

	return token, true, nil
}

// Set stores a token in the cache with the configured TTL.
// The token is JSON-serialized before storage.
func (d *Distributed[T]) Set(ctx context.Context, key string, token T) error {
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	value, err := d.strategy.EncryptValue(data, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt token: %w", err)
	}

	cmd := d.client.B().Set().Key(d.strategy.StorageKey(key)).Value(value).ExSeconds(int64(d.ttl.Seconds())).Build()
	if err := d.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to set cached value: %w", err)
	}
	return nil
}

// Invalidate removes a token from the cache.
func (d *Distributed[T]) Invalidate(ctx context.Context, key string) error {
	cmd := d.client.B().Del().Key(d.strategy.StorageKey(key)).Build()
	if err := d.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to invalidate cached value: %w", err)
	}
	return nil
}

// Close releases resources associated with the cache client and encryption strategy.
func (d *Distributed[T]) Close() error {
	if err := d.strategy.Close(); err != nil {
		log.Warn().Err(err).Msg("error closing encryption strategy")
	}
	d.client.Close()
	return nil
}
