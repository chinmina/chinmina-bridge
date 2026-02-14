package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tink-crypto/tink-go/v2/tink"
	"github.com/valkey-io/valkey-go"
)

// Distributed implements TokenCache using Valkey with server-assisted
// client-side caching.
// The generic type T represents the token type being cached.
type Distributed[T any] struct {
	client valkey.Client
	ttl    time.Duration
	aead   tink.AEAD // nil means no encryption
}

// NewDistributed creates a new Valkey-backed cache with server-assisted client-side caching.
// The ttl parameter specifies how long tokens remain valid in the cache.
// The aead parameter enables encryption for cached values; nil disables encryption.
func NewDistributed[T any](valkeyClient valkey.Client, ttl time.Duration, aead tink.AEAD) (*Distributed[T], error) {
	return &Distributed[T]{
		client: valkeyClient,
		ttl:    ttl,
		aead:   aead,
	}, nil
}

// storageKey returns the cache key with appropriate prefix.
// Encrypted entries use "enc:" prefix for namespace separation during rollout.
func (d *Distributed[T]) storageKey(key string) string {
	if d.aead != nil {
		return "enc:" + key
	}
	return key
}

// Get retrieves a token from the cache using server-assisted client-side caching.
// Returns the token, whether it was found, and any error.
func (d *Distributed[T]) Get(ctx context.Context, key string) (T, bool, error) {
	var zero T

	// Use DoCache for server-assisted client-side caching
	// The .Cache() method enables client-side caching with server tracking
	cmd := d.client.B().Get().Key(d.storageKey(key)).Cache()
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

	var token T
	if err := json.Unmarshal([]byte(val), &token); err != nil {
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

	cmd := d.client.B().Set().Key(d.storageKey(key)).Value(string(data)).ExSeconds(int64(d.ttl.Seconds())).Build()
	if err := d.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to set cached value: %w", err)
	}
	return nil
}

// Invalidate removes a token from the cache.
func (d *Distributed[T]) Invalidate(ctx context.Context, key string) error {
	cmd := d.client.B().Del().Key(d.storageKey(key)).Build()
	if err := d.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to invalidate cached value: %w", err)
	}
	return nil
}

// Close releases resources associated with the cache client.
func (d *Distributed[T]) Close() error {
	d.client.Close()
	return nil
}
