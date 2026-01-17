package cache

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/rs/zerolog/log"
	"github.com/valkey-io/valkey-go"
)

// NewFromConfig creates a cache implementation based on the provided configuration.
// It returns the cache, a cleanup function, and any error encountered.
//
// The cache type must be either "memory" or "valkey". Any other value returns an error.
// For "valkey", the valkeyConfig.Address must be provided.
func NewFromConfig[T any](
	ctx context.Context,
	cacheConfig config.CacheConfig,
	valkeyConfig config.ValkeyConfig,
	ttl time.Duration,
	maxMemorySize int,
) (TokenCache[T], func() error, error) {
	switch cacheConfig.Type {
	case "valkey":
		log.Info().
			Str("cache_type", "valkey").
			Str("address", valkeyConfig.Address).
			Bool("tls", valkeyConfig.TLS).
			Msg("initializing distributed cache")

		if valkeyConfig.Address == "" {
			return nil, nil, fmt.Errorf("valkey address is required when cache type is valkey")
		}

		valkeyOpts := valkey.ClientOption{
			InitAddress: []string{valkeyConfig.Address},
		}

		// Configure TLS if enabled
		if valkeyConfig.TLS {
			valkeyOpts.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}

		valkeyClient, err := valkey.NewClient(valkeyOpts)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create valkey client: %w", err)
		}

		distributed, err := NewDistributed[T](valkeyClient, ttl)
		if err != nil {
			valkeyClient.Close()
			return nil, nil, fmt.Errorf("failed to create distributed cache: %w", err)
		}

		return distributed, distributed.Close, nil

	case "memory":
		log.Info().
			Str("cache_type", "memory").
			Msg("initializing in-memory cache")

		memory, err := NewMemory[T](ttl, maxMemorySize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create memory cache: %w", err)
		}

		return memory, func() error { return nil }, nil

	default:
		return nil, nil, fmt.Errorf("invalid cache type %q: must be either \"memory\" or \"valkey\"", cacheConfig.Type)
	}
}
