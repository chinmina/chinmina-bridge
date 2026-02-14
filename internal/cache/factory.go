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
// It returns the cache and any error encountered.
//
// The cache type must be either "memory" or "valkey". Any other value returns an error.
// For "valkey", the cacheConfig.Valkey.Address must be provided.
func NewFromConfig[T any](
	ctx context.Context,
	cacheConfig config.CacheConfig,
	ttl time.Duration,
	maxMemorySize int,
) (TokenCache[T], error) {
	switch cacheConfig.Type {
	case "valkey":
		log.Info().
			Str("cache_type", "valkey").
			Str("address", cacheConfig.Valkey.Address).
			Bool("tls", cacheConfig.Valkey.TLS).
			Msg("initializing distributed cache")

		if cacheConfig.Valkey.Address == "" {
			return nil, fmt.Errorf("valkey address is required when cache type is valkey")
		}

		valkeyOpts := valkey.ClientOption{
			InitAddress: []string{cacheConfig.Valkey.Address},
			Username:    cacheConfig.Valkey.Username,
			Password:    cacheConfig.Valkey.Password,
		}

		// Configure TLS if enabled
		if cacheConfig.Valkey.TLS {
			valkeyOpts.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}

		valkeyClient, err := valkey.NewClient(valkeyOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to create valkey client: %w", err)
		}

		distributed, err := NewDistributed[T](valkeyClient, ttl, nil)
		if err != nil {
			valkeyClient.Close()
			return nil, fmt.Errorf("failed to create distributed cache: %w", err)
		}

		instrumented := NewInstrumented(distributed, "distributed")
		return instrumented, nil

	case "memory":
		log.Info().
			Str("cache_type", "memory").
			Msg("initializing in-memory cache")

		memory, err := NewMemory[T](ttl, maxMemorySize)
		if err != nil {
			return nil, fmt.Errorf("failed to create memory cache: %w", err)
		}

		instrumented := NewInstrumented(memory, "memory")
		return instrumented, nil

	default:
		return nil, fmt.Errorf("invalid cache type %q: must be either \"memory\" or \"valkey\"", cacheConfig.Type)
	}
}
