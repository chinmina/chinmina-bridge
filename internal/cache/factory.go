package cache

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/chinmina/chinmina-bridge/internal/cache/encryption"
	"github.com/chinmina/chinmina-bridge/internal/config"
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
		slog.Info("initializing distributed cache",
			"cache_type", "valkey",
			"address", cacheConfig.Valkey.Address,
			"tls", cacheConfig.Valkey.TLS,
			"iam_enabled", cacheConfig.Valkey.IAMEnabled,
		)

		if cacheConfig.Valkey.Address == "" {
			return nil, fmt.Errorf("valkey address is required when cache type is valkey")
		}

		valkeyOpts := valkey.ClientOption{
			InitAddress: []string{cacheConfig.Valkey.Address},
		}

		if cacheConfig.Valkey.IAMEnabled {
			awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
			if err != nil {
				return nil, fmt.Errorf("loading AWS config for IAM auth: %w", err)
			}

			credsFn, err := IAMCredentialsFn(cacheConfig.Valkey, awsCfg)
			if err != nil {
				return nil, fmt.Errorf("configuring IAM credentials: %w", err)
			}
			valkeyOpts.AuthCredentialsFn = credsFn
			valkeyOpts.ConnLifetime = 11 * time.Hour
		} else {
			valkeyOpts.AuthCredentialsFn = StaticCredentialsFn(
				cacheConfig.Valkey.Username,
				cacheConfig.Valkey.Password,
			)
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

		// Initialize encryption strategy if enabled.
		var strategy EncryptionStrategy
		if cacheConfig.Encryption.Enabled {
			var aead *encryption.RefreshableAEAD
			var err error

			switch {
			case cacheConfig.Encryption.KeysetFile != "":
				aead, err = encryption.NewRefreshableAEADFromFile(ctx, cacheConfig.Encryption.KeysetFile)
			default:
				aead, err = encryption.NewRefreshableAEAD(ctx, cacheConfig.Encryption.KeysetURI, cacheConfig.Encryption.KMSEnvelopeKeyURI)
			}
			if err != nil {
				valkeyClient.Close()
				return nil, fmt.Errorf("initializing encryption: %w", err)
			}
			strategy = NewInstrumentedStrategy(NewTinkEncryptionStrategy(aead))

			slog.Info("cache encryption enabled with automatic keyset refresh")
		}

		distributed, err := NewDistributed[T](valkeyClient, ttl, strategy)
		if err != nil {
			if strategy != nil {
				_ = strategy.Close()
			}
			valkeyClient.Close()
			return nil, fmt.Errorf("failed to create distributed cache: %w", err)
		}

		instrumented := NewInstrumented(distributed, "distributed")
		return instrumented, nil

	case "memory":
		slog.Info("initializing in-memory cache", "cache_type", "memory")

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
