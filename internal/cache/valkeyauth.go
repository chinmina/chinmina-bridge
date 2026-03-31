package cache

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/iamcacheauth"
	"github.com/valkey-io/valkey-go"
)

// StaticCredentialsFn returns an AuthCredentialsFn that always returns the
// configured username and password.
func StaticCredentialsFn(username, password string) func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
	return func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
		return valkey.AuthCredentials{
			Username: username,
			Password: password,
		}, nil
	}
}

// IAMCredentialsFn creates an iamcacheauth TokenGenerator from the provided
// config and AWS config, and returns an AuthCredentialsFn that generates a
// fresh IAM token per connection.
//
// The aws.Config parameter allows callers to inject credentials for testing.
func IAMCredentialsFn(cfg config.ValkeyConfig, awsCfg aws.Config) (func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error), error) {
	var opts []iamcacheauth.Option
	if cfg.IAMServerless {
		opts = append(opts, iamcacheauth.WithServerless())
	}

	gen, err := iamcacheauth.NewElastiCache(cfg.Username, cfg.IAMCacheName, awsCfg, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating IAM token generator: %w", err)
	}

	username := cfg.Username

	slog.Debug("IAM token generator created",
		"username", username,
		"cache_name", cfg.IAMCacheName,
		"serverless", cfg.IAMServerless,
		"region", awsCfg.Region,
	)

	return func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
		// AuthCredentialsFn doesn't accept a context.Context. The iamcacheauth
		// README notes context only controls credential retrieval timeout
		// (signing is a local CPU op). context.Background() avoids capturing
		// a startup context that could be cancelled.

		// Retrieve credentials separately for debug logging before token generation.
		ctx := context.Background()
		awsCreds, credErr := awsCfg.Credentials.Retrieve(ctx)
		if credErr != nil {
			slog.Debug("IAM credential retrieval failed",
				"error", credErr,
			)
		} else {
			slog.Debug("IAM auth token: pre-sign state",
				"username", username,
				"cache_name", cfg.IAMCacheName,
				"serverless", cfg.IAMServerless,
				"region", awsCfg.Region,
				"access_key_id", awsCreds.AccessKeyID,
				"has_secret_key", awsCreds.SecretAccessKey != "",
				"has_session_token", awsCreds.SessionToken != "",
				"credential_source", awsCreds.Source,
			)
		}

		token, err := gen.Token(ctx)
		if err != nil {
			slog.Debug("IAM auth token generation failed",
				"error", err,
			)
			return valkey.AuthCredentials{}, fmt.Errorf("generating IAM auth token: %w", err)
		}

		slog.Debug("IAM auth token generated",
			"token_length", len(token),
			"token_prefix", token[:min(80, len(token))],
		)

		return valkey.AuthCredentials{
			Username: username,
			Password: token,
		}, nil
	}, nil
}
