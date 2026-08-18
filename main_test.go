package main

import (
	"context"
	"errors"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/jwt/jwxtest"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunWithShutdownHooks(t *testing.T) {
	t.Run("runs hooks when startup fails before serving", func(t *testing.T) {
		expectedErr := errors.New("startup failed")
		var executed []string

		err := runWithShutdownHooks(context.Background(), func(ctx context.Context, hooks *server.ShutdownHooks) error {
			hooks.Add("telemetry", func() error {
				executed = append(executed, "telemetry")
				return nil
			})
			hooks.Add("cache", func() error {
				executed = append(executed, "cache")
				return nil
			})

			return expectedErr
		})

		require.Error(t, err)
		assert.Equal(t, expectedErr, err, "the startup error is returned unchanged")
		assert.Equal(t, []string{"telemetry", "cache"}, executed,
			"hooks registered before the failure must still run, so telemetry describing the failure is flushed")
	})

	t.Run("runs hooks exactly once when the serving path has already run them", func(t *testing.T) {
		calls := 0

		err := runWithShutdownHooks(context.Background(), func(ctx context.Context, hooks *server.ShutdownHooks) error {
			hooks.Add("telemetry", func() error {
				calls++
				return nil
			})

			// The HTTP server's RegisterOnShutdown wiring executes the hooks on
			// a normal shutdown, before startup returns.
			hooks.Execute(ctx)

			return nil
		})

		require.NoError(t, err)
		assert.Equal(t, 1, calls, "the server shutdown path and the deferred startup path must not double-execute hooks")
	})

	t.Run("runs hooks when startup returns without serving", func(t *testing.T) {
		calls := 0

		err := runWithShutdownHooks(context.Background(), func(ctx context.Context, hooks *server.ShutdownHooks) error {
			hooks.Add("cache", func() error {
				calls++
				return nil
			})

			return nil
		})

		require.NoError(t, err)
		assert.Equal(t, 1, calls)
	})

	t.Run("runs hooks when startup panics", func(t *testing.T) {
		calls := 0

		assert.Panics(t, func() {
			_ = runWithShutdownHooks(context.Background(), func(ctx context.Context, hooks *server.ShutdownHooks) error {
				hooks.Add("cache", func() error {
					calls++
					return nil
				})

				panic("startup exploded")
			})
		})

		assert.Equal(t, 1, calls, "an unwinding panic is still an exit path")
	})
}

// validConfig passes offline validation, so each case can vary only the field
// it exercises.
func validConfig(t *testing.T) config.Config {
	t.Helper()

	return config.Config{
		Authorization: config.AuthorizationConfig{
			Audience:                  "test-audience",
			BuildkiteOrganizationSlug: "test-org",
			IssuerURL:                 "https://agent.buildkite.com",
		},
		Buildkite: config.BuildkiteConfig{
			Token: "test-buildkite-token",
		},
		Cache: config.CacheConfig{Type: "memory"},
		Github: config.GithubConfig{
			PrivateKey:     jwxtest.NewJWK(t).PrivateKeyPEM(),
			ApplicationID:  12345,
			InstallationID: 67890,
		},
	}
}

func TestValidateConfiguration_Valid(t *testing.T) {
	tests := []struct {
		name       string
		modify     func(*config.Config)
		expectPath string
		expectOrg  string
	}{
		{
			name:   "no base path and no organization profile",
			modify: func(*config.Config) {},
		},
		{
			name:       "base path is normalized",
			modify:     func(c *config.Config) { c.Server.BasePath = "chinmina/" },
			expectPath: "/chinmina",
		},
		{
			name:      "organization profile location is retained",
			modify:    func(c *config.Config) { c.Server.OrgProfile = "acme:silk:profile.yaml" },
			expectOrg: "acme:silk:profile.yaml",
		},
		{
			name: "a path containing colons is part of the location",
			modify: func(c *config.Config) {
				c.Server.OrgProfile = "acme:silk:some:nested:path.yaml"
			},
			expectOrg: "acme:silk:some:nested:path.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig(t)
			tt.modify(&cfg)

			validated, err := validateConfiguration(cfg)

			require.NoError(t, err)
			assert.Equal(t, tt.expectPath, validated.basePath)
			assert.Equal(t, tt.expectOrg, validated.orgProfileLocation)
			assert.NotNil(t, validated.authorizer)
		})
	}
}

func TestValidateConfiguration_Invalid(t *testing.T) {
	tests := []struct {
		name          string
		modify        func(*config.Config)
		expectedError string
	}{
		{
			name:          "base path with double slashes",
			modify:        func(c *config.Config) { c.Server.BasePath = "/chinmina//bridge" },
			expectedError: "invalid base path",
		},
		{
			name: "authorization configuration that cannot be used",
			modify: func(c *config.Config) {
				c.Authorization.ConfigurationStatic = "not-a-jwks"
			},
			expectedError: "authorizer configuration failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig(t)
			tt.modify(&cfg)

			_, err := validateConfiguration(cfg)

			require.Error(t, err)
			assert.ErrorContains(t, err, tt.expectedError)
		})
	}
}

// These moved from the gate to the offline stage; reaching the gate with an
// unresolvable location is the failure ValidateLocation exists to prevent.
func TestValidateConfiguration_MalformedProfileLocation(t *testing.T) {
	locations := []string{
		"acme:silk",
		"profile.yaml",
		":silk:docs/profile.yaml",
		"acme::docs/profile.yaml",
		"acme:silk:",
	}

	for _, location := range locations {
		t.Run(location, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Server.OrgProfile = location

			_, err := validateConfiguration(cfg)

			require.Error(t, err)
			assert.ErrorContains(t, err, "invalid organization profile location")
		})
	}
}

func TestConfigureUpstreamClients_ProfileSource(t *testing.T) {
	tests := []struct {
		name             string
		orgProfile       string
		expectProfileSrc bool
	}{
		{name: "constructed when an organization profile is configured", orgProfile: "acme:silk:profile.yaml", expectProfileSrc: true},
		{name: "absent when no organization profile is configured", orgProfile: "", expectProfileSrc: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Server.OrgProfile = tt.orgProfile

			validated, err := validateConfiguration(cfg)
			require.NoError(t, err)

			hooks := &server.ShutdownHooks{}
			t.Cleanup(func() { hooks.Execute(t.Context()) })

			clients, err := configureUpstreamClients(t.Context(), cfg, validated, hooks)

			require.NoError(t, err)
			require.NotNil(t, clients.tokenCache)
			assert.Equal(t, tt.expectProfileSrc, clients.profileSource != nil)
		})
	}
}

func TestConfigureUpstreamClients_ConfigurationError(t *testing.T) {
	cfg := validConfig(t)
	cfg.Cache.Type = "not-a-cache-backend"

	validated, err := validateConfiguration(cfg)
	require.NoError(t, err)

	hooks := &server.ShutdownHooks{}
	t.Cleanup(func() { hooks.Execute(t.Context()) })

	_, err = configureUpstreamClients(t.Context(), cfg, validated, hooks)

	require.Error(t, err)
	assert.ErrorContains(t, err, "cache configuration failed")
}

func TestStartProfileRefresh_NotConfigured(t *testing.T) {
	store := profile.NewProfileStore()
	before := store.Digest()

	// Returning cleanly is the assertion: nothing loaded, no gate entered, so an
	// unconfigured deployment starts as it always did.
	err := startProfileRefresh(t.Context(), store, nil, "", profile.DefaultAppOnly)

	require.NoError(t, err)
	assert.Equal(t, before, store.Digest())
}

func TestAwaitFirstLoad(t *testing.T) {
	t.Run("returns once the first load is signalled", func(t *testing.T) {
		ready := make(chan struct{})
		close(ready)

		assert.NoError(t, awaitFirstLoad(t.Context(), ready))
	})

	t.Run("abandons the wait when the context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := awaitFirstLoad(ctx, make(chan struct{}))

		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Contains(t, err.Error(), "initial organization profile load abandoned")
	})
}
