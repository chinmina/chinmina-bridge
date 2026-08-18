package main

import (
	"context"
	"errors"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/config"
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

func TestStartProfileRefresh(t *testing.T) {
	t.Run("does nothing when no organization profile location is configured", func(t *testing.T) {
		store := profile.NewProfileStore()
		before := store.Digest()

		// The GitHub configuration is deliberately empty: reaching the client
		// would fail, so returning cleanly proves nothing was loaded, no gate
		// was entered and startup is unaffected.
		err := startProfileRefresh(t.Context(), t.Context(), config.Config{}, store)

		require.NoError(t, err)
		assert.Equal(t, before, store.Digest())
	})

	// Startup now waits on the configured location, so a location that can
	// never resolve has to fail here. Left to the gate it is indistinguishable
	// from an outage and retries forever, holding the deployment closed.
	t.Run("rejects a malformed organization profile location", func(t *testing.T) {
		locations := []string{
			"acme:silk",
			"profile.yaml",
			":silk:docs/profile.yaml",
			"acme::docs/profile.yaml",
			"acme:silk:",
		}

		for _, location := range locations {
			t.Run(location, func(t *testing.T) {
				cfg := config.Config{}
				cfg.Server.OrgProfile = location

				err := startProfileRefresh(t.Context(), t.Context(), cfg, profile.NewProfileStore())

				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid organization profile location")
			})
		}
	})
}
