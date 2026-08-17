package main

import (
	"context"
	"errors"
	"testing"

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
