package server

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShutdownHooks_AddContext(t *testing.T) {
	t.Run("adds hook successfully", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		called := false

		hooks.AddContext("test", func(ctx context.Context) error {
			called = true
			return nil
		})

		require.Len(t, hooks.hooks, 1)
		assert.Equal(t, "test", hooks.hooks[0].name)

		// Verify the hook works
		hooks.Execute(context.Background())
		assert.True(t, called, "hook should have been called")
	})

	t.Run("ignores nil hook", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		hooks.AddContext("nil-hook", nil)
		require.Len(t, hooks.hooks, 0, "nil hook should not be added")
	})

	t.Run("initializes hooks slice if nil", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		assert.Nil(t, hooks.hooks)

		hooks.AddContext("init", func(ctx context.Context) error { return nil })
		assert.NotNil(t, hooks.hooks)
		require.Len(t, hooks.hooks, 1)
	})

	t.Run("adds multiple hooks", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		hooks.AddContext("first", func(ctx context.Context) error { return nil })
		hooks.AddContext("second", func(ctx context.Context) error { return nil })
		hooks.AddContext("third", func(ctx context.Context) error { return nil })

		require.Len(t, hooks.hooks, 3)
		assert.Equal(t, "first", hooks.hooks[0].name)
		assert.Equal(t, "second", hooks.hooks[1].name)
		assert.Equal(t, "third", hooks.hooks[2].name)
	})
}

func TestShutdownHooks_Add(t *testing.T) {
	t.Run("wraps and adds hook successfully", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		called := false

		hooks.Add("test", func() error {
			called = true
			return nil
		})

		require.Len(t, hooks.hooks, 1)
		assert.Equal(t, "test", hooks.hooks[0].name)

		// Verify the hook works and context is properly ignored
		hooks.Execute(context.Background())
		assert.True(t, called, "hook should have been called")
	})

	t.Run("ignores nil hook", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		hooks.Add("nil-hook", nil)
		require.Len(t, hooks.hooks, 0, "nil hook should not be added")
	})

	t.Run("wrapped hook returns error correctly", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		expectedErr := errors.New("test error")
		var returnedErr error

		hooks.Add("error-hook", func() error {
			return expectedErr
		})

		// Execute and capture the error through the hook function
		if len(hooks.hooks) > 0 {
			returnedErr = hooks.hooks[0].fn(context.Background())
		}

		assert.Equal(t, expectedErr, returnedErr, "wrapped hook should return the original error")
	})
}

func TestShutdownHooks_AddClose(t *testing.T) {
	t.Run("wraps closer successfully", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		closeCalled := false

		closer := &mockCloser{
			closeFn: func() {
				closeCalled = true
			},
		}

		hooks.AddClose("test-closer", closer)
		require.Len(t, hooks.hooks, 1)
		assert.Equal(t, "test-closer", hooks.hooks[0].name)

		// Verify the closer is called
		hooks.Execute(context.Background())
		assert.True(t, closeCalled, "Close() should have been called")
	})

	t.Run("ignores nil closer", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		hooks.AddClose("nil-closer", nil)
		require.Len(t, hooks.hooks, 0, "nil closer should not be added")
	})

	t.Run("does not propagate closer errors", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		closer := &mockCloser{
			closeFn: func() {
				// Close that would panic is safely ignored
			},
		}

		hooks.AddClose("closer", closer)

		// Execute should not return any error even if Close() might fail
		// (since AddClose wraps it to ignore return values)
		err := hooks.hooks[0].fn(context.Background())
		assert.NoError(t, err, "wrapped closer should always return nil")
	})
}

func TestShutdownHooks_Execute(t *testing.T) {
	t.Run("executes hooks in order", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		var order []string

		hooks.AddContext("first", func(ctx context.Context) error {
			order = append(order, "first")
			return nil
		})
		hooks.AddContext("second", func(ctx context.Context) error {
			order = append(order, "second")
			return nil
		})
		hooks.AddContext("third", func(ctx context.Context) error {
			order = append(order, "third")
			return nil
		})

		hooks.Execute(context.Background())

		assert.Equal(t, []string{"first", "second", "third"}, order,
			"hooks should execute in the order they were added")
	})

	t.Run("continues execution when hook fails", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		var executed []string

		hooks.AddContext("first", func(ctx context.Context) error {
			executed = append(executed, "first")
			return nil
		})
		hooks.AddContext("failing", func(ctx context.Context) error {
			executed = append(executed, "failing")
			return errors.New("hook failed")
		})
		hooks.AddContext("third", func(ctx context.Context) error {
			executed = append(executed, "third")
			return nil
		})

		hooks.Execute(context.Background())

		assert.Equal(t, []string{"first", "failing", "third"}, executed,
			"all hooks should execute even when one fails")
	})

	t.Run("passes context to hooks", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		type ctxKey struct{}
		expectedValue := "test-value"

		var receivedValue string
		hooks.AddContext("ctx-check", func(ctx context.Context) error {
			receivedValue = ctx.Value(ctxKey{}).(string)
			return nil
		})

		ctx := context.WithValue(context.Background(), ctxKey{}, expectedValue)
		hooks.Execute(ctx)

		assert.Equal(t, expectedValue, receivedValue, "context should be passed to hooks")
	})

	t.Run("handles empty hooks list", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		// Should not panic
		hooks.Execute(context.Background())
	})

	t.Run("handles nil hooks slice", func(t *testing.T) {
		hooks := &ShutdownHooks{hooks: nil}
		// Should not panic
		hooks.Execute(context.Background())
	})
}

func TestShutdownHooks_Integration(t *testing.T) {
	t.Run("mixed hook types execute correctly", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		var order []string

		// Add different types of hooks
		hooks.AddContext("context-hook", func(ctx context.Context) error {
			order = append(order, "context")
			return nil
		})

		hooks.Add("simple-hook", func() error {
			order = append(order, "simple")
			return nil
		})

		closer := &mockCloser{
			closeFn: func() {
				order = append(order, "closer")
			},
		}
		hooks.AddClose("close-hook", closer)

		hooks.Execute(context.Background())

		assert.Equal(t, []string{"context", "simple", "closer"}, order,
			"all hook types should execute in order")
	})

	t.Run("multiple errors do not stop execution", func(t *testing.T) {
		hooks := &ShutdownHooks{}
		var executed []string

		hooks.Add("error1", func() error {
			executed = append(executed, "error1")
			return errors.New("first error")
		})

		hooks.AddContext("success", func(ctx context.Context) error {
			executed = append(executed, "success")
			return nil
		})

		hooks.Add("error2", func() error {
			executed = append(executed, "error2")
			return errors.New("second error")
		})

		hooks.Execute(context.Background())

		assert.Equal(t, []string{"error1", "success", "error2"}, executed,
			"execution should continue through multiple errors")
	})
}

// mockCloser implements interface{ Close() } for testing
type mockCloser struct {
	closeFn func()
}

func (m *mockCloser) Close() {
	if m.closeFn != nil {
		m.closeFn()
	}
}
