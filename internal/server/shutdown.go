package server

import (
	"context"

	"log/slog"
)

type hookDefinition struct {
	name string
	fn   func(context.Context) error
}

// ShutdownHooks manages a collection of hooks to be executed during application shutdown.
// Hooks are executed in the order they were added, and execution continues even if a hook fails.
type ShutdownHooks struct {
	hooks []hookDefinition
}

// AddContext registers a shutdown hook that receives a context parameter.
// The hook will be executed during shutdown with a context that may have a deadline.
// Nil hooks are ignored with a warning logged.
func (s *ShutdownHooks) AddContext(name string, hook func(context.Context) error) {
	if s.hooks == nil {
		s.hooks = make([]hookDefinition, 0, 5)
	}
	if hook == nil {
		slog.Warn("attempted to add nil shutdown hook; ignoring", "hook", name)
		return
	}

	slog.Debug("adding shutdown hook", "hook", name)
	s.hooks = append(s.hooks, hookDefinition{name: name, fn: hook})
}

// Add registers a simple shutdown hook that does not need a context parameter.
// The hook is automatically wrapped to conform to the context-based signature.
// Nil hooks are ignored with a warning logged.
func (s *ShutdownHooks) Add(name string, hook func() error) {
	if hook == nil {
		slog.Warn("attempted to add nil shutdown hook; ignoring", "hook", name)
		return
	}

	s.AddContext(name, func(context.Context) error {
		return hook()
	})
}

// AddClose registers a shutdown hook for any resource with a Close() method.
// The closer's Close() method will be called during shutdown. Any return value is ignored.
// Nil closers are ignored with a warning logged.
func (s *ShutdownHooks) AddClose(name string, closer interface{ Close() }) {
	if closer == nil {
		slog.Warn("attempted to add nil shutdown hook; ignoring", "hook", name)
		return
	}

	s.AddContext(name, func(context.Context) error { closer.Close(); return nil })
}

// Execute runs all registered shutdown hooks in the order they were added.
// Each hook is executed with the provided context, and execution continues even if a hook fails.
// Success and failure of each hook is logged appropriately.
func (s *ShutdownHooks) Execute(ctx context.Context) {
	for _, hook := range s.hooks {
		hookLog := slog.With("hook", hook.name)

		hookLog.Info("shutdown started")
		if err := hook.fn(ctx); err != nil {
			hookLog.Warn("shutdown failed", "error", err)
		} else {
			hookLog.Info("shutdown complete")
		}
	}
}
