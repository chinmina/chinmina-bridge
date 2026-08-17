package server

import (
	"context"
	"sync"

	"log/slog"
)

type hookDefinition struct {
	name string
	fn   func(context.Context) error
}

// ShutdownHooks manages a collection of hooks to be executed during application shutdown.
// Hooks are executed in the order they were added, and execution continues even if a hook fails.
//
// A ShutdownHooks value must not be copied after first use.
type ShutdownHooks struct {
	hooks []hookDefinition

	// mu guards completed, and only completed. beginExecution is the sole
	// reader and writer of both.
	mu sync.Mutex
	// completed is created when execution begins and closed when it finishes.
	// A nil value means shutdown has not started. Waiting on a channel rather
	// than contending on a mutex (as sync.Once would) keeps the wait
	// observable: a blocked receive is a durably blocking operation, so the
	// behaviour can be tested under testing/synctest without real delays.
	completed chan struct{}
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
//
// Hooks run at most once for the lifetime of the value: the process has
// several exit paths (a startup failure, and the HTTP server's own shutdown
// wiring) and each of them calls Execute, so without this guard a normal
// shutdown would flush telemetry and close the cache twice. A caller arriving
// while another is mid-execution blocks until that execution finishes, so
// Execute returning always means shutdown is complete — the deferred
// startup-path call cannot let the process exit while the server-shutdown
// call is still flushing.
func (s *ShutdownHooks) Execute(ctx context.Context) {
	completed, owner := s.beginExecution()
	if !owner {
		<-completed
		return
	}

	// Closing on the way out releases any waiter even if a hook panics.
	defer close(completed)

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

// beginExecution claims the right to run the hooks. It returns the channel
// tracking completion of this shutdown, and whether the caller owns it: an
// owner runs the hooks and closes the channel when they are done, and any
// other caller waits on it.
//
// The lock is deliberately confined to this function: it must not be held
// while the hooks run, both because a waiter needs it to reach the channel and
// because holding a lock across caller-supplied callbacks invites deadlock.
func (s *ShutdownHooks) beginExecution() (completed chan struct{}, owner bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.completed != nil {
		return s.completed, false
	}

	s.completed = make(chan struct{})

	return s.completed, true
}
