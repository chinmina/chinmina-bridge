// Package repeat runs an action on a schedule until its context is cancelled.
package repeat

import (
	"context"
	"log/slog"
	"time"
)

// Task runs an action on a schedule until its context is cancelled.
//
// Two intervals, chosen by whether the action has ever succeeded — never by how
// it last failed. Retrying sooner does not make an upstream recover sooner;
// what differs is the cost of waiting. Before the first success a caller is
// typically blocked on it, so FirstInterval is short. Afterwards the work is
// established and staleness is cheap, so Interval applies to every attempt,
// including one that follows a failure.
type Task struct {
	// Name identifies the work in log records.
	Name string

	// Attrs are additional log attributes describing the work, applied to
	// every record this task emits.
	Attrs []any

	// FirstInterval is the delay between attempts before the first success.
	FirstInterval time.Duration

	// Interval is the delay between attempts once the action has succeeded.
	Interval time.Duration

	// Action is the work to repeat. Its failures are reported by the task, so
	// it should return them rather than logging them itself.
	Action func(context.Context) error
}

// Start runs the task in the background and returns a channel that is closed
// once the action has succeeded for the first time.
//
// The channel is a latch, not a stream: it is closed exactly once and stays
// closed, so any number of callers can wait on it, none can miss it, and there
// is nothing to drain. A caller gating on the first success selects on it
// alongside its own context.
//
// The task runs until ctx is cancelled.
func (t Task) Start(ctx context.Context) <-chan struct{} {
	ready := make(chan struct{})

	go t.run(ctx, ready)

	return ready
}

func (t Task) run(ctx context.Context, ready chan<- struct{}) {
	everSucceeded := false

	for {
		err := t.Action(ctx)

		switch {
		case err != nil:
			t.logFailure(err)
		case !everSucceeded:
			everSucceeded = true
			close(ready)
		}

		interval := t.Interval
		if !everSucceeded {
			interval = t.FirstInterval
		}

		select {
		case <-time.After(interval):
			// try again
		case <-ctx.Done():
			slog.Info("background task shutting down gracefully", "task", t.Name)
			return
		}
	}
}

// logFailure reports a failed attempt. Every failure is reported here, at a
// single call site, so the record is the same shape whether or not the action
// has ever succeeded.
func (t Task) logFailure(err error) {
	attrs := append([]any{"task", t.Name, "error", err}, t.Attrs...)

	slog.Warn("background task failed", attrs...)
}
