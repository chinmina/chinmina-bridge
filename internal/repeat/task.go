// Package repeat schedules repeating background work.
package repeat

import (
	"context"
	"log/slog"
	"time"
)

// Task runs an action on a schedule until its context is cancelled.
//
// The interval is chosen by whether the action has ever succeeded, never by how
// it last failed: retrying sooner does not make an upstream recover sooner.
// What differs is the cost of waiting, and before the first success a caller is
// usually blocked on it.
type Task struct {
	Name  string // identifies the work in log records
	Attrs []any  // further log attributes, applied to every record

	FirstInterval time.Duration // delay before the first success
	Interval      time.Duration // delay thereafter, failed attempts included

	// Action returns its failures rather than logging them; the task logs them.
	Action func(context.Context) error
}

// Start runs the task in the background, returning a channel closed on the
// action's first success.
//
// Closing rather than sending makes it a latch: no caller can miss the signal,
// and nothing has to drain it to keep the task running.
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

// logFailure is the only reporting site, so a failure logs the same shape
// whether or not the action has ever succeeded.
func (t Task) logFailure(err error) {
	attrs := append([]any{"task", t.Name, "error", err}, t.Attrs...)

	slog.Warn("background task failed", attrs...)
}
