package repeat_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/repeat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	firstInterval = time.Second
	interval      = time.Minute
)

// stubAction stands in for the work being repeated, so the loop is exercised
// without any of the action's own dependencies.
type stubAction struct {
	calls atomic.Int32
	mu    sync.Mutex
	err   error
}

func (s *stubAction) run(context.Context) error {
	s.calls.Add(1)

	return s.getErr()
}

// getErr and setErr guard err: it is written by the test goroutine and read by
// the task goroutine.
func (s *stubAction) getErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.err
}

func (s *stubAction) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.err = err
}

func (s *stubAction) count() int {
	return int(s.calls.Load())
}

func newTask(action *stubAction) repeat.Task {
	return repeat.Task{
		Name:          "test task",
		Attrs:         []any{"location", "acme:silk:profile.yaml"},
		FirstInterval: firstInterval,
		Interval:      interval,
		Action:        action.run,
	}
}

func closed(ready <-chan struct{}) bool {
	select {
	case <-ready:
		return true
	default:
		return false
	}
}

// captureLogs redirects the default logger to a buffer for the duration of the
// test, returning a function that decodes the records written so far.
func captureLogs(t *testing.T) func() []map[string]any {
	t.Helper()

	buf := &bytes.Buffer{}
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(original) })

	return func() []map[string]any {
		var records []map[string]any
		for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var record map[string]any
			require.NoError(t, json.Unmarshal([]byte(line), &record))
			records = append(records, record)
		}
		return records
	}
}

func TestTask_ReadyClosesOnFirstSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		action := &stubAction{}

		ready := newTask(action).Start(t.Context())
		synctest.Wait()

		assert.Equal(t, 1, action.count(), "the first attempt should run immediately")
		assert.True(t, closed(ready), "a caller gating on the first success should be released")
	})
}

// The latch holds the caller closed for as long as the action keeps failing:
// this is what stops a service serving before it has anything to serve.
func TestTask_ReadyStaysOpenWhileFailing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		action := &stubAction{err: errors.New("upstream unavailable")}

		ready := newTask(action).Start(t.Context())
		synctest.Wait()
		require.False(t, closed(ready))

		time.Sleep(firstInterval)
		synctest.Wait()
		assert.Equal(t, 2, action.count(), "failures should retry at the short interval")
		assert.False(t, closed(ready))

		action.setErr(nil)
		time.Sleep(firstInterval)
		synctest.Wait()

		assert.Equal(t, 3, action.count())
		assert.True(t, closed(ready), "recovery should release the caller")
	})
}

// Once the first success has happened the long interval governs every attempt,
// including one that follows a failure: retrying sooner would not make the
// upstream recover sooner, and the work is no longer blocking anyone.
func TestTask_IntervalAfterFirstSuccess(t *testing.T) {
	tests := []struct {
		name     string
		afterErr error
	}{
		{name: "after a success"},
		{name: "after a failure", afterErr: errors.New("upstream unavailable")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				action := &stubAction{}

				newTask(action).Start(t.Context())
				synctest.Wait()
				require.Equal(t, 1, action.count())

				action.setErr(tt.afterErr)

				time.Sleep(firstInterval)
				synctest.Wait()
				assert.Equal(t, 1, action.count(), "the short interval should no longer apply")

				time.Sleep(interval - firstInterval)
				synctest.Wait()
				assert.Equal(t, 2, action.count())

				time.Sleep(interval)
				synctest.Wait()
				assert.Equal(t, 3, action.count(), "the long interval should keep applying")
			})
		})
	}
}

func TestTask_StopsOnContextCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		action := &stubAction{}

		ctx, cancel := context.WithCancel(context.Background())
		newTask(action).Start(ctx)

		synctest.Wait()
		require.Equal(t, 1, action.count())

		cancel()
		synctest.Wait()

		time.Sleep(interval)
		synctest.Wait()

		assert.Equal(t, 1, action.count(), "no further attempts after cancellation")
	})
}

// Every failure is reported the same way, whether or not the action has ever
// succeeded — one call site, one record shape.
func TestTask_LogsEveryFailureIdentically(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)

		action := &stubAction{err: errors.New("upstream unavailable")}

		newTask(action).Start(t.Context())
		synctest.Wait()

		// Fail, succeed (releasing the latch), then fail again.
		action.setErr(nil)
		time.Sleep(firstInterval)
		synctest.Wait()

		action.setErr(errors.New("upstream unavailable"))
		time.Sleep(interval)
		synctest.Wait()

		var failures []map[string]any
		for _, record := range logs() {
			if record["msg"] == "background task failed" {
				failures = append(failures, record)
			}
		}

		require.Len(t, failures, 2, "a failure either side of the first success should both be reported")
		for _, failure := range failures {
			assert.Equal(t, "test task", failure["task"])
			assert.Equal(t, "acme:silk:profile.yaml", failure["location"])
			assert.Equal(t, "upstream unavailable", failure["error"])
		}
	})
}
