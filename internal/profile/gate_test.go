package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gateProfileYAML = `organization:
  profiles:
    - name: "gated"
      repositories: ["silk"]
      permissions: ["contents:read"]

pipeline:
  defaults:
    permissions: ["contents:read"]
`

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

func TestAwaitFirstGeneration_ReturnsAsSoonAsAGenerationLoads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gh := &mockGitHubClientForDaemon{yaml: gateProfileYAML}
		store := NewProfileStore()

		start := time.Now()
		err := AwaitFirstGeneration(t.Context(), store, gh, "acme:silk:profile.yaml")

		require.NoError(t, err)
		assert.Equal(t, time.Duration(0), time.Since(start), "a reachable source should not delay startup")
		assert.Equal(t, 1, gh.calls())

		profile, _, err := store.GetOrganizationProfile("gated")
		require.NoError(t, err, "the generation should be loaded before the gate opens")
		assert.Equal(t, NewSpecificScope("silk"), profile.Attrs.Scope)
	})
}

func TestAwaitFirstGeneration_RetriesAndLogsEachFailedAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)

		gh := &mockGitHubClientForDaemon{yaml: gateProfileYAML, err: errors.New("upstream unavailable")}
		store := NewProfileStore()

		done := make(chan error, 1)
		go func() {
			done <- AwaitFirstGeneration(t.Context(), store, gh, "acme:silk:profile.yaml")
		}()

		// Two attempts fail while the gate holds the service closed.
		synctest.Wait()
		assert.Equal(t, 1, gh.calls())

		time.Sleep(firstLoadRetryInterval)
		synctest.Wait()
		assert.Equal(t, 2, gh.calls())

		// The source recovers: the next attempt opens the gate.
		gh.setErr(nil)
		time.Sleep(firstLoadRetryInterval)
		synctest.Wait()

		require.NoError(t, <-done)
		assert.Equal(t, 3, gh.calls())

		_, _, err := store.GetOrganizationProfile("gated")
		require.NoError(t, err)

		var attempts []any
		for _, record := range logs() {
			if record["msg"] == "waiting for first organization profile generation" {
				assert.Contains(t, record["error"], "upstream unavailable")
				attempts = append(attempts, record["attempt"])
			}
		}
		assert.Equal(t, []any{float64(1), float64(2)}, attempts, "each failed attempt should be logged")
	})
}

func TestAwaitFirstGeneration_AbandonsOnContextCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gh := &mockGitHubClientForDaemon{err: errors.New("upstream unavailable")}
		store := NewProfileStore()

		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan error, 1)
		go func() {
			done <- AwaitFirstGeneration(ctx, store, gh, "acme:silk:profile.yaml")
		}()

		synctest.Wait()
		cancel()
		synctest.Wait()

		err := <-done
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

// The gate is a latch on the first load: once a generation is loaded, losing
// access to the source leaves the service serving what it has.
func TestAwaitFirstGeneration_LatchesOnFirstLoad(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gh := &mockGitHubClientForDaemon{yaml: gateProfileYAML}
		store := NewProfileStore()

		require.NoError(t, AwaitFirstGeneration(t.Context(), store, gh, "acme:silk:profile.yaml"))
		loaded := store.Digest()

		go PeriodicRefresh(t.Context(), store, gh, "acme:silk:profile.yaml")

		gh.setErr(errors.New("source no longer reachable"))
		time.Sleep(refreshInterval)
		synctest.Wait()

		require.Equal(t, 2, gh.calls(), "the background refresh should have attempted and failed")

		profile, _, err := store.GetOrganizationProfile("gated")
		require.NoError(t, err, "the loaded generation should still be served")
		assert.Equal(t, NewSpecificScope("silk"), profile.Attrs.Scope)
		assert.Equal(t, loaded, store.Digest())
	})
}
