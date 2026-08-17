package profile

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGitHubClientForDaemon implements GitHubClient for daemon testing
type mockGitHubClientForDaemon struct {
	yaml      string
	mu        sync.RWMutex
	err       error
	callCount atomic.Int32
	panicOn   int // panic on this call number (0 = never)
}

func (m *mockGitHubClientForDaemon) GetFileContent(ctx context.Context, owner, repo, path string) (string, error) {
	callNum := int(m.callCount.Add(1))

	if m.panicOn > 0 && callNum == m.panicOn {
		panic("mock panic for testing")
	}

	m.mu.RLock()
	err := m.err
	m.mu.RUnlock()

	if err != nil {
		return "", err
	}

	return m.yaml, nil
}

func (m *mockGitHubClientForDaemon) setErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

func (m *mockGitHubClientForDaemon) calls() int {
	return int(m.callCount.Load())
}

func TestRefresh_Success(t *testing.T) {
	validYAML := `organization:
  profiles:
    - name: "test-profile"
      repositories: ["silk"]
      permissions: ["contents:read"]

pipeline:
  defaults:
    permissions: ["contents:read"]
`

	gh := &mockGitHubClientForDaemon{
		yaml: validYAML,
	}

	store := NewProfileStore()
	ctx := context.Background()

	err := refresh(ctx, store, gh, "acme:silk:profile.yaml")
	require.NoError(t, err)

	// Verify the profile was fetched and store was updated
	assert.Equal(t, 1, gh.calls())

	// Verify store has the profile
	profile, _, err := store.GetOrganizationProfile("test-profile")
	require.NoError(t, err, "profile should be in store")
	assert.Equal(t, NewSpecificScope("silk"), profile.Attrs.Scope)
}

// refresh reports failure to its caller instead of logging it: the startup gate
// and the background loop treat a failed attempt differently.
func TestRefresh_Failure(t *testing.T) {
	tests := []struct {
		name string
		gh   *mockGitHubClientForDaemon
	}{
		{
			name: "retrieval error",
			gh:   &mockGitHubClientForDaemon{err: errors.New("github error")},
		},
		{
			name: "invalid yaml",
			gh:   &mockGitHubClientForDaemon{yaml: "invalid: yaml: content: ["},
		},
		{
			name: "panic is recovered and returned",
			gh:   &mockGitHubClientForDaemon{panicOn: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewProfileStore()
			initialDigest := store.Digest()

			err := refresh(context.Background(), store, tt.gh, "acme:silk:profile.yaml")

			require.Error(t, err)
			assert.Equal(t, 1, tt.gh.calls(), "fetch should have been attempted")
			assert.Equal(t, initialDigest, store.Digest(), "store should not be updated")
		})
	}
}

func TestPeriodicRefresh_DelaysFirstRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		validYAML := `organization:
  profiles:
    - name: "immediate"
      repositories: ["silk"]
      permissions: ["contents:read"]

pipeline:
  defaults:
    permissions: ["contents:read"]
`

		gh := &mockGitHubClientForDaemon{
			yaml: validYAML,
		}

		store := NewProfileStore()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go PeriodicRefresh(ctx, store, gh, "acme:silk:profile.yaml")

		// Wait for goroutine to reach waiting state
		synctest.Wait()

		// AwaitFirstGeneration owns the first load, so the loop must not fetch
		// again at boot.
		assert.Equal(t, 0, gh.calls(), "first refresh should wait a full interval")

		time.Sleep(5 * time.Minute)
		synctest.Wait()
		assert.Equal(t, 1, gh.calls())

		profile, _, err := store.GetOrganizationProfile("immediate")
		require.NoError(t, err)
		assert.Equal(t, NewSpecificScope("silk"), profile.Attrs.Scope)
	})
}

func TestPeriodicRefresh_MultipleCycles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		validYAML := `organization:
  profiles:
    - name: "periodic"
      repositories: ["silk"]
      permissions: ["contents:read"]

pipeline:
  defaults:
    permissions: ["contents:read"]
`

		gh := &mockGitHubClientForDaemon{
			yaml: validYAML,
		}

		store := NewProfileStore()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go PeriodicRefresh(ctx, store, gh, "acme:silk:profile.yaml")

		// Wait for the goroutine to enter its first sleep
		synctest.Wait()
		assert.Equal(t, 0, gh.calls())

		// Sleep to trigger each refresh (time will advance)
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		assert.Equal(t, 1, gh.calls())

		time.Sleep(5 * time.Minute)
		synctest.Wait()
		assert.Equal(t, 2, gh.calls())

		time.Sleep(5 * time.Minute)
		synctest.Wait()
		assert.Equal(t, 3, gh.calls())
	})
}

func TestPeriodicRefresh_ContextCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		validYAML := `organization:
  profiles:
    - name: "cancel-test"
      repositories: ["silk"]
      permissions: ["contents:read"]

pipeline:
  defaults:
    permissions: ["contents:read"]
`

		gh := &mockGitHubClientForDaemon{
			yaml: validYAML,
		}

		store := NewProfileStore()
		ctx, cancel := context.WithCancel(context.Background())

		go PeriodicRefresh(ctx, store, gh, "acme:silk:profile.yaml")

		// Advance past the first interval so one refresh has run
		synctest.Wait()
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		assert.Equal(t, 1, gh.calls())

		// Cancel context
		cancel()

		// Wait for goroutine to process cancellation
		// The goroutine should exit cleanly
		synctest.Wait()

		// No additional refreshes should have happened
		assert.Equal(t, 1, gh.calls(), "no more refreshes after cancellation")
	})
}

func TestPeriodicRefresh_ContextCancellationDuringSleep(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		validYAML := `organization:
  profiles:
    - name: "cancel-sleep"
      repositories: ["silk"]
      permissions: ["contents:read"]

pipeline:
  defaults:
    permissions: ["contents:read"]
`

		gh := &mockGitHubClientForDaemon{
			yaml: validYAML,
		}

		store := NewProfileStore()
		ctx, cancel := context.WithCancel(context.Background())

		go PeriodicRefresh(ctx, store, gh, "acme:silk:profile.yaml")

		// Wait for the goroutine to enter its interval sleep
		synctest.Wait()
		assert.Equal(t, 0, gh.calls())

		// Cancel while sleeping
		cancel()

		// Goroutine should wake up and exit
		// Wait for the goroutine to process cancellation and exit
		synctest.Wait()

		// Verify no refreshes happened
		assert.Equal(t, 0, gh.calls(), "should exit without a refresh")
	})
}

func TestPeriodicRefresh_PanicRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		validYAML := `organization:
  profiles:
    - name: "panic-recovery"
      repositories: ["silk"]
      permissions: ["contents:read"]

pipeline:
  defaults:
    permissions: ["contents:read"]
`
		gh := &mockGitHubClientForDaemon{
			yaml:    validYAML,
			panicOn: 1, // Panic on first call only
		}

		store := NewProfileStore()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go PeriodicRefresh(ctx, store, gh, "acme:silk:profile.yaml")

		// Advance to the first attempt (which panics)
		synctest.Wait()
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		assert.Equal(t, 1, gh.calls())

		// Advance time to trigger second refresh
		time.Sleep(5 * time.Minute)
		synctest.Wait()

		// Second refresh should succeed (panic was on call 1 only)
		assert.Equal(t, 2, gh.calls(), "loop should continue after panic recovery")

		// Verify profile was loaded on second attempt
		profile, _, err := store.GetOrganizationProfile("panic-recovery")
		require.NoError(t, err)
		assert.Equal(t, NewSpecificScope("silk"), profile.Attrs.Scope)
	})
}

func TestPeriodicRefresh_ContinuesAfterError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		validYAML := `organization:
  profiles:
    - name: "error-recovery"
      repositories: ["silk"]
      permissions: ["contents:read"]

pipeline:
  defaults:
    permissions: ["contents:read"]
`

		gh := &mockGitHubClientForDaemon{
			yaml: validYAML,
			err:  errors.New("temporary error"),
		}

		store := NewProfileStore()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go PeriodicRefresh(ctx, store, gh, "acme:silk:profile.yaml")

		// First refresh (fails with error)
		synctest.Wait()
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		assert.Equal(t, 1, gh.calls())

		// Clear the error for next attempt
		gh.setErr(nil)

		// Sleep to trigger second refresh (time will advance)
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		assert.Equal(t, 2, gh.calls())

		// Verify the profile was eventually loaded
		profile, _, err := store.GetOrganizationProfile("error-recovery")
		require.NoError(t, err)
		assert.Equal(t, NewSpecificScope("silk"), profile.Attrs.Scope)
	})
}
