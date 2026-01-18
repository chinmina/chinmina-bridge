package profile

import (
	"context"
	"errors"
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
	err       error
	callCount atomic.Int32
	panicOn   int // panic on this call number (0 = never)
}

func (m *mockGitHubClientForDaemon) GetFileContent(ctx context.Context, owner, repo, path string) (string, error) {
	callNum := int(m.callCount.Add(1))

	if m.panicOn > 0 && callNum == m.panicOn {
		panic("mock panic for testing")
	}

	if m.err != nil {
		return "", m.err
	}

	return m.yaml, nil
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

	refresh(ctx, store, gh, "acme:silk:profile.yaml")

	// Verify the profile was fetched and store was updated
	assert.Equal(t, 1, gh.calls())

	// Verify store has the profile
	profile, err := store.GetOrganizationProfile("test-profile")
	require.NoError(t, err, "profile should be in store")
	assert.Equal(t, []string{"silk"}, profile.Attrs.Repositories)
}

func TestRefresh_Error(t *testing.T) {
	expectedErr := errors.New("github error")
	gh := &mockGitHubClientForDaemon{
		err: expectedErr,
	}

	store := NewProfileStore()
	initialDigest := store.Digest()
	ctx := context.Background()

	// Should not panic despite error
	refresh(ctx, store, gh, "acme:silk:profile.yaml")

	// Verify fetch was attempted
	assert.Equal(t, 1, gh.calls())

	// Verify store was not updated (digest unchanged)
	assert.Equal(t, initialDigest, store.Digest())
}

func TestRefresh_InvalidYAML(t *testing.T) {
	gh := &mockGitHubClientForDaemon{
		yaml: "invalid: yaml: content: [",
	}

	store := NewProfileStore()
	initialDigest := store.Digest()
	ctx := context.Background()

	// Should not panic despite invalid YAML
	refresh(ctx, store, gh, "acme:silk:profile.yaml")

	// Verify fetch was attempted
	assert.Equal(t, 1, gh.calls())

	// Verify store was not updated (digest unchanged)
	assert.Equal(t, initialDigest, store.Digest())
}

func TestPeriodicRefresh_ImmediateFirstRefresh(t *testing.T) {
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

		// First refresh should have happened
		assert.Equal(t, 1, gh.calls(), "first refresh should happen immediately")

		profile, err := store.GetOrganizationProfile("immediate")
		require.NoError(t, err)
		assert.Equal(t, []string{"silk"}, profile.Attrs.Repositories)
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

		// Wait for first refresh to complete and goroutine to enter sleep
		synctest.Wait()
		assert.Equal(t, 1, gh.calls())

		// Sleep to trigger second refresh (time will advance)
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		assert.Equal(t, 2, gh.calls())

		// Sleep to trigger third refresh
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

		// Wait for first refresh
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

		// Wait for first refresh and goroutine to enter sleep
		synctest.Wait()
		assert.Equal(t, 1, gh.calls())

		// Cancel while sleeping
		cancel()

		// Goroutine should wake up and exit
		// Wait for the goroutine to process cancellation and exit
		synctest.Wait()

		// Verify no more refreshes happened
		assert.Equal(t, 1, gh.calls(), "should exit without additional refresh")
	})
}

func TestPeriodicRefresh_PanicRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gh := &mockGitHubClientForDaemon{
			yaml:    "valid: yaml",
			panicOn: 1, // Panic on first call
		}

		store := NewProfileStore()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Should not crash despite panic
		go PeriodicRefresh(ctx, store, gh, "acme:silk:profile.yaml")

		// Wait for first attempt (which panics)
		synctest.Wait()
		assert.Equal(t, 1, gh.calls())

		// The goroutine should have recovered and be waiting for next cycle
		// Cancel to clean up
		cancel()
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
		assert.Equal(t, 1, gh.calls())

		// Clear the error for next attempt
		gh.err = nil

		// Sleep to trigger second refresh (time will advance)
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		assert.Equal(t, 2, gh.calls())

		// Verify the profile was eventually loaded
		profile, err := store.GetOrganizationProfile("error-recovery")
		require.NoError(t, err)
		assert.Equal(t, []string{"silk"}, profile.Attrs.Repositories)
	})
}
