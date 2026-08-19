package profile

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const daemonTestYAML = `organization:
  profiles:
    - name: "test-profile"
      repositories: ["silk"]
      permissions: ["contents:read"]

pipeline:
  defaults:
    permissions: ["contents:read"]
`

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

func (m *mockGitHubClientForDaemon) calls() int {
	return int(m.callCount.Load())
}

func TestRefresh_Success(t *testing.T) {
	gh := &mockGitHubClientForDaemon{
		yaml: daemonTestYAML,
	}

	store := NewProfileStore()
	ctx := context.Background()

	err := refresh(ctx, store, gh, "acme:silk:profile.yaml", DefaultAppOnly)
	require.NoError(t, err)

	// Verify the profile was fetched and store was updated
	assert.Equal(t, 1, gh.calls())

	// Verify store has the profile
	profile, _, err := store.GetOrganizationProfile("test-profile")
	require.NoError(t, err, "profile should be in store")
	assert.Equal(t, NewSpecificScope("silk"), profile.Attrs.Scope)
}

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

			err := refresh(context.Background(), store, tt.gh, "acme:silk:profile.yaml", DefaultAppOnly)

			require.Error(t, err)
			assert.Equal(t, 1, tt.gh.calls(), "fetch should have been attempted")
			assert.Equal(t, initialDigest, store.Digest(), "store should not be updated")
		})
	}
}

// Scheduling belongs to the repeat package; only the action belongs here.
func TestRefreshTask_ActionLoadsAGeneration(t *testing.T) {
	gh := &mockGitHubClientForDaemon{
		yaml: daemonTestYAML,
	}

	store := NewProfileStore()

	err := RefreshTask(store, gh, "acme:silk:profile.yaml", DefaultAppOnly).Action(context.Background())
	require.NoError(t, err)

	profile, _, err := store.GetOrganizationProfile("test-profile")
	require.NoError(t, err, "the action should have loaded the generation")
	assert.Equal(t, NewSpecificScope("silk"), profile.Attrs.Scope)
}

// Profile validity depends on both the YAML and the app registry, but only the
// YAML feeds the digest. A refresh that compiled without the registry would
// silently invalidate app-naming profiles under an unchanged digest, so the
// generation swap would look like a no-op.
func TestRefresh_ProfileNamingAnEnabledAppStaysValidAcrossRefreshes(t *testing.T) {
	gh := &mockGitHubClientForDaemon{
		yaml: `organization:
  profiles:
    - name: "publish-packages"
      app: packages
      repositories: ["silk"]
      permissions: ["contents:read"]
`,
	}

	store := NewProfileStore()
	usableApp := usableApps("packages")

	// The second refresh is the one that would regress.
	require.NoError(t, RefreshTask(store, gh, "acme:silk:profile.yaml", usableApp).Action(t.Context()))
	firstDigest := store.Digest()

	require.NoError(t, RefreshTask(store, gh, "acme:silk:profile.yaml", usableApp).Action(t.Context()))

	assert.Equal(t, firstDigest, store.Digest(), "the YAML is unchanged, so the digest must be too")

	published, _, err := store.GetOrganizationProfile("publish-packages")
	require.NoError(t, err, "a profile naming an enabled app must survive a refresh")
	assert.Equal(t, "packages", published.Attrs.App)
	assert.Equal(t, 2, gh.calls())
}

// Unusable is terminal until the process restarts: no refresh recovers the
// profile.
func TestRefresh_ProfileNamingAnUnusableAppStaysInvalidAcrossRefreshes(t *testing.T) {
	gh := &mockGitHubClientForDaemon{
		yaml: `organization:
  profiles:
    - name: "publish-packages"
      app: packages
      repositories: ["silk"]
      permissions: ["contents:read"]
`,
	}

	store := NewProfileStore()

	require.NoError(t, RefreshTask(store, gh, "acme:silk:profile.yaml", DefaultAppOnly).Action(t.Context()))
	require.NoError(t, RefreshTask(store, gh, "acme:silk:profile.yaml", DefaultAppOnly).Action(t.Context()))

	_, _, err := store.GetOrganizationProfile("publish-packages")

	var unavailable ProfileUnavailableError
	require.ErrorAs(t, err, &unavailable)
}
