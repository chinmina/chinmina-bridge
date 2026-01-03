package profile

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGitHubClient implements GitHubClient for testing
type mockGitHubClient struct {
	files map[string]string
	err   error
}

func (m *mockGitHubClient) GetFileContent(ctx context.Context, owner, repo, path string) (string, error) {
	if m.err != nil {
		return "", m.err
	}

	key := owner + ":" + repo + ":" + path
	content, ok := m.files[key]
	if !ok {
		return "", errors.New("file not found")
	}

	return content, nil
}

func TestFetchOrganizationProfile_Success(t *testing.T) {
	validYAML := `organization:
  profiles:
    - name: "test-profile"
      repositories: ["acme/silk"]
      permissions: ["contents:read"]

pipeline:
  defaults:
    permissions: ["contents:read"]
`

	gh := &mockGitHubClient{
		files: map[string]string{
			"acme:silk:docs/profile.yaml": validYAML,
		},
	}

	profiles, err := FetchOrganizationProfile(context.Background(), "acme:silk:docs/profile.yaml", gh)
	require.NoError(t, err)

	assert.NotEmpty(t, profiles.digest)

	// Verify profile can be accessed
	profile, err := profiles.GetOrgProfile("test-profile")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/silk"}, profile.Attrs.Repositories)
}

func TestFetchOrganizationProfile_ReturnsCorrectDigest(t *testing.T) {
	validYAML := `organization:
  profiles:
    - name: "test-profile"
      repositories: ["acme/test"]
      permissions: ["contents:read"]
`

	gh := &mockGitHubClient{
		files: map[string]string{
			"acme:test:profile.yaml": validYAML,
		},
	}

	// Fetch the same profile twice
	profiles1, err := FetchOrganizationProfile(context.Background(), "acme:test:profile.yaml", gh)
	require.NoError(t, err)

	profiles2, err := FetchOrganizationProfile(context.Background(), "acme:test:profile.yaml", gh)
	require.NoError(t, err)

	// Digests should be identical for same content
	assert.Equal(t, profiles1.digest, profiles2.digest)
	assert.NotEmpty(t, profiles1.digest)
}

func TestFetchOrganizationProfile_CanBeCalledMultipleTimes(t *testing.T) {
	validYAML := `organization:
  profiles:
    - name: "test-profile"
      repositories: ["acme/silk"]
      permissions: ["contents:read"]
`

	gh := &mockGitHubClient{
		files: map[string]string{
			"acme:silk:profile.yaml": validYAML,
		},
	}

	// Call multiple times
	for i := 0; i < 3; i++ {
		profiles, err := FetchOrganizationProfile(context.Background(), "acme:silk:profile.yaml", gh)
		require.NoError(t, err)
		assert.NotEmpty(t, profiles.digest)
	}
}

func TestFetchOrganizationProfile_NonExistent(t *testing.T) {
	gh := &mockGitHubClient{
		err: errors.New("404 not found"),
	}

	_, err := FetchOrganizationProfile(context.Background(), "acme:silk:nonexistent.yaml", gh)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "organization profile load failed")
}

func TestProfileStore_GetOrganizationProfile_Success(t *testing.T) {
	validYAML := `organization:
  profiles:
    - name: "test-profile"
      repositories: ["acme/silk"]
      permissions: ["contents:read", "pull_requests:write"]
`

	gh := &mockGitHubClient{
		files: map[string]string{
			"acme:silk:profile.yaml": validYAML,
		},
	}

	// Fetch and load profiles
	profiles, err := FetchOrganizationProfile(context.Background(), "acme:silk:profile.yaml", gh)
	require.NoError(t, err)

	// Create store and update with profiles
	store := NewProfileStore()
	store.Update(profiles)

	// Retrieve profile
	profile, err := store.GetOrganizationProfile("test-profile")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/silk"}, profile.Attrs.Repositories)
	assert.Equal(t, []string{"contents:read", "pull_requests:write"}, profile.Attrs.Permissions)
}

func TestProfileStore_GetOrganizationProfile_NotFound(t *testing.T) {
	validYAML := `organization:
  profiles:
    - name: "test-profile"
      repositories: ["acme/silk"]
      permissions: ["contents:read"]
`

	gh := &mockGitHubClient{
		files: map[string]string{
			"acme:silk:profile.yaml": validYAML,
		},
	}

	profiles, err := FetchOrganizationProfile(context.Background(), "acme:silk:profile.yaml", gh)
	require.NoError(t, err)

	store := NewProfileStore()
	store.Update(profiles)

	_, err = store.GetOrganizationProfile("nonexistent")
	require.Error(t, err)

	var notFoundErr ProfileNotFoundError
	require.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "nonexistent", notFoundErr.Name)
}

func TestProfileStore_GetOrganizationProfile_Unavailable(t *testing.T) {
	// YAML with invalid profile (empty repositories)
	invalidYAML := `organization:
  profiles:
    - name: "invalid-profile"
      repositories: []
      permissions: ["contents:read"]
`

	gh := &mockGitHubClient{
		files: map[string]string{
			"acme:silk:profile.yaml": invalidYAML,
		},
	}

	profiles, err := FetchOrganizationProfile(context.Background(), "acme:silk:profile.yaml", gh)
	require.NoError(t, err)

	store := NewProfileStore()
	store.Update(profiles)

	_, err = store.GetOrganizationProfile("invalid-profile")
	require.Error(t, err)

	var unavailErr ProfileUnavailableError
	require.ErrorAs(t, err, &unavailErr)
	assert.Equal(t, "invalid-profile", unavailErr.Name)
	assert.Contains(t, unavailErr.Cause.Error(), "repositories list must be non-empty")
}

func TestProfileStore_GetPipelineProfile_Success(t *testing.T) {
	validYAML := `organization:
  profiles:
    - name: "test-profile"
      repositories: ["acme/silk"]
      permissions: ["contents:read"]

pipeline:
  defaults:
    permissions: ["contents:read"]
  profiles:
    - name: "high-access"
      permissions: ["contents:write", "pull_requests:write"]
`

	gh := &mockGitHubClient{
		files: map[string]string{
			"acme:silk:profile.yaml": validYAML,
		},
	}

	// Fetch and load profiles
	profiles, err := FetchOrganizationProfile(context.Background(), "acme:silk:profile.yaml", gh)
	require.NoError(t, err)

	// Create store and update with profiles
	store := NewProfileStore()
	store.Update(profiles)

	// Retrieve pipeline profile
	profile, err := store.GetPipelineProfile("high-access")
	require.NoError(t, err)
	assert.Equal(t, []string{"contents:write", "pull_requests:write"}, profile.Attrs.Permissions)

	// Also verify "default" profile exists (created from defaults)
	defaultProfile, err := store.GetPipelineProfile("default")
	require.NoError(t, err)
	assert.Equal(t, []string{"contents:read"}, defaultProfile.Attrs.Permissions)
}

func TestProfileStore_GetPipelineProfile_NotFound(t *testing.T) {
	validYAML := `organization:
  profiles:
    - name: "test-profile"
      repositories: ["acme/silk"]
      permissions: ["contents:read"]

pipeline:
  defaults:
    permissions: ["contents:read"]
`

	gh := &mockGitHubClient{
		files: map[string]string{
			"acme:silk:profile.yaml": validYAML,
		},
	}

	profiles, err := FetchOrganizationProfile(context.Background(), "acme:silk:profile.yaml", gh)
	require.NoError(t, err)

	store := NewProfileStore()
	store.Update(profiles)

	_, err = store.GetPipelineProfile("nonexistent")
	require.Error(t, err)

	var notFoundErr ProfileNotFoundError
	require.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "nonexistent", notFoundErr.Name)
}

func TestProfileStore_Concurrency(t *testing.T) {
	// Simple smoke test that multiple goroutines can access the store concurrently
	// without panics. Actual race conditions are caught by `go test -race`.
	validYAML := `organization:
  profiles:
    - name: "test-profile"
      repositories: ["acme/silk"]
      permissions: ["contents:read"]
`

	gh := &mockGitHubClient{
		files: map[string]string{
			"acme:silk:profile.yaml": validYAML,
		},
	}

	profiles, err := FetchOrganizationProfile(context.Background(), "acme:silk:profile.yaml", gh)
	require.NoError(t, err)

	store := NewProfileStore()
	store.Update(profiles)

	// Launch multiple goroutines accessing the store concurrently
	var wg sync.WaitGroup
	numGoroutines := 100
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			profile, err := store.GetOrganizationProfile("test-profile")
			if err != nil {
				return
			}

			// Basic sanity check
			if len(profile.Attrs.Repositories) != 1 {
				return
			}

			// Also exercise GetPipelineProfile
			_, _ = store.GetPipelineProfile("default")
		}()
	}

	wg.Wait()
	// Test passes if no panics occurred
}

func TestProfileStore_Update_MultipleTimes(t *testing.T) {
	yaml1 := `organization:
  profiles:
    - name: "profile-v1"
      repositories: ["acme/v1"]
      permissions: ["contents:read"]
`

	yaml2 := `organization:
  profiles:
    - name: "profile-v2"
      repositories: ["acme/v2"]
      permissions: ["contents:write"]
`

	gh := &mockGitHubClient{
		files: map[string]string{
			"acme:test:v1.yaml": yaml1,
			"acme:test:v2.yaml": yaml2,
		},
	}

	store := NewProfileStore()

	// Load first version
	profiles1, err := FetchOrganizationProfile(context.Background(), "acme:test:v1.yaml", gh)
	require.NoError(t, err)
	store.Update(profiles1)

	profile1, err := store.GetOrganizationProfile("profile-v1")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/v1"}, profile1.Attrs.Repositories)

	// Update with second version
	profiles2, err := FetchOrganizationProfile(context.Background(), "acme:test:v2.yaml", gh)
	require.NoError(t, err)
	store.Update(profiles2)

	// Old profile should no longer be accessible
	_, err = store.GetOrganizationProfile("profile-v1")
	require.Error(t, err)

	// New profile should be accessible
	profile2, err := store.GetOrganizationProfile("profile-v2")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/v2"}, profile2.Attrs.Repositories)
}

func TestProfileStore_Update_NoChange(t *testing.T) {
	yaml1 := `organization:
  profiles:
    - name: "profile-v1"
      repositories: ["acme/v1"]
      permissions: ["contents:read"]
`

	gh := &mockGitHubClient{
		files: map[string]string{
			"acme:test:v1.yaml": yaml1,
		},
	}

	store := NewProfileStore()

	profiles, err := FetchOrganizationProfile(context.Background(), "acme:test:v1.yaml", gh)
	require.NoError(t, err)

	// First update
	store.Update(profiles)

	// Second update with same profiles - should log "no changes detected"
	store.Update(profiles)

	// Verify profile is still accessible
	profile, err := store.GetOrganizationProfile("profile-v1")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/v1"}, profile.Attrs.Repositories)
}

func TestFetchOrganizationProfile_InvalidYAML(t *testing.T) {
	gh := &mockGitHubClient{
		files: map[string]string{
			"acme:test:invalid.yaml": "invalid: yaml: [broken",
		},
	}

	_, err := FetchOrganizationProfile(context.Background(), "acme:test:invalid.yaml", gh)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "profile file parsing failed")
}

func TestLoad_EndToEnd(t *testing.T) {
	validYAML := `organization:
  profiles:
    - name: "prod-profile"
      match:
        - claim: pipeline_slug
          value: "silk-prod"
      repositories: ["acme/silk"]
      permissions: ["contents:write"]

    - name: "staging-profile"
      match:
        - claim: pipeline_slug
          valuePattern: ".*-staging"
      repositories: ["acme/silk", "acme/cotton"]
      permissions: ["contents:read"]

pipeline:
  defaults:
    permissions: ["contents:read"]
`

	gh := &mockGitHubClient{
		files: map[string]string{
			"acme:config:profile.yaml": validYAML,
		},
	}

	// Test the load function directly (via FetchOrganizationProfile)
	profiles, err := FetchOrganizationProfile(context.Background(), "acme:config:profile.yaml", gh)
	require.NoError(t, err)

	// Verify profiles are loaded correctly
	assert.NotEmpty(t, profiles.digest)

	// Verify prod profile
	prodProfile, err := profiles.GetOrgProfile("prod-profile")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/silk"}, prodProfile.Attrs.Repositories)
	assert.Equal(t, []string{"contents:write"}, prodProfile.Attrs.Permissions)

	// Test prod profile matching
	claims := mapClaimLookup{"pipeline_slug": "silk-prod"}
	result := prodProfile.Match(claims)
	assert.True(t, result.Matched)

	// Verify staging profile
	stagingProfile, err := profiles.GetOrgProfile("staging-profile")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/silk", "acme/cotton"}, stagingProfile.Attrs.Repositories)

	// Test staging profile matching with regex
	claims = mapClaimLookup{"pipeline_slug": "silk-staging"}
	result = stagingProfile.Match(claims)
	assert.True(t, result.Matched)

	// Verify pipeline defaults via default profile
	defaultProfile, err := profiles.GetPipelineProfile("default")
	require.NoError(t, err)
	assert.Equal(t, []string{"contents:read"}, defaultProfile.Attrs.Permissions)
}

func TestNewDefaultProfiles(t *testing.T) {
	profiles := NewDefaultProfiles()

	// Verify default pipeline profile exists
	defaultProfile, err := profiles.GetPipelineProfile("default")
	require.NoError(t, err)
	assert.Equal(t, []string{"contents:read"}, defaultProfile.Attrs.Permissions)

	// Verify default profile matches any claims (universal matcher)
	claims := mapClaimLookup{"pipeline_slug": "any-pipeline"}
	result := defaultProfile.Match(claims)
	assert.True(t, result.Matched)
	assert.NoError(t, result.Err)

	// Verify stats show correct counts and digest
	expectedStats := ProfilesStats{
		OrganizationProfileCount:        0,
		OrganizationInvalidProfileCount: 0,
		PipelineProfileCount:            1,
		PipelineInvalidProfileCount:     0,
		Digest:                          "default-profile:v1",
		Location:                        "",
	}
	assert.Equal(t, expectedStats, profiles.Stats())

	// Verify organization profiles are empty
	_, err = profiles.GetOrgProfile("any-profile")
	require.Error(t, err)
	var notFoundErr ProfileNotFoundError
	assert.ErrorAs(t, err, &notFoundErr)
}
