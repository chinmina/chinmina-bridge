package vendor

import (
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/stretchr/testify/require"
)

// repoRef is a profile reference for the cache key tests, where only whether
// two references differ matters.
func repoRef(name string) profile.ProfileRef {
	return profile.ProfileRef{
		Organization: "test-org",
		Type:         profile.ProfileTypeRepo,
		Name:         name,
		PipelineID:   "pipeline-id",
		PipelineSlug: "pipeline-slug",
	}
}

// TestCacheKeyIsUnambiguous pins the property the key format depends on: two
// requests that differ in any keyed component get different keys. The digest
// may contain the separator, so the cases include digests shaped to look like
// they could shift where the application and installation IDs are read — a
// token minted through one app must never be served for another.
func TestCacheKeyIsUnambiguous(t *testing.T) {
	tests := []struct {
		name     string
		resolved Resolved[profile.PipelineProfileAttr]
	}{
		{
			name: "digest free of the separator",
			resolved: Resolved[profile.PipelineProfileAttr]{
				Ref:    repoRef("default"),
				Digest: "abc123",
				App:    github.AppIdentity{Name: "default", ApplicationID: 1, InstallationID: 2},
			},
		},
		{
			name: "synthetic digest containing the separator",
			resolved: Resolved[profile.PipelineProfileAttr]{
				Ref:    repoRef("default"),
				Digest: "default-profile:v1",
				App:    github.AppIdentity{Name: "default", ApplicationID: 1, InstallationID: 2},
			},
		},
		{
			name: "digest ending in a field that reads as an ID",
			resolved: Resolved[profile.PipelineProfileAttr]{
				Ref:    repoRef("default"),
				Digest: "7:8",
				App:    github.AppIdentity{Name: "default", ApplicationID: 1, InstallationID: 2},
			},
		},
		{
			name: "same text split differently between digest and IDs",
			resolved: Resolved[profile.PipelineProfileAttr]{
				Ref:    repoRef("default"),
				Digest: "7",
				App:    github.AppIdentity{Name: "default", ApplicationID: 8, InstallationID: 1},
			},
		},
		{
			name: "IDs that concatenate to the same digits",
			resolved: Resolved[profile.PipelineProfileAttr]{
				Ref:    repoRef("default"),
				Digest: "abc123",
				App:    github.AppIdentity{Name: "other", ApplicationID: 1, InstallationID: 23},
			},
		},
		{
			name: "IDs concatenating the same digits, split differently",
			resolved: Resolved[profile.PipelineProfileAttr]{
				Ref:    repoRef("default"),
				Digest: "abc123",
				App:    github.AppIdentity{Name: "other", ApplicationID: 12, InstallationID: 3},
			},
		},
		{
			name: "different application ID",
			resolved: Resolved[profile.PipelineProfileAttr]{
				Ref:    repoRef("default"),
				Digest: "abc123",
				App:    github.AppIdentity{Name: "other", ApplicationID: 9, InstallationID: 2},
			},
		},
		{
			name: "different installation ID",
			resolved: Resolved[profile.PipelineProfileAttr]{
				Ref:    repoRef("default"),
				Digest: "abc123",
				App:    github.AppIdentity{Name: "other", ApplicationID: 1, InstallationID: 9},
			},
		},
		{
			name: "different profile",
			resolved: Resolved[profile.PipelineProfileAttr]{
				Ref:    repoRef("write-packages"),
				Digest: "abc123",
				App:    github.AppIdentity{Name: "default", ApplicationID: 1, InstallationID: 2},
			},
		},
	}

	seen := make(map[string]string, len(tests))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := cacheKey(tt.resolved)

			clash, found := seen[key]
			require.False(t, found, "key %q collides with case %q", key, clash)

			seen[key] = tt.name
		})
	}
}

// TestCacheKeyIgnoresAppName documents the deliberate consequence of keying on
// the app identity: two registry names for one application and installation
// are the same credential, so they share cache entries.
func TestCacheKeyIgnoresAppName(t *testing.T) {
	base := Resolved[profile.PipelineProfileAttr]{
		Ref:    repoRef("default"),
		Digest: "abc123",
		App:    github.AppIdentity{Name: "packages", ApplicationID: 333, InstallationID: 444},
	}

	renamed := base
	renamed.App.Name = "publishing"

	require.Equal(t, cacheKey(base), cacheKey(renamed))
}

// Direct unit tests for checkTokenRepository (internal function)

func TestCheckTokenRepository_EmptyRequestedRepo(t *testing.T) {
	cachedToken := ProfileToken{
		Token:               "test-token",
		VendedRepositoryURL: "https://github.com/test-org/some-repo.git",
		Repositories:        profile.NewSpecificScope("some-repo"),
	}

	// Empty requested repository (non-git credentials request) should return cached token
	token, ok := checkTokenRepository(cachedToken, "")
	require.True(t, ok)
	require.Equal(t, cachedToken, token)
}

func TestCheckTokenRepository_MatchingRepository(t *testing.T) {
	cachedToken := ProfileToken{
		Token:               "test-token",
		VendedRepositoryURL: "https://github.com/test-org/old-repo.git",
		Repositories:        profile.NewSpecificScope("repo-a", "repo-b", "repo-c"),
		Profile:             "org:shared",
	}

	// Requested repository matches one in the list
	token, ok := checkTokenRepository(cachedToken, "https://github.com/test-org/repo-b.git")
	require.True(t, ok)
	require.Equal(t, "test-token", token.Token)
	require.Equal(t, "https://github.com/test-org/repo-b.git", token.VendedRepositoryURL)
	require.Equal(t, profile.NewSpecificScope("repo-a", "repo-b", "repo-c"), token.Repositories)
}

func TestCheckTokenRepository_NonMatchingRepository(t *testing.T) {
	cachedToken := ProfileToken{
		Token:        "test-token",
		Repositories: profile.NewSpecificScope("repo-a", "repo-b"),
	}

	// Requested repository not in the list
	token, ok := checkTokenRepository(cachedToken, "https://github.com/test-org/repo-c.git")
	require.False(t, ok)
	require.Equal(t, ProfileToken{}, token)
}

func TestCheckTokenRepository_InvalidURL(t *testing.T) {
	cachedToken := ProfileToken{
		Token:        "test-token",
		Repositories: profile.NewSpecificScope("repo-a"),
	}

	// Invalid URL that can't be parsed
	token, ok := checkTokenRepository(cachedToken, "not a valid url")
	require.False(t, ok)
	require.Equal(t, ProfileToken{}, token)
}

func TestCheckTokenRepository_EmptyRepositoriesList(t *testing.T) {
	cachedToken := ProfileToken{
		Token:        "test-token",
		Repositories: profile.NewSpecificScope(),
	}

	// Token has empty repositories list
	token, ok := checkTokenRepository(cachedToken, "https://github.com/test-org/any-repo.git")
	require.False(t, ok)
	require.Equal(t, ProfileToken{}, token)
}

func TestCheckTokenRepository_WildcardScope(t *testing.T) {
	cachedToken := ProfileToken{
		Token:        "test-token",
		Repositories: profile.NewWildcardScope(),
		Profile:      "org:wildcard",
	}

	// Wildcard scope should match any requested repository
	token, ok := checkTokenRepository(cachedToken, "https://github.com/test-org/any-repo.git")
	require.True(t, ok)
	require.Equal(t, "https://github.com/test-org/any-repo.git", token.VendedRepositoryURL)
	require.Equal(t, "test-token", token.Token)
	require.Equal(t, "org:wildcard", token.Profile)
}
