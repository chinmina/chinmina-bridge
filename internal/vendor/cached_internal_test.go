package vendor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Direct unit tests for checkTokenRepository (internal function)

func TestCheckTokenRepository_EmptyRequestedRepo(t *testing.T) {
	cachedToken := ProfileToken{
		Token:               "test-token",
		VendedRepositoryURL: "https://github.com/test-org/some-repo.git",
		Repositories:        []string{"some-repo"},
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
		Repositories:        []string{"repo-a", "repo-b", "repo-c"},
		Profile:             "org:shared",
	}

	// Requested repository matches one in the list
	token, ok := checkTokenRepository(cachedToken, "https://github.com/test-org/repo-b.git")
	require.True(t, ok)
	require.Equal(t, "test-token", token.Token)
	require.Equal(t, "https://github.com/test-org/repo-b.git", token.VendedRepositoryURL)
	require.Equal(t, []string{"repo-a", "repo-b", "repo-c"}, token.Repositories)
}

func TestCheckTokenRepository_NonMatchingRepository(t *testing.T) {
	cachedToken := ProfileToken{
		Token:        "test-token",
		Repositories: []string{"repo-a", "repo-b"},
	}

	// Requested repository not in the list
	token, ok := checkTokenRepository(cachedToken, "https://github.com/test-org/repo-c.git")
	require.False(t, ok)
	require.Equal(t, ProfileToken{}, token)
}

func TestCheckTokenRepository_InvalidURL(t *testing.T) {
	cachedToken := ProfileToken{
		Token:        "test-token",
		Repositories: []string{"repo-a"},
	}

	// Invalid URL that can't be parsed
	token, ok := checkTokenRepository(cachedToken, "not a valid url")
	require.False(t, ok)
	require.Equal(t, ProfileToken{}, token)
}

func TestCheckTokenRepository_EmptyRepositoriesList(t *testing.T) {
	cachedToken := ProfileToken{
		Token:        "test-token",
		Repositories: []string{},
	}

	// Token has empty repositories list
	token, ok := checkTokenRepository(cachedToken, "https://github.com/test-org/any-repo.git")
	require.False(t, ok)
	require.Equal(t, ProfileToken{}, token)
}
