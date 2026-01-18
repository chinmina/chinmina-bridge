package profiletest

import (
	"context"
	_ "embed"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/profiles.yaml
var testProfileYAML string

// mockGitHubClient is a GitHub client mock that returns the provided YAML.
type mockGitHubClient struct {
	yaml string
}

func (m mockGitHubClient) GetFileContent(ctx context.Context, owner, repo, path string) (string, error) {
	return m.yaml, nil
}

// CompileFromYAML parses and compiles profile YAML for tests outside the profile package.
// Uses the existing external API via a mock GitHub client.
func CompileFromYAML(yamlContent string) (profile.Profiles, error) {
	mock := mockGitHubClient{yaml: yamlContent}
	return profile.FetchOrganizationProfile(context.Background(), "test:test:test.yaml", mock)
}

// CreateTestProfileStore creates a ProfileStore from the provided YAML.
// Fails the test if YAML parsing/compilation fails.
func CreateTestProfileStore(t *testing.T, yamlContent string) *profile.ProfileStore {
	t.Helper()

	profiles, err := CompileFromYAML(yamlContent)
	require.NoError(t, err, "failed to compile test profiles")

	store := profile.NewProfileStore()
	store.Update(t.Context(), profiles)

	return store
}

// DefaultTestProfileStore returns a pre-populated ProfileStore with default test profiles.
// Uses embedded YAML testdata with sample profiles.
func DefaultTestProfileStore(t *testing.T) *profile.ProfileStore {
	t.Helper()
	return CreateTestProfileStore(t, testProfileYAML)
}
