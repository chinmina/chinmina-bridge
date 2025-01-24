package github_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/github"
	api "github.com/google/go-github/v61/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test that the profile URL is valid
func TestValidProfileURL(t *testing.T) {
	// Example of a valid profile URL
	configURL := "github.com/chinmina/chinmina-bridge/docs/profile.yaml"

	// Test that the profile URL is valid
	owner, repo, path := github.DecomposePath(configURL)
	assert.Equal(t, "chinmina", owner)
	assert.Equal(t, "chinmina-bridge", repo)
	assert.Equal(t, "docs/profile.yaml", path)

}

// Test case where the profile URL is invalid, or does not exist
func TestInvalidProfileURL(t *testing.T) {
	// Example of a valid profile URL
	configURL := "github.com/chinmina/non-existent-profile.yaml"
	// Test that the profile URL is valid
	owner, repo, path := github.DecomposePath(configURL)
	assert.Equal(t, "", owner)
	assert.Equal(t, "", repo)
	assert.Equal(t, "", path)
}

// Test that repository contents are handled correctly
func TestRepositoryContents(t *testing.T) {
	//valid profile content
	profile := `
organization:
  profiles:
    # allow read access to a set of buildkite-plugins
    - name: "buildkite-plugin"
      # array of repos accessible to the profile
      repositories: 
        - deploy-templates-buildkite-plugin
        - very-private-buildkite-plugin
      permissions: ["contents:read"]
      
    # allow package access to any repository
    - name: "package-registry"
    # '*' indicates all, when specified must be only value. No other wildcards supported.
      repositories: ["*"]
      permissions: ["packages:read"]
	  `

	router := http.NewServeMux()

	router.HandleFunc("/repos/chinmina/chinmina-bridge/contents/docs/profile.yaml", func(w http.ResponseWriter, r *http.Request) {

		JSON(w, &api.RepositoryContent{
			Content: &profile,
		})
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	// generate valid key for testing
	key := generateKey(t)

	// Example of a valid profile URL
	configURL := "github.com/chinmina/chinmina-bridge/docs/profile.yaml"
	gh, err := github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     key,
			ApplicationID:  10,
			InstallationID: 20,
		},
	)
	require.NoError(t, err)

	// Load the profile
	profile, err = github.GetProfile(context.Background(), gh, configURL)
	require.NoError(t, err)
}

func TestInvalidRepositoryContents(t *testing.T) {
	//valid profile content

	router := http.NewServeMux()

	router.HandleFunc("/repos/chinmina/chinmina-bridge/contents/docs/profile.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	// generate valid key for testing
	key := generateKey(t)

	// Example of an invalid profile URL
	configURL := "github.com/chinmina/chinmina-bridge/docs/profile.yaml"
	gh, err := github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     key,
			ApplicationID:  10,
			InstallationID: 20,
		},
	)
	require.NoError(t, err)

	// Load the profile
	_, err = github.GetProfile(context.Background(), gh, configURL)
	require.Error(t, err)
	assert.ErrorContains(t, err, ": 418")
}

// Test that the profile that is loaded is valid
func TestValidProfile(t *testing.T) {
	// Example of valid profile content
	profile := `
organization:
  profiles:
    # allow read access to a set of buildkite-plugins
    - name: "buildkite-plugin"
      # array of repos accessible to the profile
      repositories: 
        - deploy-templates-buildkite-plugin
        - very-private-buildkite-plugin
      permissions: ["contents:read"]
      
    # allow package access to any repository
    - name: "package-registry"
    # '*' indicates all, when specified must be only value. No other wildcards supported.
      repositories: ["*"]
      permissions: ["packages:read"]
`

	_, err := github.ValidateProfile(context.Background(), profile)

	require.NoError(t, err)
}

// Test case where the profile that is loaded is invalid
func TestInvalidProfile(t *testing.T) {
	// Example of invalid profile content
	profile := `
organisation:
  profilez:
    # allow read access to a set of buildkite-plugins
    - name: "buildkite-plugin"
      # array of repos accessible to the profile
      repositories: 
        - deploy-templates-buildkite-plugin
        - very-private-buildkite-plugin
      permissions: ["contents:read"]
      
    # allow package access to any repository
    - name: "package-registry"
      # '*' indicates all, when specified must be only value. No other wildcards supported.
      repositories: ["*"]
      permissions: ["packages:read"]
`

	_, err := github.ValidateProfile(context.Background(), profile)

	require.Error(t, err)

}

func TestLoadProfile(t *testing.T) {
	profile := `
organization:
  profiles:
    # allow read access to a set of buildkite-plugins
    - name: "buildkite-plugin"
      # array of repos accessible to the profile
      repositories: 
        - deploy-templates-buildkite-plugin
        - very-private-buildkite-plugin
      permissions: ["contents:read"]
      
    # allow package access to any repository
    - name: "package-registry"
    # '*' indicates all, when specified must be only value. No other wildcards supported.
      repositories: ["*"]
      permissions: ["packages:read"]
`

	router := http.NewServeMux()

	router.HandleFunc("/repos/chinmina/chinmina-bridge/contents/docs/profile.yaml", func(w http.ResponseWriter, r *http.Request) {

		JSON(w, &api.RepositoryContent{
			Content: &profile,
		})
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	// generate valid key for testing
	key := generateKey(t)

	// Example of a valid profile URL
	configURL := "github.com/chinmina/chinmina-bridge/docs/profile.yaml"
	gh, err := github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     key,
			ApplicationID:  10,
			InstallationID: 20,
		},
	)
	require.NoError(t, err)

	err = github.LoadProfile(context.Background(), gh, configURL)
	require.NoError(t, err)
}

// Test the case where the profile is inconsistent with the request made to Chinmina
// In this case, the target repository is not included in the targeted profile
func TestInconsistentProfile(t *testing.T) {
	profile := `
organization:
  profiles:
    # allow read access to a set of buildkite-plugins
    - name: "buildkite-plugin"
      # array of repos accessible to the profile
      repositories: 
        - deploy-templates-buildkite-plugin
        - very-private-buildkite-plugin
      permissions: ["contents:read"]
      
    # allow package access to any repository
    - name: "package-registry"
      # '*' indicates all, when specified must be only value. No other wildcards supported.
      repositories: ["*"]
      permissions: ["packages:read"]
`
	profileName := "buildkite-plugin"
	repositoryName := "fake-repo"
	profileConfig, err := github.ValidateProfile(context.Background(), profile)
	require.NoError(t, err)
	_, ok := profileConfig.HasProfile(profileName)
	assert.Equal(t, ok, true)
	assert.Equal(t, profileConfig.HasRepository(profileName, repositoryName), false)
}

// Test the case where the profile does not exist
func TestNonExistentProfile(t *testing.T) {
	profile := `
organization:
  profiles:
    # allow read access to a set of buildkite-plugins
    - name: "buildkite-plugin"
      # array of repos accessible to the profile
      repositories: 
        - deploy-templates-buildkite-plugin
        - very-private-buildkite-plugin
      permissions: ["contents:read"]
      
    # allow package access to any repository
    - name: "package-registry"
      # '*' indicates all, when specified must be only value. No other wildcards supported.
      repositories: ["*"]
      permissions: ["packages:read"]
`
	profileName := "fake-profile"
	repositoryName := "fake-repo"
	profileConfig, err := github.ValidateProfile(context.Background(), profile)
	require.NoError(t, err)
	_, ok := profileConfig.HasProfile(profileName)
	assert.Equal(t, ok, false)
	assert.Equal(t, profileConfig.HasRepository(profileName, repositoryName), false)
}

// Test the case where the profile is OK
func TestConsistentProfile(t *testing.T) {
	profile := `
organization:
  profiles:
    # allow read access to a set of buildkite-plugins
    - name: "buildkite-plugin"
      # array of repos accessible to the profile
      repositories: 
        - deploy-templates-buildkite-plugin
        - very-private-buildkite-plugin
      permissions: ["contents:read"]
      
    # allow package access to any repository
    - name: "package-registry"
      # '*' indicates all, when specified must be only value. No other wildcards supported.
      repositories: ["*"]
      permissions: ["packages:read"]
`
	profileName := "buildkite-plugin"
	repositoryName := "deploy-templates-buildkite-plugin"
	profileConfig, err := github.ValidateProfile(context.Background(), profile)
	require.NoError(t, err)
	_, ok := profileConfig.HasProfile(profileName)
	assert.Equal(t, ok, true)
	assert.Equal(t, profileConfig.HasRepository(profileName, repositoryName), true)
}
