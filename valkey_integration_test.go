//go:build integration

package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valkey-io/valkey-go"
)

// setupValkeyContainer starts a Valkey container and returns the address and cleanup function
func setupValkeyContainer(t *testing.T) (string, func()) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "valkey/valkey:8-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	endpoint, err := container.Endpoint(ctx, "")
	require.NoError(t, err)

	cleanup := func() {
		_ = container.Terminate(ctx)
	}

	return endpoint, cleanup
}

// newValkeyHarness creates a test harness configured with Valkey cache
func newValkeyHarness(t *testing.T, valkeyAddress string) *APITestHarness {
	t.Helper()

	harness := &APITestHarness{
		t:            t,
		ProfileStore: profile.NewProfileStore(),
	}

	// Generate JWK for JWT signing
	harness.jwk = testhelpers.GenerateJWK(t)
	harness.privateKeyPEM = rsaPrivateKeyToPEM(t, harness.jwk.Key.(*rsa.PrivateKey))

	// Setup mock servers
	harness.JWKSServer = testhelpers.SetupJWKSServer(t, harness.jwk)
	harness.GitHubMock = testhelpers.SetupMockGitHubServer(t)
	harness.BuildkiteMock = testhelpers.SetupMockBuildkiteServer(t)

	// Initialize with default profiles
	harness.ProfileStore.Update(profile.NewDefaultProfiles())

	// Configure API server with Valkey cache
	cfg := config.Config{
		Authorization: config.AuthorizationConfig{
			Audience:                  "test-audience",
			BuildkiteOrganizationSlug: "test-org",
			IssuerURL:                 harness.JWKSServer.URL,
		},
		Buildkite: config.BuildkiteConfig{
			APIURL: harness.BuildkiteMock.Server.URL,
			Token:  "test-buildkite-token",
		},
		Cache: config.CacheConfig{
			Type: "valkey",
		},
		Github: config.GithubConfig{
			APIURL:         harness.GitHubMock.Server.URL,
			PrivateKey:     harness.privateKeyPEM,
			ApplicationID:  12345,
			InstallationID: 67890,
		},
		Observe: config.ObserveConfig{
			Enabled: false,
		},
		Server: config.ServerConfig{
			Port: 0,
		},
		Valkey: config.ValkeyConfig{
			Address: valkeyAddress,
			TLS:     false, // No TLS for test container
		},
	}

	handler, cleanup, err := configureServerRoutes(context.Background(), cfg, harness.ProfileStore)
	require.NoError(t, err)

	harness.cacheCleanup = cleanup
	harness.Server = httptest.NewServer(handler)

	return harness
}

// TestIntegrationValkey_CacheHit verifies that the cache correctly serves cached tokens
func TestIntegrationValkey_CacheHit(t *testing.T) {
	valkeyAddress, cleanup := setupValkeyContainer(t)
	defer cleanup()

	harness := newValkeyHarness(t, valkeyAddress)
	defer harness.Close()

	// Setup: Configure mocks
	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
	harness.GitHubMock.Token = "ghs_firsttoken"

	// Create valid JWT
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:test-pipeline:ref:refs/heads/main:commit:abc123:step:build",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "test-pipeline",
		"pipeline_id":       "pipeline-123",
		"build_number":      42,
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

	// First request - should miss cache and call GitHub
	req1, err := http.NewRequest("POST", harness.Server.URL+"/token", nil)
	require.NoError(t, err)
	req1.Header.Set("Authorization", "Bearer "+token)

	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	defer resp1.Body.Close()

	require.Equal(t, http.StatusOK, resp1.StatusCode)

	var tokenResponse1 map[string]interface{}
	err = json.NewDecoder(resp1.Body).Decode(&tokenResponse1)
	require.NoError(t, err)
	assert.Equal(t, "ghs_firsttoken", tokenResponse1["token"])

	// Reset GitHub mock to return a different token
	// If cache is working, we should still get the first token
	harness.GitHubMock.Token = "ghs_differenttoken"

	// Second request - should hit cache and not call GitHub again
	req2, err := http.NewRequest("POST", harness.Server.URL+"/token", nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+token)

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	require.Equal(t, http.StatusOK, resp2.StatusCode)

	var tokenResponse2 map[string]interface{}
	err = json.NewDecoder(resp2.Body).Decode(&tokenResponse2)
	require.NoError(t, err)

	// Should still be the original token from cache
	assert.Equal(t, "ghs_firsttoken", tokenResponse2["token"], "expected cached token, not new token from GitHub")
}

// TestIntegrationValkey_CacheInvalidationOnDigestChange verifies that cache keys change when config digest changes
func TestIntegrationValkey_CacheInvalidationOnDigestChange(t *testing.T) {
	valkeyAddress, cleanup := setupValkeyContainer(t)
	defer cleanup()

	harness := newValkeyHarness(t, valkeyAddress)
	defer harness.Close()

	// Setup
	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
	harness.GitHubMock.Token = "ghs_token1"

	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:test-pipeline:ref:refs/heads/main:commit:abc123:step:build",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "test-pipeline",
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

	// First request - cache the token
	req1, err := http.NewRequest("POST", harness.Server.URL+"/token", nil)
	require.NoError(t, err)
	req1.Header.Set("Authorization", "Bearer "+token)

	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	defer resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode)

	// Update profile store - this changes the digest
	// Create a new profile with different permissions
	newMatcher := profile.CompositeMatcher()
	newPipelineProfiles := map[string]profile.AuthorizedProfile[profile.PipelineProfileAttr]{
		"default": profile.NewAuthorizedProfile(newMatcher, profile.PipelineProfileAttr{
			Permissions: []string{"contents:read", "metadata:read", "pull_requests:write"},
		}),
	}
	newOrgProfiles := profile.NewProfileStoreOf(
		map[string]profile.AuthorizedProfile[profile.OrganizationProfileAttr]{},
		map[string]error{},
	)
	newProfiles := profile.NewProfiles(newPipelineProfiles, newOrgProfiles, "")
	harness.ProfileStore.Update(newProfiles)

	// Change GitHub mock response
	harness.GitHubMock.Token = "ghs_token2"

	// Second request - should miss cache due to digest change
	req2, err := http.NewRequest("POST", harness.Server.URL+"/token", nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+token)

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)

	var tokenResponse2 map[string]interface{}
	err = json.NewDecoder(resp2.Body).Decode(&tokenResponse2)
	require.NoError(t, err)

	// Should get the new token because digest changed
	assert.Equal(t, "ghs_token2", tokenResponse2["token"], "expected new token after digest change")
}

// TestIntegrationValkey_SharedCacheAcrossRequests verifies that the same cache key yields the same cached token
func TestIntegrationValkey_SharedCacheAcrossRequests(t *testing.T) {
	valkeyAddress, cleanup := setupValkeyContainer(t)
	defer cleanup()

	harness := newValkeyHarness(t, valkeyAddress)
	defer harness.Close()

	// Setup
	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
	harness.GitHubMock.Token = "ghs_sharedtoken"

	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:test-pipeline:ref:refs/heads/main:commit:abc123:step:build",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "test-pipeline",
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

	// First request
	req1, err := http.NewRequest("POST", harness.Server.URL+"/token", nil)
	require.NoError(t, err)
	req1.Header.Set("Authorization", "Bearer "+token)

	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	defer resp1.Body.Close()

	var tokenResponse1 map[string]interface{}
	err = json.NewDecoder(resp1.Body).Decode(&tokenResponse1)
	require.NoError(t, err)

	// Second request (simulating different instance/request)
	req2, err := http.NewRequest("POST", harness.Server.URL+"/token", nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+token)

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	var tokenResponse2 map[string]interface{}
	err = json.NewDecoder(resp2.Body).Decode(&tokenResponse2)
	require.NoError(t, err)

	// Both responses should have the same token and expiry
	assert.Equal(t, tokenResponse1["token"], tokenResponse2["token"])
	assert.Equal(t, tokenResponse1["expiry"], tokenResponse2["expiry"])
}

// TestIntegrationValkey_ConnectionToServer verifies basic connectivity to Valkey
func TestIntegrationValkey_ConnectionToServer(t *testing.T) {
	valkeyAddress, cleanup := setupValkeyContainer(t)
	defer cleanup()

	// Create a simple Valkey client
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{valkeyAddress},
	})
	require.NoError(t, err)
	defer client.Close()

	// Test basic operations
	ctx := context.Background()

	// Set a value
	setCmd := client.B().Set().Key("test-key").Value("test-value").Build()
	err = client.Do(ctx, setCmd).Error()
	require.NoError(t, err)

	// Get the value
	getCmd := client.B().Get().Key("test-key").Build()
	result, err := client.Do(ctx, getCmd).ToString()
	require.NoError(t, err)
	assert.Equal(t, "test-value", result)
}
