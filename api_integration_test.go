//go:build integration

package main

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/jwt/jwxtest"
	"github.com/chinmina/chinmina-bridge/internal/profile/profiletest"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJWTHelpers verifies JWT generation helpers work correctly
func TestIntegrationJWTHelpers(t *testing.T) {
	// Generate key pair
	j := jwxtest.NewJWK(t)
	require.NotNil(t, j.Key(), "expected JWK to be generated")

	// Setup JWKS server
	jwksServer := jwxtest.SetupJWKSServer(t, j)
	defer jwksServer.Close()

	// Create token with claims
	token := jwt.New()
	_ = token.Set(jwt.AudienceKey, []string{"test-audience"})
	_ = token.Set(jwt.SubjectKey, "test-subject")
	token = jwxtest.AddTimingClaims(token)

	// Generate JWT
	tokenStr := jwxtest.SignToken(t, j, jwksServer.URL, token)
	require.NotEmpty(t, tokenStr, "expected token to be generated")
}

// TestMockServers verifies GitHub and Buildkite mock servers work correctly
func TestIntegrationMockServers(t *testing.T) {
	t.Run("GitHub mock server", func(t *testing.T) {
		mock := testhelpers.SetupMockGitHubServer(t)
		defer mock.Close()

		// Verify server is running
		require.NotEmpty(t, mock.Server.URL, "expected server URL to be set")

		// Verify default response values
		assert.Equal(t, "test-github-token", mock.Token)
	})

	t.Run("Buildkite mock server", func(t *testing.T) {
		mock := testhelpers.SetupMockBuildkiteServer(t)
		defer mock.Close()

		// Verify server is running
		require.NotEmpty(t, mock.Server.URL, "expected server URL to be set")

		// Verify default response values
		assert.Equal(t, "https://github.com/test-org/test-repo", mock.RepositoryURL)
	})
}

// TestAPIHarness verifies the API test harness sets up correctly
func TestIntegrationAPIHarness(t *testing.T) {
	harness := NewAPITestHarness(t)

	// Verify all components are initialized
	require.NotNil(t, harness.Server, "expected API server to be initialized")
	require.NotNil(t, harness.JWKSServer, "expected JWKS server to be initialized")
	require.NotNil(t, harness.GitHubMock, "expected GitHub mock to be initialized")
	require.NotNil(t, harness.BuildkiteMock, "expected Buildkite mock to be initialized")
}

// TestHealthCheck verifies the healthcheck endpoint works without authentication
func TestIntegrationHealthCheck(t *testing.T) {
	harness := NewAPITestHarness(t)

	// Make request to healthcheck endpoint (no auth required)
	resp, err := http.Get(harness.Server.URL + "/healthcheck")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestPipelineToken_Success tests successful token vending via /token endpoint
func TestIntegrationPipelineToken_Success(t *testing.T) {
	harness := NewAPITestHarness(t)

	// Setup: Configure mock to return specific repository
	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
	harness.GitHubMock.Token = "ghs_testtoken123"

	// Create valid JWT with Buildkite claims
	token := harness.PipelineToken()

	// Make request
	result, err := harness.Client().Token(token, "")
	require.NoError(t, err)

	// Verify token response
	assert.Equal(t, "ghs_testtoken123", result.Token)
	assert.Equal(t, "test-org", result.OrganizationSlug)
	assert.Equal(t, "repo:default", result.Profile)
}

// TestPipelineToken_DefaultProfile tests successful token vending with the default profile
func TestIntegrationPipelineToken_DefaultProfile(t *testing.T) {
	harness := NewAPITestHarness(t)

	// The harness already has default profiles configured
	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
	harness.GitHubMock.Token = "ghs_defaulttoken"

	// Create JWT
	token := harness.PipelineToken()

	// Make request with explicit default profile parameter
	result, err := harness.Client().Token(token, "default")
	require.NoError(t, err)

	assert.Equal(t, "repo:default", result.Profile)
	assert.Equal(t, "ghs_defaulttoken", result.Token)
}

// TestPipelineToken_TokenFields verifies all fields in the token response
func TestIntegrationPipelineToken_TokenFields(t *testing.T) {
	harness := NewAPITestHarness(t)

	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/api-service"
	harness.GitHubMock.Token = "ghs_verifyfields123"

	// Create JWT
	token := harness.PipelineToken()

	// Make request
	result, err := harness.Client().Token(token, "")
	require.NoError(t, err)

	// Verify all expected fields are present
	assert.NotEmpty(t, result.Token, "expected token field to be present")
	assert.False(t, result.Expiry.IsZero(), "expected expiry field to be present")
	assert.Equal(t, "test-org", result.OrganizationSlug)
	assert.NotEmpty(t, result.Profile, "expected profile field to be present")
}

// TestPipelineToken_AuthErrors tests auth error responses
func TestIntegrationPipelineToken_AuthErrors(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		expectedStatus int
	}{
		{
			name:           "missing auth header",
			token:          "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid JWT",
			token:          "invalid.jwt.token",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness := NewAPITestHarness(t)

			_, err := harness.Client().Token(tt.token, "")
			require.Error(t, err)

			var apiErr *APIError
			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, tt.expectedStatus, apiErr.StatusCode)
		})
	}
}

// TestPipelineToken_ProfileNotFound tests 404 response when profile doesn't exist
func TestIntegrationPipelineToken_ProfileNotFound(t *testing.T) {
	harness := NewAPITestHarness(t)

	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"

	// Create valid JWT
	token := harness.PipelineToken()

	// Request non-existent profile
	_, err := harness.Client().Token(token, "nonexistent")
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
	assert.Equal(t, "profile not found", apiErr.Message)
}

// Note: 403 Forbidden testing requires custom profiles with match conditions.
// The default profile has no conditions, so claim validation isn't triggered.
// This scenario is adequately covered by unit tests in handlers_test.go

// TestOrganizationToken_Success tests successful organization token vending
func TestIntegrationOrganizationToken_Success(t *testing.T) {
	harness := NewAPITestHarness(t)

	// Load organization profiles from YAML (tests full parse/compile pipeline)
	yamlContent, err := os.ReadFile("testdata/org-profiles-basic.yaml")
	require.NoError(t, err)

	profiles, err := profiletest.CompileFromYAML(string(yamlContent))
	require.NoError(t, err)
	harness.ProfileStore.Update(t.Context(), profiles)

	harness.GitHubMock.Token = "ghs_orgtoken123"

	// Create valid JWT
	token := harness.PipelineToken()

	// Request organization token
	result, err := harness.Client().OrganizationToken(token, "test-org-profile")
	require.NoError(t, err)

	// Verify token response
	assert.Equal(t, "ghs_orgtoken123", result.Token)
	assert.Equal(t, "test-org", result.OrganizationSlug)
	assert.Equal(t, "org:test-org-profile", result.Profile)
	assert.Len(t, result.Repositories, 2, "expected 2 repositories")
}

// TestOrganizationToken_ProfileNotFound tests 404 when org profile doesn't exist
func TestIntegrationOrganizationToken_ProfileNotFound(t *testing.T) {
	harness := NewAPITestHarness(t)

	// Create valid JWT
	token := harness.PipelineToken()

	// Request non-existent organization profile
	_, err := harness.Client().OrganizationToken(token, "nonexistent")
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
	assert.Equal(t, "profile not found", apiErr.Message)
}

// TestOrganizationToken_Unauthorized tests 401 when JWT is invalid
func TestIntegrationOrganizationToken_Unauthorized(t *testing.T) {
	harness := NewAPITestHarness(t)

	// Load organization profiles from YAML
	yamlContent, err := os.ReadFile("testdata/org-profiles-basic.yaml")
	require.NoError(t, err)

	profiles, err := profiletest.CompileFromYAML(string(yamlContent))
	require.NoError(t, err)
	harness.ProfileStore.Update(t.Context(), profiles)

	// Make request with invalid JWT
	_, err = harness.Client().OrganizationToken("invalid.jwt.token", "test-org-profile")
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
}

// ============================================================================
// Git Credentials Endpoint Tests
// ============================================================================

func TestIntegrationPipelineGitCredentials_Success(t *testing.T) {
	harness := NewAPITestHarness(t)

	// Setup: Configure mock to return specific repository
	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
	harness.GitHubMock.Token = "ghs_testtoken123"

	// Create valid JWT with Buildkite claims
	token := harness.PipelineToken()

	// Make request
	props, err := harness.Client().GitCredentials(token, "", GitCredentialRequest{
		Protocol: "https",
		Host:     "github.com",
		Path:     "test-org/test-repo",
	})
	require.NoError(t, err)

	// Verify credential properties
	assert.Equal(t, "https", props.Get("protocol"))
	assert.Equal(t, "github.com", props.Get("host"))
	assert.Equal(t, "test-org/test-repo", props.Get("path"))
	assert.Equal(t, "x-access-token", props.Get("username"))
	assert.Equal(t, "ghs_testtoken123", props.Get("password"))
	assert.NotEmpty(t, props.Get("password_expiry_utc"), "expected password_expiry_utc to be set")
}

func TestIntegrationPipelineGitCredentials_ExplicitProfile(t *testing.T) {
	harness := NewAPITestHarness(t)

	// Setup: Configure mock to return specific repository
	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
	harness.GitHubMock.Token = "ghs_testtoken456"

	// Create valid JWT with Buildkite claims
	token := harness.PipelineToken()

	// Make request with explicit default profile
	props, err := harness.Client().GitCredentials(token, "default", GitCredentialRequest{
		Protocol: "https",
		Host:     "github.com",
		Path:     "test-org/test-repo",
	})
	require.NoError(t, err)

	// Verify token is correct
	assert.Equal(t, "ghs_testtoken456", props.Get("password"))
}

func TestIntegrationOrganizationGitCredentials_Success(t *testing.T) {
	harness := NewAPITestHarness(t)

	// Load organization profiles from YAML
	yamlContent, err := os.ReadFile("testdata/org-profiles-basic.yaml")
	require.NoError(t, err)

	profiles, err := profiletest.CompileFromYAML(string(yamlContent))
	require.NoError(t, err)
	harness.ProfileStore.Update(t.Context(), profiles)

	// Setup: Configure mock to return token
	harness.GitHubMock.Token = "ghs_orgtoken789"

	// Create valid JWT with Buildkite claims
	token := harness.PipelineToken()

	// Make request for organization profile git credentials
	props, err := harness.Client().OrganizationGitCredentials(token, "test-org-profile", GitCredentialRequest{
		Protocol: "https",
		Host:     "github.com",
		Path:     "test-org/repo1",
	})
	require.NoError(t, err)

	// Verify token and path
	assert.Equal(t, "ghs_orgtoken789", props.Get("password"))
	assert.Equal(t, "test-org/repo1", props.Get("path"))
}

func TestIntegrationPipelineGitCredentials_MissingAuth(t *testing.T) {
	harness := NewAPITestHarness(t)

	// Make request without Authorization header
	_, err := harness.Client().GitCredentials("", "", GitCredentialRequest{
		Protocol: "https",
		Host:     "github.com",
		Path:     "test-org/test-repo",
	})
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
}

func TestIntegrationPipelineGitCredentials_InvalidJWT(t *testing.T) {
	harness := NewAPITestHarness(t)

	// Make request with invalid JWT
	_, err := harness.Client().GitCredentials("invalid.jwt.token", "", GitCredentialRequest{
		Protocol: "https",
		Host:     "github.com",
		Path:     "test-org/test-repo",
	})
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
}

func TestIntegrationPipelineGitCredentials_ProfileNotFound(t *testing.T) {
	harness := NewAPITestHarness(t)

	// Create valid JWT with Buildkite claims
	token := harness.PipelineToken()

	// Make request with non-existent profile
	_, err := harness.Client().GitCredentials(token, "nonexistent", GitCredentialRequest{
		Protocol: "https",
		Host:     "github.com",
		Path:     "test-org/test-repo",
	})
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
}

// ============================================================================
// Request Size Limit Tests
// ============================================================================

func TestIntegrationRequestSizeLimit_GitCredentials(t *testing.T) {
	harness := NewAPITestHarness(t)

	// Create valid JWT with Buildkite claims
	token := harness.PipelineToken()

	// Create oversized request body (larger than 20KB)
	largeBody := strings.Repeat("x", 21*1024)
	reqBody := strings.NewReader(largeBody)
	req, err := http.NewRequest("POST", harness.Server.URL+"/git-credentials", reqBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// entity too large is triggered by the request size middleware
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
}

// ============================================================================
// Cache Tests
// ============================================================================

// cacheVariant describes a cache configuration for data-driven tests
type cacheVariant struct {
	name    string
	options []APITestHarnessOption
}

// cacheVariants defines the cache configurations to test
var cacheVariants = []cacheVariant{
	{name: "memory", options: nil},
	{name: "valkey/encrypted", options: []APITestHarnessOption{WithValkeyCache()}},
}

// TestIntegrationCache_CacheHit verifies that both cache implementations correctly serve cached tokens
func TestIntegrationCache_CacheHit(t *testing.T) {
	for _, variant := range cacheVariants {
		t.Run(variant.name, func(t *testing.T) {
			harness := NewAPITestHarness(t, variant.options...)

			// Setup: Configure mocks
			harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
			harness.GitHubMock.Token = "ghs_firsttoken"

			token := harness.PipelineToken()

			// First request - should miss cache and call GitHub
			result1, err := harness.Client().Token(token, "")
			require.NoError(t, err)
			assert.Equal(t, "ghs_firsttoken", result1.Token)
			assert.Equal(t, 1, harness.GitHubMock.RequestCount, "expected GitHub to be called once for cache miss")

			// Reset GitHub mock to return a different token
			// If cache is working, we should still get the first token
			harness.GitHubMock.Token = "ghs_differenttoken"

			// Second request - should hit cache and not call GitHub again
			result2, err := harness.Client().Token(token, "")
			require.NoError(t, err)

			// Should still be the original token from cache
			assert.Equal(t, "ghs_firsttoken", result2.Token, "expected cached token, not new token from GitHub")
			assert.Equal(t, 1, harness.GitHubMock.RequestCount, "expected GitHub to still be called only once (cache hit)")
		})
	}
}

// TestIntegrationCache_CacheInvalidationOnProfileChange verifies that cache keys are invalidated
// when the profile configuration changes (i.e. the digest changes).
func TestIntegrationCache_CacheInvalidationOnProfileChange(t *testing.T) {
	for _, variant := range cacheVariants {
		t.Run(variant.name, func(t *testing.T) {
			harness := NewAPITestHarness(t, variant.options...)

			// Load initial profile configuration from YAML
			yamlContent, err := os.ReadFile("testdata/pipeline-profiles-basic.yaml")
			require.NoError(t, err)

			profiles, err := profiletest.CompileFromYAML(string(yamlContent))
			require.NoError(t, err)
			harness.ProfileStore.Update(t.Context(), profiles)

			digestBefore := harness.ProfileStore.Digest()

			// Setup
			harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
			harness.GitHubMock.Token = "ghs_token1"

			token := harness.PipelineToken()

			// First request - cache the token
			_, err = harness.Client().Token(token, "")
			require.NoError(t, err)
			assert.Equal(t, 1, harness.GitHubMock.RequestCount, "expected GitHub to be called once for initial cache miss")

			// Load modified profile configuration - this changes the digest
			yamlContent, err = os.ReadFile("testdata/pipeline-profiles-extended.yaml")
			require.NoError(t, err)

			profiles, err = profiletest.CompileFromYAML(string(yamlContent))
			require.NoError(t, err)
			harness.ProfileStore.Update(t.Context(), profiles)

			digestAfter := harness.ProfileStore.Digest()
			require.NotEqual(t, digestBefore, digestAfter, "profile digest must change between the two configurations")

			// Change GitHub mock response
			harness.GitHubMock.Token = "ghs_token2"

			// Second request - should miss cache due to digest change
			result2, err := harness.Client().Token(token, "")
			require.NoError(t, err)

			// Should get the new token because digest changed, requiring a second GitHub call
			assert.Equal(t, "ghs_token2", result2.Token, "expected new token after profile change")
			assert.Equal(t, 2, harness.GitHubMock.RequestCount, "expected GitHub to be called again after cache invalidation")
		})
	}
}

// TestIntegrationCache_SharedCacheAcrossRequests verifies that the same cache key yields the same cached token
func TestIntegrationCache_SharedCacheAcrossRequests(t *testing.T) {
	for _, variant := range cacheVariants {
		t.Run(variant.name, func(t *testing.T) {
			harness := NewAPITestHarness(t, variant.options...)

			// Setup
			harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
			harness.GitHubMock.Token = "ghs_sharedtoken"

			token := harness.PipelineToken()

			// First request
			result1, err := harness.Client().Token(token, "")
			require.NoError(t, err)

			// Second request (simulating different instance/request)
			result2, err := harness.Client().Token(token, "")
			require.NoError(t, err)

			// Both responses should have the same token and expiry
			assert.Equal(t, result1.Token, result2.Token)
			assert.Equal(t, result1.Expiry, result2.Expiry)
		})
	}
}

// TestIntegrationValkey_DecryptionFailureAsCacheMiss verifies that when encrypted cache values
// fail to decrypt, the cache treats it as a miss rather than an error.
func TestIntegrationValkey_DecryptionFailureAsCacheMiss(t *testing.T) {
	harness := NewAPITestHarness(t, WithValkeyCache())

	// Setup: Configure mocks
	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
	harness.GitHubMock.Token = "ghs_firsttoken"

	token := harness.PipelineToken()

	// First request - should cache the token
	result1, err := harness.Client().Token(token, "")
	require.NoError(t, err)
	assert.Equal(t, "ghs_firsttoken", result1.Token)
	assert.Equal(t, 1, harness.GitHubMock.RequestCount, "expected GitHub to be called once")

	// Get direct Valkey access to corrupt the cached value
	valkeyClient := harness.newTestValkeyClient(t)

	// Find the encrypted cache key (prefix: enc:)
	scanCmd := valkeyClient.B().Scan().Cursor(0).Match("enc:*").Build()
	scanResult := valkeyClient.Do(t.Context(), scanCmd)
	require.NoError(t, scanResult.Error())

	keys, err := scanResult.AsScanEntry()
	require.NoError(t, err)
	require.NotEmpty(t, keys.Elements, "expected to find at least one encrypted cache key")

	cacheKey := keys.Elements[0]

	// Corrupt the cached value with invalid ciphertext
	// Use cb-enc: prefix (valid) but invalid base64 ciphertext
	corruptedValue := "cb-enc:aW52YWxpZA==" // base64("invalid")
	setCmd := valkeyClient.B().Set().Key(cacheKey).Value(corruptedValue).Build()
	setResult := valkeyClient.Do(t.Context(), setCmd)
	require.NoError(t, setResult.Error())

	// Change the GitHub mock to return a different token
	harness.GitHubMock.Token = "ghs_secondtoken"

	// Second request - should fail to decrypt, treat as cache miss, and call GitHub again
	result2, err := harness.Client().Token(token, "")
	require.NoError(t, err)
	assert.Equal(t, "ghs_secondtoken", result2.Token, "expected new token after decryption failure")
	assert.Equal(t, 2, harness.GitHubMock.RequestCount, "expected GitHub to be called twice (decryption failure = cache miss)")
}
