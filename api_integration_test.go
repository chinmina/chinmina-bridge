//go:build integration

package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/profile/profiletest"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegrationSetup verifies the integration test framework is configured correctly
func TestIntegrationSetup(t *testing.T) {
}

// TestJWTHelpers verifies JWT generation helpers work correctly
func TestIntegrationJWTHelpers(t *testing.T) {
	// Generate key pair
	jwk := testhelpers.GenerateJWK(t)
	require.NotNil(t, jwk, "expected JWK to be generated")

	// Setup JWKS server
	jwksServer := testhelpers.SetupJWKSServer(t, jwk)
	defer jwksServer.Close()

	// Create valid claims
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "test-subject",
	})

	// Generate JWT
	token := testhelpers.CreateJWT(t, jwk, jwksServer.URL, claims)
	require.NotEmpty(t, token, "expected token to be generated")
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

// APITestHarness manages the complete test environment for API integration tests.
// It sets up mock servers, generates JWTs, and provides the API server for testing.
type APITestHarness struct {
	t             *testing.T
	Server        *httptest.Server
	JWKSServer    *httptest.Server
	GitHubMock    *testhelpers.MockGitHubServer
	BuildkiteMock *testhelpers.MockBuildkiteServer
	ProfileStore  *profile.ProfileStore
	jwk           *jose.JSONWebKey
	privateKeyPEM string
}

// NewAPITestHarness creates a complete test harness with all mock servers and the API server.
func NewAPITestHarness(t *testing.T) *APITestHarness {
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

	// Configure and start the API server
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
		Github: config.GithubConfig{
			APIURL:         harness.GitHubMock.Server.URL,
			PrivateKey:     harness.privateKeyPEM,
			ApplicationID:  12345,
			InstallationID: 67890,
		},
		Observe: config.ObserveConfig{
			Enabled: false, // Disable observability for tests
		},
		Server: config.ServerConfig{
			Port: 0, // Not used for httptest.Server
		},
	}

	handler, err := configureServerRoutes(context.Background(), cfg, harness.ProfileStore)
	require.NoError(t, err)

	harness.Server = httptest.NewServer(handler)

	return harness
}

// Close shuts down all mock servers and the API server.
func (h *APITestHarness) Close() {
	h.Server.Close()
	h.JWKSServer.Close()
	h.GitHubMock.Close()
	h.BuildkiteMock.Close()
}

// GenerateToken creates a valid JWT signed with the test JWK.
// Claims are passed as variadic parameters and will be included in the token.
func (h *APITestHarness) GenerateToken(claims ...any) string {
	return testhelpers.CreateJWT(h.t, h.jwk, h.JWKSServer.URL, claims...)
}

// rsaPrivateKeyToPEM converts an RSA private key to PEM format.
func rsaPrivateKeyToPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()

	privBytes := x509.MarshalPKCS1PrivateKey(key)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	return string(privPEM)
}

// TestAPIHarness verifies the API test harness sets up correctly
func TestIntegrationAPIHarness(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Verify all components are initialized
	require.NotNil(t, harness.Server, "expected API server to be initialized")
	require.NotNil(t, harness.JWKSServer, "expected JWKS server to be initialized")
	require.NotNil(t, harness.GitHubMock, "expected GitHub mock to be initialized")
	require.NotNil(t, harness.BuildkiteMock, "expected Buildkite mock to be initialized")
}

// TestHealthCheck verifies the healthcheck endpoint works without authentication
func TestIntegrationHealthCheck(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

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
	defer harness.Close()

	// Setup: Configure mock to return specific repository
	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
	harness.GitHubMock.Token = "ghs_testtoken123"

	// Create valid JWT with Buildkite claims
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:test-pipeline:ref:refs/heads/main:commit:abc123:step:build",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "test-pipeline",
		"pipeline_id":       "pipeline-123",
		"build_number":      42,
		"build_branch":      "main",
		"build_commit":      "abc123",
		"step_key":          "build",
		"job_id":            "job-456",
		"agent_id":          "agent-789",
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

	// Make request
	req, err := http.NewRequest("POST", harness.Server.URL+"/token", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Parse response body (do this first to see error messages)
	var tokenResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil && resp.StatusCode == http.StatusOK {
		require.NoError(t, err)
	}

	// Verify response
	require.Equal(t, http.StatusOK, resp.StatusCode, "Response: %v", tokenResponse)

	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Verify token response structure
	assert.Equal(t, "ghs_testtoken123", tokenResponse["token"])
	assert.Equal(t, "test-org", tokenResponse["organizationSlug"])
	assert.Equal(t, "repo:default", tokenResponse["profile"])
}

// TestPipelineToken_DefaultProfile tests successful token vending with the default profile
func TestIntegrationPipelineToken_DefaultProfile(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// The harness already has default profiles configured
	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
	harness.GitHubMock.Token = "ghs_defaulttoken"

	// Create JWT
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:test-pipeline:ref:refs/heads/main:commit:def456:step:build",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "test-pipeline",
		"pipeline_id":       "pipeline-123",
		"build_number":      43,
		"build_branch":      "main",
		"build_commit":      "def456",
		"job_id":            "job-999",
		"agent_id":          "agent-888",
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

	// Make request with explicit default profile parameter
	req, err := http.NewRequest("POST", harness.Server.URL+"/token/default", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	require.NoError(t, err)

	assert.Equal(t, "repo:default", tokenResponse["profile"])
	assert.Equal(t, "ghs_defaulttoken", tokenResponse["token"])
}

// TestPipelineToken_TokenFields verifies all fields in the token response
func TestIntegrationPipelineToken_TokenFields(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/api-service"
	harness.GitHubMock.Token = "ghs_verifyfields123"

	// Create JWT
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:api-deploy:ref:refs/heads/production:commit:abc789:step:deploy",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "api-deploy",
		"pipeline_id":       "pipeline-456",
		"build_number":      100,
		"build_branch":      "production",
		"build_commit":      "abc789",
		"job_id":            "job-111",
		"agent_id":          "agent-222",
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

	// Make request
	req, err := http.NewRequest("POST", harness.Server.URL+"/token", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	require.NoError(t, err)

	// Verify all expected fields are present
	assert.NotNil(t, tokenResponse["token"], "expected token field to be present")
	assert.NotNil(t, tokenResponse["expiry"], "expected expiry field to be present")
	assert.Equal(t, "test-org", tokenResponse["organizationSlug"])
	assert.NotNil(t, tokenResponse["profile"], "expected profile field to be present")
}

// TestPipelineToken_AuthErrors tests auth error responses
func TestIntegrationPipelineToken_AuthErrors(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "missing auth header",
			authHeader:     "",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid JWT",
			authHeader:     "Bearer invalid.jwt.token",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness := NewAPITestHarness(t)
			defer harness.Close()

			req, err := http.NewRequest("POST", harness.Server.URL+"/token", nil)
			require.NoError(t, err)

			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
		})
	}
}

// TestPipelineToken_ProfileNotFound tests 404 response when profile doesn't exist
func TestIntegrationPipelineToken_ProfileNotFound(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"

	// Create valid JWT
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:test-pipeline:ref:refs/heads/main:commit:abc123:step:build",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "test-pipeline",
		"pipeline_id":       "pipeline-123",
		"build_number":      1,
		"build_branch":      "main",
		"build_commit":      "abc123",
		"job_id":            "job-111",
		"agent_id":          "agent-222",
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

	// Request non-existent profile
	req, err := http.NewRequest("POST", harness.Server.URL+"/token/nonexistent", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify 404 Not Found
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Verify JSON error response
	var errorResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&errorResponse)
	require.NoError(t, err)

	assert.Equal(t, "profile not found", errorResponse["error"])
}

// Note: 403 Forbidden testing requires custom profiles with match conditions.
// The default profile has no conditions, so claim validation isn't triggered.
// This scenario is adequately covered by unit tests in handlers_test.go

// TestOrganizationToken_Success tests successful organization token vending
func TestIntegrationOrganizationToken_Success(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Load organization profiles from YAML (tests full parse/compile pipeline)
	yamlContent, err := os.ReadFile("testdata/org-profiles-basic.yaml")
	require.NoError(t, err)

	profiles, err := profiletest.CompileFromYAML(string(yamlContent))
	require.NoError(t, err)
	harness.ProfileStore.Update(profiles)

	harness.GitHubMock.Token = "ghs_orgtoken123"

	// Create valid JWT
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:test-pipeline:ref:refs/heads/main:commit:abc123:step:build",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "test-pipeline",
		"pipeline_id":       "pipeline-123",
		"build_number":      1,
		"build_branch":      "main",
		"build_commit":      "abc123",
		"job_id":            "job-111",
		"agent_id":          "agent-222",
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

	// Request organization token
	req, err := http.NewRequest("POST", harness.Server.URL+"/organization/token/test-org-profile", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	require.NoError(t, err)

	// Verify token response
	assert.Equal(t, "ghs_orgtoken123", tokenResponse["token"])
	assert.Equal(t, "test-org", tokenResponse["organizationSlug"])
	assert.Equal(t, "org:test-org-profile", tokenResponse["profile"])

	// Verify repositories list
	repos, ok := tokenResponse["repositories"].([]interface{})
	assert.True(t, ok && len(repos) == 2, "expected 2 repositories, got %v", tokenResponse["repositories"])
}

// TestOrganizationToken_ProfileNotFound tests 404 when org profile doesn't exist
func TestIntegrationOrganizationToken_ProfileNotFound(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Create valid JWT
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:test-pipeline:ref:refs/heads/main:commit:abc123:step:build",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "test-pipeline",
		"pipeline_id":       "pipeline-123",
		"build_number":      1,
		"build_branch":      "main",
		"build_commit":      "abc123",
		"job_id":            "job-111",
		"agent_id":          "agent-222",
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

	// Request non-existent organization profile
	req, err := http.NewRequest("POST", harness.Server.URL+"/organization/token/nonexistent", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify 404 Not Found
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	var errorResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&errorResponse)
	require.NoError(t, err)

	assert.Equal(t, "profile not found", errorResponse["error"])
}

// TestOrganizationToken_Unauthorized tests 401 when JWT is invalid
func TestIntegrationOrganizationToken_Unauthorized(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Load organization profiles from YAML
	yamlContent, err := os.ReadFile("testdata/org-profiles-basic.yaml")
	require.NoError(t, err)

	profiles, err := profiletest.CompileFromYAML(string(yamlContent))
	require.NoError(t, err)
	harness.ProfileStore.Update(profiles)

	// Make request with invalid JWT
	req, err := http.NewRequest("POST", harness.Server.URL+"/organization/token/test-org-profile", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify 401 Unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ============================================================================
// Git Credentials Endpoint Tests
// ============================================================================

func TestIntegrationPipelineGitCredentials_Success(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Setup: Configure mock to return specific repository
	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
	harness.GitHubMock.Token = "ghs_testtoken123"

	// Create valid JWT with Buildkite claims
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:test-pipeline:ref:refs/heads/main:commit:abc123:step:build",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "test-pipeline",
		"pipeline_id":       "pipeline-123",
		"build_number":      42,
		"build_branch":      "main",
		"build_commit":      "abc123",
		"step_key":          "build",
		"job_id":            "job-456",
		"agent_id":          "agent-789",
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

	// Make request with git credential format body
	reqBody := strings.NewReader("protocol=https\nhost=github.com\npath=test-org/test-repo\n\n")
	req, err := http.NewRequest("POST", harness.Server.URL+"/git-credentials", reqBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))

	// Parse git credentials response
	props, err := credentialhandler.ReadProperties(resp.Body)
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
	defer harness.Close()

	// Setup: Configure mock to return specific repository
	harness.BuildkiteMock.RepositoryURL = "https://github.com/test-org/test-repo"
	harness.GitHubMock.Token = "ghs_testtoken456"

	// Create valid JWT with Buildkite claims
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:test-pipeline:ref:refs/heads/main:commit:abc123:step:build",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "test-pipeline",
		"pipeline_id":       "pipeline-123",
		"build_number":      42,
		"build_branch":      "main",
		"build_commit":      "abc123",
		"step_key":          "build",
		"job_id":            "job-456",
		"agent_id":          "agent-789",
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

	// Make request with explicit default profile
	reqBody := strings.NewReader("protocol=https\nhost=github.com\npath=test-org/test-repo\n\n")
	req, err := http.NewRequest("POST", harness.Server.URL+"/git-credentials/default", reqBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse git credentials response
	props, err := credentialhandler.ReadProperties(resp.Body)
	require.NoError(t, err)

	// Verify token is correct
	assert.Equal(t, "ghs_testtoken456", props.Get("password"))
}

func TestIntegrationOrganizationGitCredentials_Success(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Load organization profiles from YAML
	yamlContent, err := os.ReadFile("testdata/org-profiles-basic.yaml")
	require.NoError(t, err)

	profiles, err := profiletest.CompileFromYAML(string(yamlContent))
	require.NoError(t, err)
	harness.ProfileStore.Update(profiles)

	// Setup: Configure mock to return token
	harness.GitHubMock.Token = "ghs_orgtoken789"

	// Create valid JWT with Buildkite claims
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:test-pipeline:ref:refs/heads/main:commit:abc123:step:build",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "test-pipeline",
		"pipeline_id":       "pipeline-123",
		"build_number":      42,
		"build_branch":      "main",
		"build_commit":      "abc123",
		"step_key":          "build",
		"job_id":            "job-456",
		"agent_id":          "agent-789",
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

	// Make request for organization profile git credentials
	reqBody := strings.NewReader("protocol=https\nhost=github.com\npath=test-org/repo1\n\n")
	req, err := http.NewRequest("POST", harness.Server.URL+"/organization/git-credentials/test-org-profile", reqBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse git credentials response
	props, err := credentialhandler.ReadProperties(resp.Body)
	require.NoError(t, err)

	// Verify token and path
	assert.Equal(t, "ghs_orgtoken789", props.Get("password"))
	assert.Equal(t, "test-org/repo1", props.Get("path"))
}

func TestIntegrationPipelineGitCredentials_MissingAuth(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Make request without Authorization header
	reqBody := strings.NewReader("protocol=https\nhost=github.com\npath=test-org/test-repo\n\n")
	req, err := http.NewRequest("POST", harness.Server.URL+"/git-credentials", reqBody)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestIntegrationPipelineGitCredentials_InvalidJWT(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Make request with invalid JWT
	reqBody := strings.NewReader("protocol=https\nhost=github.com\npath=test-org/test-repo\n\n")
	req, err := http.NewRequest("POST", harness.Server.URL+"/git-credentials", reqBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify 401 Unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIntegrationPipelineGitCredentials_ProfileNotFound(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Create valid JWT with Buildkite claims
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:test-pipeline:ref:refs/heads/main:commit:abc123:step:build",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "test-pipeline",
		"pipeline_id":       "pipeline-123",
		"build_number":      42,
		"build_branch":      "main",
		"build_commit":      "abc123",
		"step_key":          "build",
		"job_id":            "job-456",
		"agent_id":          "agent-789",
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

	// Make request with non-existent profile
	reqBody := strings.NewReader("protocol=https\nhost=github.com\npath=test-org/test-repo\n\n")
	req, err := http.NewRequest("POST", harness.Server.URL+"/git-credentials/nonexistent", reqBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify 404 Not Found
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ============================================================================
// Request Size Limit Tests
// ============================================================================

func TestIntegrationRequestSizeLimit_GitCredentials(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Create valid JWT with Buildkite claims
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "org:test-org:pipeline:test-pipeline:ref:refs/heads/main:commit:abc123:step:build",
	})
	buildkiteClaims := map[string]interface{}{
		"organization_slug": "test-org",
		"pipeline_slug":     "test-pipeline",
		"pipeline_id":       "pipeline-123",
		"build_number":      42,
		"build_branch":      "main",
		"build_commit":      "abc123",
		"step_key":          "build",
		"job_id":            "job-456",
		"agent_id":          "agent-789",
	}
	token := harness.GenerateToken(claims, buildkiteClaims)

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
