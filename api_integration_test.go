//go:build integration

package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
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
)

// TestIntegrationSetup verifies the integration test framework is configured correctly
func TestIntegrationSetup(t *testing.T) {
	t.Log("Integration test framework initialized successfully")
}

// TestJWTHelpers verifies JWT generation helpers work correctly
func TestIntegrationJWTHelpers(t *testing.T) {
	// Generate key pair
	jwk := testhelpers.GenerateJWK(t)
	if jwk == nil {
		t.Fatal("expected JWK to be generated")
	}

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
	if token == "" {
		t.Fatal("expected token to be generated")
	}

	t.Log("JWT helpers verified successfully")
}

// TestMockServers verifies GitHub and Buildkite mock servers work correctly
func TestIntegrationMockServers(t *testing.T) {
	t.Run("GitHub mock server", func(t *testing.T) {
		mock := testhelpers.SetupMockGitHubServer(t)
		defer mock.Close()

		// Verify server is running
		if mock.Server.URL == "" {
			t.Fatal("expected server URL to be set")
		}

		// Verify default response values
		if mock.Token != "test-github-token" {
			t.Errorf("expected default token, got %s", mock.Token)
		}

		t.Log("GitHub mock server verified")
	})

	t.Run("Buildkite mock server", func(t *testing.T) {
		mock := testhelpers.SetupMockBuildkiteServer(t)
		defer mock.Close()

		// Verify server is running
		if mock.Server.URL == "" {
			t.Fatal("expected server URL to be set")
		}

		// Verify default response values
		if mock.RepositoryURL != "https://github.com/test-org/test-repo" {
			t.Errorf("expected default repo URL, got %s", mock.RepositoryURL)
		}

		t.Log("Buildkite mock server verified")
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
	if err != nil {
		t.Fatalf("failed to configure server routes: %v", err)
	}

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
	if harness.Server == nil {
		t.Fatal("expected API server to be initialized")
	}
	if harness.JWKSServer == nil {
		t.Fatal("expected JWKS server to be initialized")
	}
	if harness.GitHubMock == nil {
		t.Fatal("expected GitHub mock to be initialized")
	}
	if harness.BuildkiteMock == nil {
		t.Fatal("expected Buildkite mock to be initialized")
	}

	t.Log("API harness verified successfully")
}

// TestHealthCheck verifies the healthcheck endpoint works without authentication
func TestIntegrationHealthCheck(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Make request to healthcheck endpoint (no auth required)
	resp, err := http.Get(harness.Server.URL + "/healthcheck")
	if err != nil {
		t.Fatalf("failed to make healthcheck request: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	t.Log("Healthcheck endpoint verified")
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
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Parse response body (do this first to see error messages)
	var tokenResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil && resp.StatusCode == http.StatusOK {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify response
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Response: %v", resp.StatusCode, tokenResponse)
	}

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", resp.Header.Get("Content-Type"))
	}

	// Verify token response structure
	if tokenResponse["token"] != "ghs_testtoken123" {
		t.Errorf("expected token 'ghs_testtoken123', got %v", tokenResponse["token"])
	}
	if tokenResponse["organizationSlug"] != "test-org" {
		t.Errorf("expected organizationSlug 'test-org', got %v", tokenResponse["organizationSlug"])
	}
	if tokenResponse["profile"] != "repo:default" {
		t.Errorf("expected profile 'repo:default', got %v", tokenResponse["profile"])
	}

	t.Log("Pipeline token success test verified")
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
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var tokenResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if tokenResponse["profile"] != "repo:default" {
		t.Errorf("expected profile 'repo:default', got %v", tokenResponse["profile"])
	}
	if tokenResponse["token"] != "ghs_defaulttoken" {
		t.Errorf("expected token 'ghs_defaulttoken', got %v", tokenResponse["token"])
	}

	t.Log("Pipeline token with default profile verified")
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
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var tokenResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify all expected fields are present
	if tokenResponse["token"] == nil {
		t.Error("expected token field to be present")
	}
	if tokenResponse["expiry"] == nil {
		t.Error("expected expiry field to be present")
	}
	if tokenResponse["organizationSlug"] != "test-org" {
		t.Errorf("expected organizationSlug 'test-org', got %v", tokenResponse["organizationSlug"])
	}
	if tokenResponse["profile"] == nil {
		t.Error("expected profile field to be present")
	}

	t.Log("Pipeline token fields verified")
}

// TestPipelineToken_MissingAuth tests 400 response when JWT is missing
func TestIntegrationPipelineToken_MissingAuth(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Make request without Authorization header
	req, err := http.NewRequest("POST", harness.Server.URL+"/token", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify 400 Bad Request (missing auth header)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}

	t.Log("Pipeline token missing auth test verified")
}

// TestPipelineToken_InvalidJWT tests 401 response when JWT is invalid
func TestIntegrationPipelineToken_InvalidJWT(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Make request with invalid JWT
	req, err := http.NewRequest("POST", harness.Server.URL+"/token", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}

	t.Log("Pipeline token invalid JWT test verified")
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
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify 404 Not Found
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", resp.StatusCode)
	}

	// Verify JSON error response
	var errorResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errorResponse["error"] != "profile not found" {
		t.Errorf("expected error 'profile not found', got %v", errorResponse["error"])
	}

	t.Log("Pipeline token profile not found test verified")
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
	if err != nil {
		t.Fatalf("failed to read test profile YAML: %v", err)
	}

	profiles, err := profiletest.CompileFromYAML(string(yamlContent))
	if err != nil {
		t.Fatalf("failed to compile profiles: %v", err)
	}
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
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		t.Fatalf("expected status 200, got %d. Response: %s", resp.StatusCode, string(body[:n]))
	}

	var tokenResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify token response
	if tokenResponse["token"] != "ghs_orgtoken123" {
		t.Errorf("expected token 'ghs_orgtoken123', got %v", tokenResponse["token"])
	}
	if tokenResponse["organizationSlug"] != "test-org" {
		t.Errorf("expected organizationSlug 'test-org', got %v", tokenResponse["organizationSlug"])
	}
	if tokenResponse["profile"] != "org:test-org-profile" {
		t.Errorf("expected profile 'org:test-org-profile', got %v", tokenResponse["profile"])
	}

	// Verify repositories list
	repos, ok := tokenResponse["repositories"].([]interface{})
	if !ok || len(repos) != 2 {
		t.Errorf("expected 2 repositories, got %v", tokenResponse["repositories"])
	}

	t.Log("Organization token success test verified")
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
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify 404 Not Found
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", resp.StatusCode)
	}

	var errorResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errorResponse["error"] != "profile not found" {
		t.Errorf("expected error 'profile not found', got %v", errorResponse["error"])
	}

	t.Log("Organization token profile not found test verified")
}

// TestOrganizationToken_Unauthorized tests 401 when JWT is invalid
func TestIntegrationOrganizationToken_Unauthorized(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Load organization profiles from YAML
	yamlContent, err := os.ReadFile("testdata/org-profiles-basic.yaml")
	if err != nil {
		t.Fatalf("failed to read test profile YAML: %v", err)
	}

	profiles, err := profiletest.CompileFromYAML(string(yamlContent))
	if err != nil {
		t.Fatalf("failed to compile profiles: %v", err)
	}
	harness.ProfileStore.Update(profiles)

	// Make request with invalid JWT
	req, err := http.NewRequest("POST", harness.Server.URL+"/organization/token/test-org-profile", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}

	t.Log("Organization token unauthorized test verified")
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
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d. Body: %s", resp.StatusCode, string(body))
	}

	if resp.Header.Get("Content-Type") != "text/plain" {
		t.Errorf("expected Content-Type text/plain, got %s", resp.Header.Get("Content-Type"))
	}

	// Parse git credentials response
	props, err := credentialhandler.ReadProperties(resp.Body)
	if err != nil {
		t.Fatalf("failed to parse git credentials response: %v", err)
	}

	// Verify credential properties
	protocol := props.Get("protocol")
	if protocol != "https" {
		t.Errorf("expected protocol 'https', got %s", protocol)
	}

	host := props.Get("host")
	if host != "github.com" {
		t.Errorf("expected host 'github.com', got %s", host)
	}

	path := props.Get("path")
	if path != "test-org/test-repo" {
		t.Errorf("expected path 'test-org/test-repo', got %s", path)
	}

	username := props.Get("username")
	if username != "x-access-token" {
		t.Errorf("expected username 'x-access-token', got %s", username)
	}

	password := props.Get("password")
	if password != "ghs_testtoken123" {
		t.Errorf("expected password 'ghs_testtoken123', got %s", password)
	}

	passwordExpiry := props.Get("password_expiry_utc")
	if passwordExpiry == "" {
		t.Errorf("expected password_expiry_utc to be set")
	}

	t.Log("Pipeline git-credentials success test verified")
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
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d. Body: %s", resp.StatusCode, string(body))
	}

	// Parse git credentials response
	props, err := credentialhandler.ReadProperties(resp.Body)
	if err != nil {
		t.Fatalf("failed to parse git credentials response: %v", err)
	}

	// Verify token is correct
	password := props.Get("password")
	if password != "ghs_testtoken456" {
		t.Errorf("expected password 'ghs_testtoken456', got %s", password)
	}

	t.Log("Pipeline git-credentials with explicit profile test verified")
}

func TestIntegrationOrganizationGitCredentials_Success(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Load organization profiles from YAML
	yamlContent, err := os.ReadFile("testdata/org-profiles-basic.yaml")
	if err != nil {
		t.Fatalf("failed to read test profile YAML: %v", err)
	}

	profiles, err := profiletest.CompileFromYAML(string(yamlContent))
	if err != nil {
		t.Fatalf("failed to compile profiles: %v", err)
	}
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
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d. Body: %s", resp.StatusCode, string(body))
	}

	// Parse git credentials response
	props, err := credentialhandler.ReadProperties(resp.Body)
	if err != nil {
		t.Fatalf("failed to parse git credentials response: %v", err)
	}

	// Verify token and path
	password := props.Get("password")
	if password != "ghs_orgtoken789" {
		t.Errorf("expected password 'ghs_orgtoken789', got %s", password)
	}

	path := props.Get("path")
	if path != "test-org/repo1" {
		t.Errorf("expected path 'test-org/repo1', got %s", path)
	}

	t.Log("Organization git-credentials success test verified")
}

func TestIntegrationPipelineGitCredentials_MissingAuth(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Make request without Authorization header
	reqBody := strings.NewReader("protocol=https\nhost=github.com\npath=test-org/test-repo\n\n")
	req, err := http.NewRequest("POST", harness.Server.URL+"/git-credentials", reqBody)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify 400 Bad Request
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}

	t.Log("Pipeline git-credentials missing auth test verified")
}

func TestIntegrationPipelineGitCredentials_InvalidJWT(t *testing.T) {
	harness := NewAPITestHarness(t)
	defer harness.Close()

	// Make request with invalid JWT
	reqBody := strings.NewReader("protocol=https\nhost=github.com\npath=test-org/test-repo\n\n")
	req, err := http.NewRequest("POST", harness.Server.URL+"/git-credentials", reqBody)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}

	t.Log("Pipeline git-credentials invalid JWT test verified")
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
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify 404 Not Found
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", resp.StatusCode)
	}

	t.Log("Pipeline git-credentials profile not found test verified")
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
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Note: The current implementation returns 500 (Internal Server Error) when
	// the request body exceeds the 20KB limit. This happens because
	// credentialhandler.ReadProperties treats the "request body too large" error
	// as an internal error. The HTTP standard would be 413 (Request Entity Too Large).
	if resp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected status 500, got %d. Body: %s", resp.StatusCode, string(body))
	}

	t.Log("Request size limit git-credentials test verified")
}
