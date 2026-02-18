//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/jwt/jwxtest"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/server"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
	"github.com/valkey-io/valkey-go"
)

// APITestHarness manages the complete test environment for API integration tests.
// It sets up mock servers, generates JWTs, and provides the API server for testing.
type APITestHarness struct {
	DefaultAudience     string
	DefaultOrganization string
	t                   *testing.T
	Server              *httptest.Server
	JWKSServer          *httptest.Server
	GitHubMock          *testhelpers.MockGitHubServer
	BuildkiteMock       *testhelpers.MockBuildkiteServer
	ProfileStore        *profile.ProfileStore
	jwk                 jwxtest.JWK
	valkeyAddr          string
	valkeyPassword      string
}

// APITestHarnessOption configures the API test harness.
type APITestHarnessOption func(*config.Config)

// WithValkeyCache configures the test harness to use a Valkey cache container.
func WithValkeyCache() APITestHarnessOption {
	return func(cfg *config.Config) {
		cfg.Cache.Type = "valkey"
	}
}

// NewAPITestHarness creates a complete test harness with all mock servers and the API server.
// Use options to customize the configuration (e.g., WithValkeyCache).
// Cleanup is handled automatically via t.Cleanup().
func NewAPITestHarness(t *testing.T, options ...APITestHarnessOption) *APITestHarness {
	t.Helper()
	testhelpers.SetupLogger(t)
	hooks := server.ShutdownHooks{}

	t.Cleanup(func() {
		hooks.Execute(t.Context())
	})

	harness := &APITestHarness{
		DefaultAudience:     "test-audience",
		DefaultOrganization: "test-org",
		t:                   t,
		ProfileStore:        profile.NewProfileStore(),
	}

	// Generate JWK for JWT signing
	harness.jwk = jwxtest.NewJWK(t)

	// Setup mock servers
	harness.JWKSServer = jwxtest.SetupJWKSServer(t, harness.jwk)
	harness.GitHubMock = testhelpers.SetupMockGitHubServer(t)
	harness.BuildkiteMock = testhelpers.SetupMockBuildkiteServer(t)

	hooks.AddClose("jwks", harness.JWKSServer)
	hooks.AddClose("github", harness.GitHubMock)
	hooks.AddClose("buildkite", harness.BuildkiteMock)

	// Initialize with default profiles
	harness.ProfileStore.Update(context.Background(), profile.NewDefaultProfiles())

	// Configure and start the API server
	cfg := config.Config{
		Authorization: config.AuthorizationConfig{
			Audience:                  harness.DefaultAudience,
			BuildkiteOrganizationSlug: harness.DefaultOrganization,
			IssuerURL:                 harness.JWKSServer.URL,
		},
		Buildkite: config.BuildkiteConfig{
			APIURL: harness.BuildkiteMock.Server.URL,
			Token:  "test-buildkite-token",
		},
		Cache: config.CacheConfig{
			Type: "memory", // Default to memory cache for tests
		},
		Github: config.GithubConfig{
			APIURL:         harness.GitHubMock.Server.URL,
			PrivateKey:     harness.jwk.PrivateKeyPEM(),
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

	// Apply options
	for _, opt := range options {
		opt(&cfg)
	}

	if cfg.Cache.Type == "valkey" {
		cacheCfg := testhelpers.RunValkeyContainer(t)
		cfg.Cache = cacheCfg
		harness.valkeyAddr = cacheCfg.Valkey.Address
		harness.valkeyPassword = cacheCfg.Valkey.Password
	}

	handler, err := configureServerRoutes(context.Background(), cfg, harness.ProfileStore, &hooks)
	require.NoError(t, err)

	harness.Server = httptest.NewServer(handler)
	hooks.AddClose("api-server", harness.Server)

	return harness
}

// GenerateToken creates a valid JWT signed with the test JWK.
// The token parameter should be configured with all desired claims.
func (h *APITestHarness) GenerateToken(token jwxjwt.Token) string {
	return jwxtest.SignToken(h.t, h.jwk, h.JWKSServer.URL, token)
}

// PipelineToken generates a valid JWT with default Buildkite pipeline claims for testing.
func (h *APITestHarness) PipelineToken(tokenOptions ...TokenClaimOption) string {
	bc := jwt.BuildkiteClaims{
		OrganizationSlug: h.DefaultOrganization,
		PipelineSlug:     "test-pipeline",
		PipelineID:       "pipeline-123",
		BuildNumber:      42,
		BuildBranch:      "main",
		BuildCommit:      "abc123",
		StepKey:          "build",
		JobID:            "job-456",
		AgentID:          "agent-789",
	}

	for _, opt := range tokenOptions {
		opt(&bc)
	}

	// Create token with standard claims
	token := jwxjwt.New()
	_ = token.Set(jwxjwt.AudienceKey, []string{h.DefaultAudience})
	_ = token.Set(jwxjwt.SubjectKey, fmt.Sprintf(
		"org:%s:pipeline:%s:ref:refs/heads/%s:commit:%s:step:%s",
		h.DefaultOrganization,
		bc.PipelineSlug,
		bc.BuildBranch,
		bc.BuildCommit,
		bc.StepKey,
	))

	// Add Buildkite custom claims
	if err := bc.SetOnToken(token); err != nil {
		h.t.Fatalf("failed to set Buildkite claims on token: %v", err)
	}

	// Add timing claims
	token = jwxtest.AddTimingClaims(token)

	return h.GenerateToken(token)
}

type TokenClaimOption func(*jwt.BuildkiteClaims)

// WithPipeline sets the pipeline slug and ID in the Buildkite claims. For use
// with PipelineToken().
func WithPipeline(slug string, id string) TokenClaimOption {
	return func(bc *jwt.BuildkiteClaims) {
		bc.PipelineSlug = slug
		bc.PipelineID = id
	}
}

// Client returns a TestClient configured for this harness.
func (h *APITestHarness) Client() *TestClient {
	return &TestClient{
		baseURL: h.Server.URL,
		client:  http.DefaultClient,
	}
}

// newTestValkeyClient returns a connected valkey client for direct Valkey
// access in tests. Skips the test if this harness does not use Valkey.
func (h *APITestHarness) newTestValkeyClient(t *testing.T) valkey.Client {
	t.Helper()

	if h.valkeyAddr == "" {
		t.Skip("not a Valkey harness")
	}

	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{h.valkeyAddr},
		Username:    "default",
		Password:    h.valkeyPassword,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		client.Close()
	})

	return client
}

// APIError represents a non-2xx response from the API.
type APIError struct {
	StatusCode int
	Body       []byte
	Message    string // parsed from JSON error response if available
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("API error %d", e.StatusCode)
}

// TestClient provides typed access to chinmina API endpoints for testing.
type TestClient struct {
	baseURL string
	client  *http.Client
}

// GitCredentialRequest represents input to git-credentials endpoints.
type GitCredentialRequest struct {
	Protocol string
	Host     string
	Path     string
}

// Response wraps raw HTTP response for low-level assertions.
type Response struct {
	StatusCode int
	Body       []byte
	Headers    http.Header
}

// Request performs a low-level HTTP request and returns the raw response.
// This method is useful for testing error cases and edge conditions.
func (c *TestClient) Request(method, path, token string, body io.Reader) (*Response, error) {
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       bodyBytes,
		Headers:    resp.Header,
	}, nil
}

// RequestJSON performs a request and returns the parsed JSON response.
// Returns the parsed JSON, status code, and any error.
func (c *TestClient) RequestJSON(method, path, token string, body io.Reader) (map[string]any, int, error) {
	resp, err := c.Request(method, path, token, body)
	if err != nil {
		return nil, 0, err
	}

	var result map[string]any
	if len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, &result); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("unmarshal JSON: %w", err)
		}
	}

	return result, resp.StatusCode, nil
}

// Token requests a pipeline token for the given profile.
// Returns the token result or an error if the request fails or returns non-2xx.
func (c *TestClient) Token(token, profile string) (*vendor.ProfileToken, error) {
	path := "/token"
	if profile != "" {
		path = "/token/" + profile
	}

	resp, err := c.Request("POST", path, token, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var result vendor.ProfileToken
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal token response: %w", err)
	}

	return &result, nil
}

// GitCredentials requests git credentials for the given profile.
// Returns the credentials map or an error if the request fails or returns non-2xx.
func (c *TestClient) GitCredentials(token, profile string, req GitCredentialRequest) (*credentialhandler.ArrayMap, error) {
	path := "/git-credentials"
	if profile != "" {
		path = "/git-credentials/" + profile
	}

	// Build git credentials request body
	body := fmt.Sprintf("protocol=%s\nhost=%s\npath=%s\n\n", req.Protocol, req.Host, req.Path)

	resp, err := c.Request("POST", path, token, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	// Parse git credentials response
	props, err := credentialhandler.ReadProperties(bytes.NewReader(resp.Body))
	if err != nil {
		return nil, fmt.Errorf("parse git credentials: %w", err)
	}

	return props, nil
}

// OrganizationToken requests an organization token for the given profile.
// Returns the token result or an error if the request fails or returns non-2xx.
func (c *TestClient) OrganizationToken(token, profile string) (*vendor.ProfileToken, error) {
	path := "/organization/token/" + profile

	resp, err := c.Request("POST", path, token, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var result vendor.ProfileToken
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal token response: %w", err)
	}

	return &result, nil
}

// OrganizationGitCredentials requests organization git credentials for the given profile.
// Returns the credentials map or an error if the request fails or returns non-2xx.
func (c *TestClient) OrganizationGitCredentials(token, profile string, req GitCredentialRequest) (*credentialhandler.ArrayMap, error) {
	path := "/organization/git-credentials/" + profile

	// Build git credentials request body
	body := fmt.Sprintf("protocol=%s\nhost=%s\npath=%s\n\n", req.Protocol, req.Host, req.Path)

	resp, err := c.Request("POST", path, token, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	// Parse git credentials response
	props, err := credentialhandler.ReadProperties(bytes.NewReader(resp.Body))
	if err != nil {
		return nil, fmt.Errorf("parse git credentials: %w", err)
	}

	return props, nil
}

// parseError attempts to parse an error response from the API.
func (c *TestClient) parseError(resp *Response) error {
	apiErr := &APIError{
		StatusCode: resp.StatusCode,
		Body:       resp.Body,
	}

	// Try to parse JSON error message
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &errResp); err == nil && errResp.Error != "" {
		apiErr.Message = errResp.Error
	}

	return apiErr
}
