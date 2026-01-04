//go:build integration

package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// TestIntegrationSetup verifies the integration test framework is configured correctly
func TestIntegrationSetup(t *testing.T) {
	t.Log("Integration test framework initialized successfully")
}

// TestJWTHelpers verifies JWT generation helpers work correctly
func TestJWTHelpers(t *testing.T) {
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
func TestMockServers(t *testing.T) {
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
	t              *testing.T
	Server         *httptest.Server
	JWKSServer     *httptest.Server
	GitHubMock     *testhelpers.MockGitHubServer
	BuildkiteMock  *testhelpers.MockBuildkiteServer
	ProfileStore   *profile.ProfileStore
	jwk            *jose.JSONWebKey
	privateKeyPEM  string
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
func TestAPIHarness(t *testing.T) {
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
func TestHealthCheck(t *testing.T) {
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
