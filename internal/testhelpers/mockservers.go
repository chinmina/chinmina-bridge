package testhelpers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-github/v80/github"
)

// MockGitHubServer provides a configurable mock GitHub API server for testing.
type MockGitHubServer struct {
	Server       *httptest.Server
	Token        string    // Token to return from CreateAccessToken
	Expiry       time.Time // Expiry time for the token
	StatusCode   int       // HTTP status code to return (200 if not set)
	RequestCount int       // Number of requests received
}

// SetupMockGitHubServer creates a mock GitHub API server that handles token creation requests.
// Returns a MockGitHubServer with configurable response values and request tracking.
func SetupMockGitHubServer(t *testing.T) *MockGitHubServer {
	t.Helper()

	mock := &MockGitHubServer{
		Token:      "test-github-token",
		Expiry:     time.Now().Add(1 * time.Hour),
		StatusCode: http.StatusOK,
	}

	router := http.NewServeMux()

	router.HandleFunc("/app/installations/{installationID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		mock.RequestCount++

		if mock.StatusCode != http.StatusOK {
			w.WriteHeader(mock.StatusCode)
			return
		}

		expiryTimestamp := github.Timestamp{Time: mock.Expiry}
		token := &github.InstallationToken{
			Token:     &mock.Token,
			ExpiresAt: &expiryTimestamp,
		}

		WriteJSON(w, token)
	})

	mock.Server = httptest.NewServer(router)
	return mock
}

// Close shuts down the mock server.
func (m *MockGitHubServer) Close() {
	m.Server.Close()
}

// MockBuildkiteServer provides a configurable mock Buildkite API server for testing.
type MockBuildkiteServer struct {
	Server         *httptest.Server
	RepositoryURL  string // Repository URL to return from pipeline lookup
	StatusCode     int    // HTTP status code to return (200 if not set)
	RequestCount   int    // Number of requests received
	LastAuthHeader string // Captured Authorization header from last request
}

// SetupMockBuildkiteServer creates a mock Buildkite API server that handles pipeline lookups.
// Returns a MockBuildkiteServer with configurable response values and request tracking.
func SetupMockBuildkiteServer(t *testing.T) *MockBuildkiteServer {
	t.Helper()

	mock := &MockBuildkiteServer{
		RepositoryURL: "https://github.com/test-org/test-repo",
		StatusCode:    http.StatusOK,
	}

	router := http.NewServeMux()

	router.HandleFunc("/v2/organizations/{organization}/pipelines/{pipeline}", func(w http.ResponseWriter, r *http.Request) {
		mock.RequestCount++
		mock.LastAuthHeader = r.Header.Get("Authorization")

		if mock.StatusCode != http.StatusOK {
			w.WriteHeader(mock.StatusCode)
			return
		}

		pipeline := r.PathValue("pipeline")

		response := struct {
			Name       string `json:"name"`
			Slug       string `json:"slug"`
			Repository string `json:"repository"`
		}{
			Name:       pipeline,
			Slug:       pipeline,
			Repository: mock.RepositoryURL,
		}

		WriteJSON(w, response)
	})

	mock.Server = httptest.NewServer(router)
	return mock
}

// Close shuts down the mock server.
func (m *MockBuildkiteServer) Close() {
	m.Server.Close()
}

// WriteJSON is a helper function that writes a JSON response.
// It sets the Content-Type header and marshals the payload to JSON.
func WriteJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(payload)
	if err != nil {
		// In test context, this should never happen with valid test data
		http.Error(w, fmt.Sprintf("failed to marshal JSON: %v", err), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(data)
}
