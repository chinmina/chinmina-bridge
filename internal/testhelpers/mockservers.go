package testhelpers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-github/v89/github"
)

// MockGitHubServer provides a configurable mock GitHub API server for testing.
// The request counter is atomic: tests may drive the server concurrently.
type MockGitHubServer struct {
	Server       *httptest.Server
	Token        string    // Token to return from CreateAccessToken
	Expiry       time.Time // Expiry time for the token
	StatusCode   int       // HTTP status code to return (200 if not set)
	requestCount atomic.Int64
}

// RequestCount reports how many requests the server has received.
func (m *MockGitHubServer) RequestCount() int {
	return int(m.requestCount.Load())
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
		mock.requestCount.Add(1)

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

// MockBuildkiteServer provides a configurable mock Buildkite API server for
// testing. The request counter and captured header are guarded: tests may
// drive the server concurrently.
type MockBuildkiteServer struct {
	Server        *httptest.Server
	RepositoryURL string // Repository URL to return from pipeline lookup
	StatusCode    int    // HTTP status code to return (200 if not set)
	requestCount  atomic.Int64

	mu             sync.Mutex
	lastAuthHeader string // Captured Authorization header from last request
}

// RequestCount reports how many requests the server has received.
func (m *MockBuildkiteServer) RequestCount() int {
	return int(m.requestCount.Load())
}

// LastAuthHeader reports the Authorization header of the most recent request.
func (m *MockBuildkiteServer) LastAuthHeader() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.lastAuthHeader
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
		mock.requestCount.Add(1)

		mock.mu.Lock()
		mock.lastAuthHeader = r.Header.Get("Authorization")
		mock.mu.Unlock()

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
