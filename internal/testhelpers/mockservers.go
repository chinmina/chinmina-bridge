package testhelpers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-github/v90/github"
)

// MockInstallation is the mocked response for one installation. The app
// registry compares account IDs, so a test makes apps share or differ in
// organisation purely by choosing IDs.
type MockInstallation struct {
	AccountID    int64
	AccountLogin string

	// AccountType is the installation's target_type. Empty defaults to
	// "Organization", the only type most tests care about.
	AccountType string

	// StatusCode is the response status for this installation's endpoints.
	// Zero means 200; a non-2xx fails one app's installation only.
	StatusCode int

	// Token overrides the token minted for this installation, so a test can
	// attribute a response to an app.
	Token string
}

// MockGitHubServer provides a configurable mock GitHub API server for testing.
// Responses and counters are per installation as well as server-wide, so one
// server can serve several apps and a test can assert which installations were
// contacted. Counters and the installation table are guarded: tests may drive
// the server concurrently.
type MockGitHubServer struct {
	Server     *httptest.Server
	Token      string    // Token to return from CreateAccessToken
	Expiry     time.Time // Expiry time for the token
	StatusCode int       // HTTP status code to return (200 if not set)

	// DefaultInstallation answers any installation a test has not configured
	// explicitly.
	DefaultInstallation MockInstallation

	requestCount           atomic.Int64
	installationQueryCount atomic.Int64
	tokenRequestCount      atomic.Int64

	mu              sync.Mutex
	installations   map[int64]MockInstallation
	perInstallCalls map[int64]int
}

// RequestCount reports how many requests the server has received.
func (m *MockGitHubServer) RequestCount() int {
	return int(m.requestCount.Load())
}

// InstallationQueryCount reports how many installation lookups were made.
func (m *MockGitHubServer) InstallationQueryCount() int {
	return int(m.installationQueryCount.Load())
}

// TokenRequestCount reports how many installation tokens were minted.
func (m *MockGitHubServer) TokenRequestCount() int {
	return int(m.tokenRequestCount.Load())
}

// CallsForInstallation reports how many requests named this installation,
// across both the query and mint endpoints.
func (m *MockGitHubServer) CallsForInstallation(installationID int64) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.perInstallCalls[installationID]
}

// SetInstallation overrides DefaultInstallation for one installation.
func (m *MockGitHubServer) SetInstallation(installationID int64, installation MockInstallation) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.installations[installationID] = installation
}

// installationFor returns the configured response for an installation, or
// DefaultInstallation, and records the call against it.
func (m *MockGitHubServer) installationFor(installationID int64) MockInstallation {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.perInstallCalls[installationID]++

	if installation, configured := m.installations[installationID]; configured {
		return installation
	}
	return m.DefaultInstallation
}

// SetupMockGitHubServer creates a mock GitHub API server that handles token creation requests.
// Returns a MockGitHubServer with configurable response values and request tracking.
func SetupMockGitHubServer(t *testing.T) *MockGitHubServer {
	t.Helper()

	mock := &MockGitHubServer{
		Token:      "test-github-token",
		Expiry:     time.Now().Add(1 * time.Hour),
		StatusCode: http.StatusOK,
		DefaultInstallation: MockInstallation{
			AccountID:    1,
			AccountLogin: "test-org",
		},
		installations:   map[int64]MockInstallation{},
		perInstallCalls: map[int64]int{},
	}

	router := http.NewServeMux()

	router.HandleFunc("/app/installations/{installationID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		mock.requestCount.Add(1)
		mock.tokenRequestCount.Add(1)

		installation := mock.installationFor(installationIDFromPath(r))

		if status := effectiveStatus(mock.StatusCode, installation.StatusCode); status != http.StatusOK {
			w.WriteHeader(status)
			return
		}

		tokenValue := mock.Token
		if installation.Token != "" {
			tokenValue = installation.Token
		}

		expiryTimestamp := github.Timestamp{Time: mock.Expiry}
		token := &github.InstallationToken{
			Token:     &tokenValue,
			ExpiresAt: &expiryTimestamp,
		}

		WriteJSON(w, token)
	})

	router.HandleFunc("GET /app/installations/{installationID}", func(w http.ResponseWriter, r *http.Request) {
		mock.requestCount.Add(1)
		mock.installationQueryCount.Add(1)

		installationID := installationIDFromPath(r)
		installation := mock.installationFor(installationID)

		if status := effectiveStatus(mock.StatusCode, installation.StatusCode); status != http.StatusOK {
			w.WriteHeader(status)
			return
		}

		accountType := installation.AccountType
		if accountType == "" {
			accountType = "Organization"
		}

		WriteJSON(w, &github.Installation{
			ID:         &installationID,
			TargetType: &accountType,
			Account: &github.User{
				ID:    &installation.AccountID,
				Login: &installation.AccountLogin,
			},
		})
	})

	mock.Server = httptest.NewServer(router)
	return mock
}

// effectiveStatus prefers a per-installation status over the server-wide one,
// so a test can fail one app while the others succeed.
func effectiveStatus(serverStatus, installationStatus int) int {
	if installationStatus != 0 {
		return installationStatus
	}
	if serverStatus == 0 {
		return http.StatusOK
	}
	return serverStatus
}

func installationIDFromPath(r *http.Request) int64 {
	id, err := strconv.ParseInt(r.PathValue("installationID"), 10, 64)
	if err != nil {
		return 0
	}
	return id
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
