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

// MockInstallation is the mocked response for one installation: the account it
// belongs to, and whether querying it succeeds at all.
//
// The account ID is what the app registry compares on, so a test distinguishes
// "same organization" from "different organization" purely by choosing IDs.
// Login exists so a test can assert what was logged, not what was decided.
type MockInstallation struct {
	AccountID    int64
	AccountLogin string

	// StatusCode is the response status for this installation's endpoints.
	// Zero means 200. A non-2xx here is how a test drives "this app's
	// installation cannot be queried" for one app without affecting the rest.
	StatusCode int

	// Token overrides the token minted for this installation, so an end-to-end
	// test can tell which app a response was minted through.
	Token string
}

// MockGitHubServer provides a configurable mock GitHub API server for testing.
//
// Responses are configurable per installation so one server can serve an app
// on the default account, an app on a different account, and an app whose
// installation cannot be queried, in a single boot. Counters are per
// installation as well as global, so a test can assert which installations
// were contacted and not merely how many calls were made.
//
// Counters and the installation table are guarded: tests may drive the server
// concurrently.
type MockGitHubServer struct {
	Server     *httptest.Server
	Token      string    // Token to return from CreateAccessToken
	Expiry     time.Time // Expiry time for the token
	StatusCode int       // HTTP status code to return (200 if not set)

	// DefaultInstallation answers any installation a test has not configured
	// explicitly, which keeps single-app tests working unchanged.
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
// R19 is asserted on this: a deployment with no app registry configured must
// query no installation at startup.
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

// SetInstallation configures the response for one installation, overriding
// DefaultInstallation for it.
func (m *MockGitHubServer) SetInstallation(installationID int64, installation MockInstallation) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.installations[installationID] = installation
}

// installationFor returns the configured response for an installation, falling
// back to DefaultInstallation, and records the call against it.
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

		// The server-wide StatusCode remains the single-app control it has
		// always been; a per-installation status narrows it to one app.
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

		WriteJSON(w, &github.Installation{
			ID: &installationID,
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
// so a test can fail one app's installation while the others succeed.
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
