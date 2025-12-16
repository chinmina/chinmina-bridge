package github_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/github"
	api "github.com/google/go-github/v80/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_FailsWithInvalidConfig(t *testing.T) {
	_, err := github.New(
		context.Background(),
		config.GithubConfig{
			// at least one of these is required
			PrivateKey:    "",
			PrivateKeyARN: "",
		},
	)
	assert.ErrorContains(t, err, "no private key configuration specified")
}

func TestNew_SucceedsWithKMSConfig(t *testing.T) {
	// set a purposefully invalid endpoint to prevent any errant remote calls
	t.Setenv("AWS_ENDPOINT_URL", "http://localhost:20987/not-bound")

	_, err := github.New(
		context.Background(),
		config.GithubConfig{
			PrivateKeyARN: "arn://foo",
		},
	)
	assert.NoError(t, err)
}

func TestCreateAccessToken_Succeeds(t *testing.T) {
	router := http.NewServeMux()

	expectedExpiry := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)
	actualInstallation := "unknown"

	router.HandleFunc("/app/installations/{installationID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		actualInstallation = r.PathValue("installationID")

		JSON(w, &api.InstallationToken{
			Token:     api.Ptr("expected-token"),
			ExpiresAt: &api.Timestamp{Time: expectedExpiry},
		})
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	// generate valid key for testing
	key := generateKey(t)

	gh, err := github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     key,
			ApplicationID:  10,
			InstallationID: 20,
		},
	)
	require.NoError(t, err)

	token, expiry, err := gh.CreateAccessToken(context.Background(), []string{"https://github.com/organization/repository", "https://github.com/organization/another-repo"}, []string{"contents:read"})

	require.NoError(t, err)
	assert.Equal(t, "expected-token", token)
	assert.Equal(t, expectedExpiry, expiry)
	assert.Equal(t, "20", actualInstallation)
}

func TestCreateAccessToken_Succeeds_If_Some_URLs_Valid(t *testing.T) {
	router := http.NewServeMux()

	expectedExpiry := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)
	actualInstallation := "unknown"

	router.HandleFunc("/app/installations/{installationID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		actualInstallation = r.PathValue("installationID")

		JSON(w, &api.InstallationToken{
			Token:     api.Ptr("expected-token"),
			ExpiresAt: &api.Timestamp{Time: expectedExpiry},
		})
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	// generate valid key for testing
	key := generateKey(t)

	gh, err := github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     key,
			ApplicationID:  10,
			InstallationID: 20,
		},
	)
	require.NoError(t, err)

	token, expiry, err := gh.CreateAccessToken(context.Background(), []string{"repository", "google"}, []string{"contents:read"})

	require.NoError(t, err)
	assert.Equal(t, "expected-token", token)
	assert.Equal(t, expectedExpiry, expiry)
	assert.Equal(t, "20", actualInstallation)
}

func TestCreateAccessToken_Fails_On_Failed_Request(t *testing.T) {
	router := http.NewServeMux()

	router.HandleFunc("/app/installations/{installationID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	// generate valid key for testing
	key := generateKey(t)

	gh, err := github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     key,
			ApplicationID:  10,
			InstallationID: 20,
		},
	)
	require.NoError(t, err)

	tok, _, err := gh.CreateAccessToken(context.Background(), []string{"https://github.com/org/repo"}, []string{"contents:read"})

	assert.Equal(t, "", tok)
	require.Error(t, err)
	assert.ErrorContains(t, err, ": 418")
}

func TestTransportOptions(t *testing.T) {

	router := http.NewServeMux()

	expectedExpiry := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)

	router.HandleFunc("/app/installations/{installationID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {

		JSON(w, &api.InstallationToken{
			Token:     api.Ptr("expected-token"),
			ExpiresAt: &api.Timestamp{Time: expectedExpiry},
		})
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	// generate valid key for testing
	key := generateKey(t)

	_, err := github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     key,
			ApplicationID:  10,
			InstallationID: 20,
		},
	)
	require.NoError(t, err)

	_, err = github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     key,
			ApplicationID:  10,
			InstallationID: 20,
		},
		github.WithAppTransport,
	)
	require.NoError(t, err)

	_, err = github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     key,
			ApplicationID:  10,
			InstallationID: 20,
		},
		github.WithTokenTransport,
	)
	require.NoError(t, err)

	// Fail on invalid config
	_, err = github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     "badkey",
			ApplicationID:  10,
			InstallationID: 20,
		},
		github.WithTokenTransport,
	)
	require.Error(t, err)
}

func TestGetRepoNames_Succeeds(t *testing.T) {
	tests := []struct {
		name           string
		repositoryURLs []string
		expected       []string
	}{
		{
			name:           "valid URLs",
			repositoryURLs: []string{"https://github.com/organization/valid-repository", "https://github.com/organization/another-valid-repository"},
			expected:       []string{"valid-repository", "another-valid-repository"},
		},
		{
			name:           "some valid URLs",
			repositoryURLs: []string{"https://github.com/only-org-mentioned", "https://dodgey.com", "https://github.com/super-cool-org/super-cool-repo"},
			expected:       []string{"super-cool-repo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualRepoNames, err := github.GetRepoNames(tt.repositoryURLs)
			assert.Equal(t, tt.expected, actualRepoNames)
			assert.NoError(t, err)
		})
	}
}

func TestGetRepoNames_Fails(t *testing.T) {
	tests := []struct {
		name           string
		repositoryURLs []string
		expectedError  string
	}{
		{
			name:           "invalid URLs",
			repositoryURLs: []string{"sch_eme://invalid_url/", "https://totally-not-malware.com"},
			expectedError:  "no valid repository URLs found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := github.GetRepoNames(tt.repositoryURLs)
			assert.Error(t, err)
			assert.ErrorContains(t, err, tt.expectedError)
		})
	}
}

func TestScopesToPermissions_Succeeds(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		expected *api.InstallationPermissions
	}{
		{
			name:   "valid scopes",
			scopes: []string{"contents:read", "packages:write"},
			expected: &api.InstallationPermissions{
				Contents: api.Ptr("read"),
				Packages: api.Ptr("write"),
			},
		},
		{
			name:   "some valid scopes",
			scopes: []string{"blah", "pull_requests:write", "invalid:read", "actions:admin"},
			expected: &api.InstallationPermissions{
				PullRequests: api.Ptr("write"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualPermissions, err := github.ScopesToPermissions(tt.scopes)
			assert.Equal(t, tt.expected, actualPermissions)
			assert.NoError(t, err)
		})
	}
}

func TestScopesToPermissions_Fails(t *testing.T) {
	tests := []struct {
		name          string
		scopes        []string
		expectedError string
	}{
		{
			name:          "invalid permissions",
			scopes:        []string{"nonsense", "contents:", "invalid:read", "contents:invalid"},
			expectedError: "no valid permissions found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualPermissions, err := github.ScopesToPermissions(tt.scopes)
			assert.Equal(t, &api.InstallationPermissions{}, actualPermissions)
			assert.Error(t, err)
			assert.ErrorContains(t, err, tt.expectedError)
		})
	}
}

func JSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	res, _ := json.Marshal(payload)
	_, _ = w.Write(res)
}

// generateKey creates and PEM encodes a valid RSA private key for testing.
func generateKey(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	key := pem.EncodeToMemory(privateKeyPEM)

	return string(key)
}
