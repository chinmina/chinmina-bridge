package github_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
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

	tok, _, err := gh.CreateAccessToken(
		context.Background(),
		[]string{"https://github.com/org/repo"},
		[]string{"contents:read"},
	)

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
	cfg := config.GithubConfig{
		ApiURL:         svr.URL,
		PrivateKey:     key,
		ApplicationID:  10,
		InstallationID: 20,
	}

	// Default transport
	_, err := github.New(
		context.Background(),
		cfg,
	)
	require.NoError(t, err)

	_, err = github.New(
		context.Background(),
		cfg,
		github.WithAppTransport,
	)
	require.NoError(t, err)

	_, err = github.New(
		context.Background(),
		cfg,
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

func TestGetFileContent_Succeeds(t *testing.T) {
	router := http.NewServeMux()

	router.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, &api.RepositoryContent{
			Type:     api.Ptr("file"),
			Content:  api.Ptr(base64.StdEncoding.EncodeToString([]byte("expected content"))),
			Encoding: api.Ptr("base64"),
		})
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	gh, err := github.New(
		context.Background(),
		config.GithubConfig{ApiURL: svr.URL},
		withPlainTransport,
	)
	require.NoError(t, err)

	content, err := gh.GetFileContent(context.Background(), "owner", "repo", "path/to/file.txt")
	require.NoError(t, err)
	assert.Equal(t, "expected content", content)
}

func TestGetFileContent_Fails_On_Directory(t *testing.T) {
	router := http.NewServeMux()

	router.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, []*api.RepositoryContent{
			{
				Type: api.Ptr("file"),
				Name: api.Ptr("file1.txt"),
			},
			{
				Type: api.Ptr("file"),
				Name: api.Ptr("file2.txt"),
			},
		})
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	gh, err := github.New(
		context.Background(),
		config.GithubConfig{ApiURL: svr.URL},
		withPlainTransport,
	)
	require.NoError(t, err)

	content, err := gh.GetFileContent(context.Background(), "owner", "repo", "some-directory")
	assert.Equal(t, "", content)
	require.Error(t, err)
	assert.ErrorContains(t, err, "is a directory, expected a file")
}

func TestGetFileContent_Fails_On_API_Error(t *testing.T) {
	router := http.NewServeMux()

	router.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	gh, err := github.New(
		context.Background(),
		config.GithubConfig{ApiURL: svr.URL},
		withPlainTransport,
	)
	require.NoError(t, err)

	content, err := gh.GetFileContent(context.Background(), "owner", "repo", "nonexistent.txt")
	assert.Equal(t, "", content)
	require.Error(t, err)
}

func TestGetFileContent_Fails_On_No_Content(t *testing.T) {
	router := http.NewServeMux()

	router.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("null"))
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	gh, err := github.New(
		context.Background(),
		config.GithubConfig{ApiURL: svr.URL},
		withPlainTransport,
	)
	require.NoError(t, err)

	content, err := gh.GetFileContent(context.Background(), "owner", "repo", "empty.txt")
	assert.Equal(t, "", content)
	require.Error(t, err)
	assert.ErrorContains(t, err, "returned no content")
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

// withPlainTransport creates a transport with no auth - for testing only
func withPlainTransport(clientConfig *github.ClientConfig) {
	clientConfig.TransportFactory = func(ctx context.Context, cfg config.GithubConfig, wrapped http.RoundTripper) (http.RoundTripper, error) {
		return wrapped, nil
	}
}
