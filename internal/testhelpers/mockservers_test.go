package testhelpers_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/google/go-github/v90/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
)

// A configured status in the 2xx range is a success: GitHub answers some
// requests with 201, and the mock must still return the body a caller parses.
func TestMockGitHubServerSuccessStatuses(t *testing.T) {
	const installationID = int64(77)

	tests := []struct {
		name       string
		statusCode int
	}{
		{name: "default", statusCode: 0},
		{name: "explicit 200", statusCode: http.StatusOK},
		{name: "created", statusCode: http.StatusCreated},
		{name: "accepted", statusCode: http.StatusAccepted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := testhelpers.SetupMockGitHubServer(t)
			defer mock.Close()

			mock.SetInstallation(installationID, testhelpers.MockInstallation{
				AccountID:    42,
				AccountLogin: "acme",
				StatusCode:   tt.statusCode,
				Token:        "installation-token",
			})

			expectedStatus := tt.statusCode
			if expectedStatus == 0 {
				expectedStatus = http.StatusOK
			}

			installationResponse := get(t, fmt.Sprintf("%s/app/installations/%d", mock.Server.URL, installationID))
			assert.Equal(t, expectedStatus, installationResponse.status)

			var installation github.Installation
			require.NoError(t, json.Unmarshal(installationResponse.body, &installation))
			assert.Equal(t, installationID, installation.GetID())
			assert.Equal(t, "Organization", installation.GetTargetType())
			assert.Equal(t, int64(42), installation.GetAccount().GetID())
			assert.Equal(t, "acme", installation.GetAccount().GetLogin())

			tokenResponse := post(t, fmt.Sprintf("%s/app/installations/%d/access_tokens", mock.Server.URL, installationID))
			assert.Equal(t, expectedStatus, tokenResponse.status)

			var token github.InstallationToken
			require.NoError(t, json.Unmarshal(tokenResponse.body, &token))
			assert.Equal(t, "installation-token", token.GetToken())
		})
	}
}

// A non-2xx status is a failure: the status is written with no body, so a
// caller sees the error rather than a usable response.
func TestMockGitHubServerFailureStatuses(t *testing.T) {
	const installationID = int64(88)

	tests := []struct {
		name       string
		statusCode int
	}{
		{name: "unauthorized", statusCode: http.StatusUnauthorized},
		{name: "not found", statusCode: http.StatusNotFound},
		{name: "server error", statusCode: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := testhelpers.SetupMockGitHubServer(t)
			defer mock.Close()

			mock.SetInstallation(installationID, testhelpers.MockInstallation{StatusCode: tt.statusCode})

			installationResponse := get(t, fmt.Sprintf("%s/app/installations/%d", mock.Server.URL, installationID))
			assert.Equal(t, tt.statusCode, installationResponse.status)
			assert.Empty(t, installationResponse.body)

			tokenResponse := post(t, fmt.Sprintf("%s/app/installations/%d/access_tokens", mock.Server.URL, installationID))
			assert.Equal(t, tt.statusCode, tokenResponse.status)
			assert.Empty(t, tokenResponse.body)
		})
	}
}

type response struct {
	status int
	body   []byte
}

func get(t *testing.T, url string) response {
	t.Helper()
	return do(t, http.MethodGet, url)
}

func post(t *testing.T, url string) response {
	t.Helper()
	return do(t, http.MethodPost, url)
}

func do(t *testing.T, method, url string) response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, url, http.NoBody)
	require.NoError(t, err)

	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	return response{status: res.StatusCode, body: body}
}
