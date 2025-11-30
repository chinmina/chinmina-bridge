package vendor_test

import (
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for ProfileToken and utility functions that don't depend on the New() function

func TestProfileToken_URL(t *testing.T) {
	testCases := []struct {
		name          string
		repositoryURL string
		expectedURL   string
		expectedError string
	}{
		{
			name:          "valid absolute URL",
			repositoryURL: "https://github.com/org/repo",
			expectedURL:   "https://github.com/org/repo",
		},
		{
			name:          "valid absolute URL with path",
			repositoryURL: "https://github.com/org/repo/path/to/file",
			expectedURL:   "https://github.com/org/repo/path/to/file",
		},
		{
			name:          "invalid relative URL",
			repositoryURL: "org/repo",
			expectedError: "repository URL must be absolute: org/repo",
		},
		{
			name:          "invalid URL",
			repositoryURL: "://invalid",
			expectedError: "parse \"://invalid\": missing protocol scheme",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := vendor.ProfileToken{RequestedRepositoryURL: tc.repositoryURL}
			url, err := token.URL()

			if tc.expectedError != "" {
				require.Error(t, err)
				assert.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedURL, url.String())
			}
		})
	}
}

func TestProfileToken_ExpiryUnix(t *testing.T) {
	testCases := []struct {
		name     string
		expiry   time.Time
		expected string
	}{
		{
			name:     "UTC time",
			expiry:   time.Date(2023, 5, 1, 12, 0, 0, 0, time.UTC),
			expected: "1682942400",
		},
		{
			name:     "+1000 timezone",
			expiry:   time.Date(2023, 5, 1, 22, 0, 0, 0, time.FixedZone("+1000", 10*60*60)),
			expected: "1682942400",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := vendor.ProfileToken{
				Expiry: tc.expiry,
			}

			actual := token.ExpiryUnix()
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestTranslateSSHToHTTPS(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "ssh, valid GitHub",
			url:      "git@github.com:organization/chinmina.git",
			expected: "https://github.com/organization/chinmina.git",
		},
		{
			name:     "ssh, no user",
			url:      "github.com:organization/chinmina.git",
			expected: "github.com:organization/chinmina.git",
		},
		{
			name:     "ssh, different host",
			url:      "git@githab.com:organization/chinmina.git",
			expected: "git@githab.com:organization/chinmina.git",
		},
		{
			name:     "ssh, another different host",
			url:      "git@githubxcom:organization/chinmina.git",
			expected: "git@githubxcom:organization/chinmina.git",
		},
		{
			name:     "ssh, invalid path specifier",
			url:      "git@github.com/organization/chinmina.git",
			expected: "git@github.com/organization/chinmina.git",
		},
		{
			name:     "ssh, zero length path",
			url:      "git@github.com:",
			expected: "git@github.com:",
		},
		{
			name:     "ssh, no extension",
			url:      "git@github.com:organization/chinmina",
			expected: "https://github.com/organization/chinmina",
		},
		{
			name:     "https, valid",
			url:      "https://github.com/organization/chinmina.git",
			expected: "https://github.com/organization/chinmina.git",
		},
		{
			name:     "https, nonsense",
			url:      "https://githubxcom/passthrough.git",
			expected: "https://githubxcom/passthrough.git",
		},
		{
			name:     "http, valid",
			url:      "http://github.com/organization/chinmina.git",
			expected: "http://github.com/organization/chinmina.git",
		},
		{
			name:     "pure nonsense",
			url:      "molybdenum://mo",
			expected: "molybdenum://mo",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := vendor.TranslateSSHToHTTPS(tc.url)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
