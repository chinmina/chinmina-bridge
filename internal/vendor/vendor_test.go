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
			token := vendor.ProfileToken{VendedRepositoryURL: tc.repositoryURL}
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

func TestNewVendorSuccess(t *testing.T) {
	token := vendor.ProfileToken{
		OrganizationSlug:    "test-org",
		Profile:             "test-profile",
		VendedRepositoryURL: "https://github.com/test/repo",
		Token:               "test-token",
		Expiry:              time.Date(2023, 5, 1, 12, 0, 0, 0, time.UTC),
	}

	result := vendor.NewVendorSuccess(token)

	assertVendorSuccess(t, result, token)
}

func TestNewVendorUnmatched(t *testing.T) {
	result := vendor.NewVendorUnmatched()

	assertVendorUnmatched(t, result)
}

func TestNewVendorFailed(t *testing.T) {
	result := vendor.NewVendorFailed(assert.AnError)

	assertVendorFailure(t, result, "general error for testing")
}

func TestVendorResult_Failed(t *testing.T) {
	testCases := []struct {
		name         string
		result       vendor.VendorResult
		expectFailed bool
		expectError  error
	}{
		{
			name:         "success returns not failed",
			result:       vendor.NewVendorSuccess(vendor.ProfileToken{}),
			expectFailed: false,
			expectError:  nil,
		},
		{
			name:         "unmatched returns not failed",
			result:       vendor.NewVendorUnmatched(),
			expectFailed: false,
			expectError:  nil,
		},
		{
			name:         "failed returns failed with error",
			result:       vendor.NewVendorFailed(assert.AnError),
			expectFailed: true,
			expectError:  assert.AnError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err, failed := tc.result.Failed()
			assert.Equal(t, tc.expectFailed, failed)
			assert.Equal(t, tc.expectError, err)
		})
	}
}

func TestVendorResult_Token(t *testing.T) {
	testToken := vendor.ProfileToken{
		OrganizationSlug:    "test-org",
		Profile:             "test-profile",
		VendedRepositoryURL: "https://github.com/test/repo",
		Token:               "test-token",
		Expiry:              time.Date(2023, 5, 1, 12, 0, 0, 0, time.UTC),
	}

	testCases := []struct {
		name        string
		result      vendor.VendorResult
		expectOk    bool
		expectToken vendor.ProfileToken
	}{
		{
			name:        "success returns token and true",
			result:      vendor.NewVendorSuccess(testToken),
			expectOk:    true,
			expectToken: testToken,
		},
		{
			name:        "unmatched returns false",
			result:      vendor.NewVendorUnmatched(),
			expectOk:    false,
			expectToken: vendor.ProfileToken{},
		},
		{
			name:        "failed returns false",
			result:      vendor.NewVendorFailed(assert.AnError),
			expectOk:    false,
			expectToken: vendor.ProfileToken{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, ok := tc.result.Token()
			assert.Equal(t, tc.expectOk, ok)
			assert.Equal(t, tc.expectToken, token)
		})
	}
}
