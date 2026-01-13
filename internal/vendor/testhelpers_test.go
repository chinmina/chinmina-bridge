package vendor_test

import (
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/cache"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDigester returns a fixed digest for testing
type mockDigester struct {
	digest string
}

func (m mockDigester) Digest() string {
	return m.digest
}

// newTestCached creates a Cached vendor with the specified TTL and digest
func newTestCached(t *testing.T, ttl time.Duration, digest string) func(vendor.ProfileTokenVendor) vendor.ProfileTokenVendor {
	t.Helper()
	tokenCache, err := cache.NewMemory[vendor.ProfileToken](ttl, 10_000)
	require.NoError(t, err)
	digester := mockDigester{digest: digest}
	return vendor.Cached(tokenCache, digester)
}

// assertVendorSuccess verifies that vending succeeded and returns the expected token
func assertVendorSuccess(t *testing.T, result vendor.VendorResult, expected vendor.ProfileToken) {
	t.Helper()
	_, failed := result.Failed()
	require.False(t, failed, "expected vendor to succeed")
	token, ok := result.Token()
	require.True(t, ok, "expected token to be present")
	assert.Equal(t, expected, token)
}

func assertVendorTokenValue(t *testing.T, result vendor.VendorResult, expected string) {
	t.Helper()
	_, failed := result.Failed()
	require.False(t, failed, "expected vendor to succeed")
	token, ok := result.Token()
	require.True(t, ok, "expected token to be present")
	assert.Equal(t, expected, token.Token)
}

// assertVendorUnmatched verifies that vending succeeded but no token was returned (unmatched case)
func assertVendorUnmatched(t *testing.T, result vendor.VendorResult) {
	t.Helper()
	_, failed := result.Failed()
	require.False(t, failed, "expected vendor to succeed with no match")
	_, ok := result.Token()
	require.False(t, ok, "expected no token for unmatched case")
}

// assertVendorFailure verifies that vending failed with the expected error
func assertVendorFailure(t *testing.T, result vendor.VendorResult, expectedErrorSubstring string) {
	t.Helper()
	err, failed := result.Failed()
	require.True(t, failed, "expected vendor to fail")
	require.ErrorContains(t, err, expectedErrorSubstring)
}
