package profile

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_Success(t *testing.T) {
	tests := []struct {
		name     string
		filename string
	}{
		{
			name:     "valid profile",
			filename: "testdata/profile/valid_profile.yaml",
		},
		{
			name:     "profile with defaults",
			filename: "testdata/profile/profile_with_defaults.yaml",
		},
		{
			name:     "profile with match rules",
			filename: "testdata/profile/profile_with_match_rules.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yamlContent, err := os.ReadFile(tt.filename)
			require.NoError(t, err)

			config, digest, err := parse(string(yamlContent))

			require.NoError(t, err)
			assert.NotEmpty(t, digest, "digest should not be empty")
			assert.NotEmpty(t, config.Organization.Profiles, "profiles should be loaded")
		})
	}
}

func TestParse_UnknownFieldRejection(t *testing.T) {
	yamlContent, err := os.ReadFile("testdata/profile/invalid_profile.yaml")
	require.NoError(t, err)

	_, _, err = parse(string(yamlContent))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "organization profile file parsing failed")
}

func TestParse_DigestCalculation(t *testing.T) {
	yamlContent1, err := os.ReadFile("testdata/profile/valid_profile.yaml")
	require.NoError(t, err)

	yamlContent2, err := os.ReadFile("testdata/profile/profile_with_defaults.yaml")
	require.NoError(t, err)

	// Parse same content twice
	_, digest1a, err := parse(string(yamlContent1))
	require.NoError(t, err)

	_, digest1b, err := parse(string(yamlContent1))
	require.NoError(t, err)

	// Parse different content
	_, digest2, err := parse(string(yamlContent2))
	require.NoError(t, err)

	// Same content should produce same digest
	assert.Equal(t, digest1a, digest1b, "identical YAML should produce identical digests")

	// Different content should produce different digests
	assert.NotEqual(t, digest1a, digest2, "different YAML should produce different digests")

	// Digests should be SHA256 hex strings (64 characters)
	assert.Len(t, digest1a, 64, "digest should be 64 character hex string")
	assert.Len(t, digest2, 64, "digest should be 64 character hex string")
}

func TestClaimValidationError_Format(t *testing.T) {
	err := ClaimValidationError{
		Claim: "test_claim",
		Value: "test value",
		Err:   assert.AnError,
	}

	assert.Equal(t, `claim "test_claim" validation failed for value "test value": assert.AnError general error for testing`, err.Error())
}

func TestClaimValidationError_Status(t *testing.T) {
	err := ClaimValidationError{
		Claim: "test_claim",
		Value: "test value",
		Err:   assert.AnError,
	}

	code, message := err.Status()
	assert.Equal(t, 403, code)
	assert.Equal(t, "Forbidden", message)
}

func TestClaimValidationError_Unwrap(t *testing.T) {
	innerErr := assert.AnError
	err := ClaimValidationError{
		Claim: "test_claim",
		Value: "test value",
		Err:   innerErr,
	}

	assert.Equal(t, innerErr, err.Unwrap())
}

func TestProfileUnavailableError_Format(t *testing.T) {
	err := ProfileUnavailableError{
		Name:  "test-profile",
		Cause: assert.AnError,
	}

	assert.Equal(t, `profile "test-profile" unavailable: validation failed`, err.Error())
}

func TestProfileUnavailableError_Status(t *testing.T) {
	err := ProfileUnavailableError{
		Name:  "test-profile",
		Cause: assert.AnError,
	}

	code, message := err.Status()
	assert.Equal(t, 404, code)
	assert.Equal(t, "profile unavailable: validation failed", message)
}

func TestProfileUnavailableError_Unwrap(t *testing.T) {
	innerErr := assert.AnError
	err := ProfileUnavailableError{
		Name:  "test-profile",
		Cause: innerErr,
	}

	assert.Equal(t, innerErr, err.Unwrap())
}

func TestProfileNotFoundError_Format(t *testing.T) {
	err := ProfileNotFoundError{
		Name: "test-profile",
	}

	assert.Equal(t, `profile "test-profile" not found`, err.Error())
}

func TestProfileNotFoundError_Status(t *testing.T) {
	err := ProfileNotFoundError{
		Name: "test-profile",
	}

	code, message := err.Status()
	assert.Equal(t, 404, code)
	assert.Equal(t, "profile not found", message)
}

func TestProfileMatchFailedError_Format(t *testing.T) {
	err := ProfileMatchFailedError{
		Name: "test-profile",
	}

	assert.Equal(t, `profile "test-profile" match conditions not met`, err.Error())
}

func TestProfileMatchFailedError_Status(t *testing.T) {
	err := ProfileMatchFailedError{
		Name: "test-profile",
	}

	code, message := err.Status()
	assert.Equal(t, 403, code)
	assert.Equal(t, "Forbidden", message)
}

func TestProfileStoreNotLoadedError_Format(t *testing.T) {
	err := ProfileStoreNotLoadedError{}

	assert.Equal(t, "organization profile not loaded", err.Error())
}

func TestProfileStoreNotLoadedError_Status(t *testing.T) {
	err := ProfileStoreNotLoadedError{}

	code, message := err.Status()
	assert.Equal(t, 503, code)
	assert.Equal(t, "organization profile not loaded", message)
}
