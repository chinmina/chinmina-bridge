package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
)

func TestAuditor_Success(t *testing.T) {
	successfulVendor := func(ctx context.Context, claims jwt.BuildkiteClaims, repo string, profile string) (*vendor.ProfileToken, error) {
		return &vendor.ProfileToken{
			Repositories:           []string{"https://example.com/repo"},
			Permissions:            []string{"contents:read"},
			RequestedRepositoryURL: "https://example.com/repo",
			Expiry:                 time.Now().Add(1 * time.Hour),
		}, nil
	}
	auditedVendor := vendor.Auditor(successfulVendor)

	ctx, _ := audit.Context(context.Background())
	claims := jwt.BuildkiteClaims{}
	repo := "example-repo"
	profile := "example-profile"
	defaultProfile := ""

	token, err := auditedVendor(ctx, claims, repo, defaultProfile)

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "https://example.com/repo", token.RequestedRepositoryURL)

	entry := audit.Log(ctx)
	assert.Empty(t, entry.Error)
	assert.Equal(t, []string{"https://example.com/repo"}, entry.Repositories)
	assert.Equal(t, []string{"contents:read"}, entry.Permissions)
	assert.NotZero(t, entry.ExpirySecs)

	token, err = auditedVendor(ctx, claims, repo, profile)

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "https://example.com/repo", token.RequestedRepositoryURL)

	entry = audit.Log(ctx)
	assert.Empty(t, entry.Error)
	assert.Equal(t, []string{"https://example.com/repo"}, entry.Repositories)
	assert.Equal(t, []string{"contents:read"}, entry.Permissions)
	assert.NotZero(t, entry.ExpirySecs)

}

func TestAuditor_Mismatch(t *testing.T) {
	successfulVendor := func(ctx context.Context, claims jwt.BuildkiteClaims, repo string, profile string) (*vendor.ProfileToken, error) {
		return nil, nil
	}
	auditedVendor := vendor.Auditor(successfulVendor)

	ctx, _ := audit.Context(context.Background())
	claims := jwt.BuildkiteClaims{}
	repo := "example-repo"

	token, err := auditedVendor(ctx, claims, repo, "")

	assert.NoError(t, err)
	assert.Nil(t, token)

	entry := audit.Log(ctx)
	assert.Equal(t, "repository mismatch, no token vended", entry.Error)
	assert.Empty(t, entry.Repositories)
	assert.Empty(t, entry.Permissions)
	assert.Zero(t, entry.ExpirySecs)
}

func TestAuditor_Failure(t *testing.T) {
	failingVendor := func(ctx context.Context, claims jwt.BuildkiteClaims, repo string, profile string) (*vendor.ProfileToken, error) {
		return nil, errors.New("vendor error")
	}
	auditedVendor := vendor.Auditor(failingVendor)

	ctx, _ := audit.Context(context.Background())
	claims := jwt.BuildkiteClaims{}
	repo := "example-repo"

	token, err := auditedVendor(ctx, claims, repo, "")
	assert.Error(t, err)
	assert.Nil(t, token)

	entry := audit.Log(ctx)
	assert.Equal(t, "vendor failure: vendor error", entry.Error)
	assert.Empty(t, entry.Repositories)
	assert.Empty(t, entry.Permissions)
	assert.Zero(t, entry.ExpirySecs)
}
func TestAuditor_ProfileAuditing(t *testing.T) {
	profileVendor := func(ctx context.Context, claims jwt.BuildkiteClaims, repo string, profile string) (*vendor.ProfileToken, error) {
		return &vendor.ProfileToken{
			Repositories:           []string{"https://example.com/repo"},
			Permissions:            []string{"contents:read"},
			RequestedRepositoryURL: "https://example.com/repo",
			Profile:                profile,
			Expiry:                 time.Now().Add(1 * time.Hour),
		}, nil
	}
	// Testing auditing over the cache layer as there
	// are resultant changes to audit objects.
	vendorCache, err := vendor.Cached(45 * time.Minute)
	assert.NoError(t, err)

	auditedVendor := vendor.Auditor(vendorCache(profileVendor))

	ctx, _ := audit.Context(context.Background())
	claims := jwt.BuildkiteClaims{}
	repo := "example-repo"
	profile := "org:test-profile"
	emptyProfile := ""

	// Case 1: Test with empty profile
	_, err = auditedVendor(ctx, claims, repo, emptyProfile)

	assert.NoError(t, err)

	entry := audit.Log(ctx)
	assert.Empty(t, entry.Error)
	assert.Equal(t, entry.RequestedProfile, "repo:default")

	// Case 2: Test with specified profile
	_, err = auditedVendor(ctx, claims, repo, profile)

	assert.NoError(t, err)

	entry = audit.Log(ctx)
	assert.Empty(t, entry.Error)
	assert.Equal(t, profile, entry.RequestedProfile)
}
