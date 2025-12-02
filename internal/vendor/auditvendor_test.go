package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
)

func TestAuditor_Success(t *testing.T) {
	successfulVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) (*vendor.ProfileToken, error) {
		return &vendor.ProfileToken{
			Repositories:           []string{"https://example.com/repo"},
			Permissions:            []string{"contents:read"},
			RequestedRepositoryURL: "https://example.com/repo",
			Expiry:                 time.Now().Add(1 * time.Hour),
		}, nil
	}
	auditedVendor := vendor.Auditor(successfulVendor)

	ctx, _ := audit.Context(context.Background())
	repo := "example-repo"

	ref1 := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	token, err := auditedVendor(ctx, ref1, repo)

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "https://example.com/repo", token.RequestedRepositoryURL)

	entry := audit.Log(ctx)
	assert.Empty(t, entry.Error)
	assert.Equal(t, []string{"https://example.com/repo"}, entry.Repositories)
	assert.Equal(t, []string{"contents:read"}, entry.Permissions)
	assert.NotZero(t, entry.ExpirySecs)

	ref2 := profile.ProfileRef{
		Organization: "org",
		Name:         "test-profile",
		Type:         profile.ProfileTypeOrg,
		PipelineSlug: "",
	}
	token, err = auditedVendor(ctx, ref2, repo)

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
	successfulVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) (*vendor.ProfileToken, error) {
		return nil, nil
	}
	auditedVendor := vendor.Auditor(successfulVendor)

	ctx, _ := audit.Context(context.Background())
	repo := "example-repo"

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	token, err := auditedVendor(ctx, ref, repo)

	assert.NoError(t, err)
	assert.Nil(t, token)

	entry := audit.Log(ctx)
	assert.Equal(t, "repository mismatch, no token vended", entry.Error)
	assert.Empty(t, entry.Repositories)
	assert.Empty(t, entry.Permissions)
	assert.Zero(t, entry.ExpirySecs)
}

func TestAuditor_Failure(t *testing.T) {
	failingVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) (*vendor.ProfileToken, error) {
		return nil, errors.New("vendor error")
	}
	auditedVendor := vendor.Auditor(failingVendor)

	ctx, _ := audit.Context(context.Background())
	repo := "example-repo"

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	token, err := auditedVendor(ctx, ref, repo)
	assert.Error(t, err)
	assert.Nil(t, token)

	entry := audit.Log(ctx)
	assert.Equal(t, "vendor failure: vendor error", entry.Error)
	assert.Empty(t, entry.Repositories)
	assert.Empty(t, entry.Permissions)
	assert.Zero(t, entry.ExpirySecs)
}
func TestAuditor_ProfileAuditing(t *testing.T) {
	profileVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) (*vendor.ProfileToken, error) {
		return &vendor.ProfileToken{
			Repositories:           []string{"https://example.com/repo"},
			Permissions:            []string{"contents:read"},
			RequestedRepositoryURL: "https://example.com/repo",
			Profile:                ref.ShortString(),
			Expiry:                 time.Now().Add(1 * time.Hour),
		}, nil
	}
	// Testing auditing over the cache layer as there
	// are resultant changes to audit objects.
	vendorCache, err := vendor.Cached(45 * time.Minute)
	assert.NoError(t, err)

	auditedVendor := vendor.Auditor(vendorCache(profileVendor))

	ctx, _ := audit.Context(context.Background())
	repo := "example-repo"

	ref1 := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	// Case 1: Test with default profile - audit log should contain full URN
	_, err = auditedVendor(ctx, ref1, repo)

	assert.NoError(t, err)

	entry := audit.Log(ctx)
	assert.Empty(t, entry.Error)
	assert.Equal(t, "profile://organization/org/pipeline/pipeline-id/my-pipeline/profile/default", entry.RequestedProfile)

	ref2 := profile.ProfileRef{
		Organization: "org",
		Name:         "test-profile",
		Type:         profile.ProfileTypeOrg,
		PipelineSlug: "",
	}
	// Case 2: Test with specified profile - audit log should contain full URN
	_, err = auditedVendor(ctx, ref2, repo)

	assert.NoError(t, err)

	entry = audit.Log(ctx)
	assert.Empty(t, entry.Error)
	assert.Equal(t, "profile://organization/org/profile/test-profile", entry.RequestedProfile)
}
