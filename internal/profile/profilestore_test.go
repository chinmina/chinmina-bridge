package profile_test

import (
	"errors"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewProfileStoreOf_OrganizationProfile verifies NewProfileStoreOf creates an immutable store for organization profiles.
func TestNewProfileStoreOf_OrganizationProfile(t *testing.T) {
	profiles := map[string]profile.AuthorizedProfile[profile.OrganizationProfileAttr]{
		"test": profile.NewAuthorizedProfile(
			profile.ExactMatcher("pipeline_slug", "my-pipeline"),
			profile.OrganizationProfileAttr{
				Repositories: []string{"chinmina/chinmina-bridge"},
				Permissions:  []string{"contents:read"},
			},
		),
	}
	invalidProfiles := map[string]error{
		"invalid-profile": errors.New("validation error"),
	}

	store := profile.NewProfileStoreOf(profiles, invalidProfiles)

	// Verify the store was created (non-nil check not needed for value type)
	_, err := store.Get("test")
	assert.NoError(t, err)
}

// TestNewProfileStoreOf_PipelineProfile verifies NewProfileStoreOf creates an immutable store for pipeline profiles.
func TestNewProfileStoreOf_PipelineProfile(t *testing.T) {
	profiles := map[string]profile.AuthorizedProfile[profile.PipelineProfileAttr]{
		"test": profile.NewAuthorizedProfile(
			profile.ExactMatcher("pipeline_slug", "my-pipeline"),
			profile.PipelineProfileAttr{},
		),
	}
	invalidProfiles := map[string]error{}

	store := profile.NewProfileStoreOf(profiles, invalidProfiles)

	// Verify the store was created
	_, err := store.Get("test")
	assert.NoError(t, err)
}

// TestProfileStoreOf_Get_Success verifies successful retrieval of a profile.
func TestProfileStoreOf_Get_Success(t *testing.T) {
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	attrs := profile.OrganizationProfileAttr{
		Repositories: []string{"chinmina/chinmina-bridge"},
		Permissions:  []string{"contents:read"},
	}
	authProfile := profile.NewAuthorizedProfile(matcher, attrs)

	profiles := map[string]profile.AuthorizedProfile[profile.OrganizationProfileAttr]{
		"test-profile": authProfile,
	}
	store := profile.NewProfileStoreOf(profiles, map[string]error{})

	// Retrieve the profile
	retrieved, err := store.Get("test-profile")
	require.NoError(t, err)
	assert.Equal(t, attrs, retrieved.Attrs)
}

// TestProfileStoreOf_Get_NotFound verifies ProfileNotFoundError is returned for missing profiles.
func TestProfileStoreOf_Get_NotFound(t *testing.T) {
	store := profile.NewProfileStoreOf(
		map[string]profile.AuthorizedProfile[profile.OrganizationProfileAttr]{},
		map[string]error{},
	)

	// Try to get a non-existent profile
	_, err := store.Get("nonexistent")

	require.Error(t, err)
	var notFoundErr profile.ProfileNotFoundError
	require.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "nonexistent", notFoundErr.Name)
}

// TestProfileStoreOf_Get_InvalidProfile verifies ProfileUnavailableError is returned for invalid profiles.
func TestProfileStoreOf_Get_InvalidProfile(t *testing.T) {
	validationErr := errors.New("invalid selector: missing required field")
	invalidProfiles := map[string]error{
		"invalid-profile": validationErr,
	}
	store := profile.NewProfileStoreOf(
		map[string]profile.AuthorizedProfile[profile.OrganizationProfileAttr]{},
		invalidProfiles,
	)

	// Try to get an invalid profile
	_, err := store.Get("invalid-profile")

	require.Error(t, err)
	var unavailableErr profile.ProfileUnavailableError
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "invalid-profile", unavailableErr.Name)
	assert.ErrorIs(t, unavailableErr, validationErr)
}

// TestProfileStoreOf_Get_InvalidProfileTakesPrecedence verifies that invalid profiles are checked before valid profiles.
func TestProfileStoreOf_Get_InvalidProfileTakesPrecedence(t *testing.T) {
	validationErr := errors.New("profile failed validation")

	// Create a profile with the same name in both maps
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	attrs := profile.OrganizationProfileAttr{
		Repositories: []string{"chinmina/chinmina-bridge"},
		Permissions:  []string{"contents:read"},
	}
	authProfile := profile.NewAuthorizedProfile(matcher, attrs)

	profiles := map[string]profile.AuthorizedProfile[profile.OrganizationProfileAttr]{
		"test-profile": authProfile,
	}
	invalidProfiles := map[string]error{
		"test-profile": validationErr,
	}

	store := profile.NewProfileStoreOf(profiles, invalidProfiles)

	// Invalid should take precedence
	_, err := store.Get("test-profile")

	require.Error(t, err)
	var unavailableErr profile.ProfileUnavailableError
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "test-profile", unavailableErr.Name)
	assert.ErrorIs(t, unavailableErr, validationErr)
}

// TestProfileStoreOf_Immutable verifies that ProfileStoreOf is immutable after creation.
func TestProfileStoreOf_Immutable(t *testing.T) {
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	attrs := profile.OrganizationProfileAttr{
		Repositories: []string{"chinmina/chinmina-bridge"},
		Permissions:  []string{"contents:read"},
	}
	authProfile := profile.NewAuthorizedProfile(matcher, attrs)

	profiles := map[string]profile.AuthorizedProfile[profile.OrganizationProfileAttr]{
		"test-profile": authProfile,
	}
	store := profile.NewProfileStoreOf(profiles, map[string]error{})

	// Retrieve the profile
	retrieved, err := store.Get("test-profile")
	require.NoError(t, err)
	assert.Equal(t, "chinmina/chinmina-bridge", retrieved.Attrs.Repositories[0])

	// Modify the source map (should not affect the store since it's immutable)
	newMatcher := profile.ExactMatcher("pipeline_slug", "other-pipeline")
	newAttrs := profile.OrganizationProfileAttr{
		Repositories: []string{"chinmina/other-repo"},
		Permissions:  []string{"packages:write"},
	}
	newAuthProfile := profile.NewAuthorizedProfile(newMatcher, newAttrs)
	profiles["test-profile"] = newAuthProfile

	// The store should still return the original profile
	retrieved2, err := store.Get("test-profile")
	require.NoError(t, err)
	assert.Equal(t, "chinmina/chinmina-bridge", retrieved2.Attrs.Repositories[0])
	assert.NotEqual(t, "chinmina/other-repo", retrieved2.Attrs.Repositories[0])
}
