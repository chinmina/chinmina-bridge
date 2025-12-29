package profile

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOrganizationProfileAttr_HasRepository tests the HasRepository method
func TestOrganizationProfileAttr_HasRepository_Match(t *testing.T) {
	tests := []struct {
		name         string
		repositories []string
		repo         string
		expected     bool
	}{
		{
			name:         "exact match in list",
			repositories: []string{"acme/repo1", "acme/repo2"},
			repo:         "acme/repo1",
			expected:     true,
		},
		{
			name:         "wildcard matches any",
			repositories: []string{"*"},
			repo:         "any/repository",
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := OrganizationProfileAttr{
				Repositories: tt.repositories,
			}
			assert.Equal(t, tt.expected, attr.HasRepository(tt.repo))
		})
	}
}

func TestOrganizationProfileAttr_HasRepository_NoMatch(t *testing.T) {
	tests := []struct {
		name         string
		repositories []string
		repo         string
	}{
		{
			name:         "partial match fails",
			repositories: []string{"acme/repo"},
			repo:         "acme",
		},
		{
			name:         "over-match fails",
			repositories: []string{"acme/repo"},
			repo:         "acme/repo-extra",
		},
		{
			name:         "empty list fails",
			repositories: []string{},
			repo:         "acme/repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := OrganizationProfileAttr{
				Repositories: tt.repositories,
			}
			assert.False(t, attr.HasRepository(tt.repo))
		})
	}
}

// TestOrganizationProfileAttr_GetRepositories tests the GetRepositories method
func TestOrganizationProfileAttr_GetRepositories_SpecificRepos(t *testing.T) {
	tests := []struct {
		name         string
		repositories []string
		expected     []string
	}{
		{
			name:         "single repository",
			repositories: []string{"acme/repo1"},
			expected:     []string{"acme/repo1"},
		},
		{
			name:         "multiple repositories",
			repositories: []string{"acme/repo1", "acme/repo2", "other/repo3"},
			expected:     []string{"acme/repo1", "acme/repo2", "other/repo3"},
		},
		{
			name:         "empty list",
			repositories: []string{},
			expected:     []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := OrganizationProfileAttr{
				Repositories: tt.repositories,
			}
			assert.Equal(t, tt.expected, attr.GetRepositories())
		})
	}
}

func TestOrganizationProfileAttr_GetRepositories_Wildcard(t *testing.T) {
	attr := OrganizationProfileAttr{
		Repositories: []string{"*"},
	}

	// nil indicates all repositories
	assert.Nil(t, attr.GetRepositories())
}

// TestAuthorizedProfile_Match tests the Match method behavior
func TestAuthorizedProfile_Match_Success(t *testing.T) {
	matcher := ExactMatcher("pipeline_slug", "silk-prod")
	attrs := OrganizationProfileAttr{
		Repositories: []string{"acme/silk"},
		Permissions:  []string{"contents:read"},
	}
	profile := NewAuthorizedProfile(matcher, attrs)

	claims := mapClaimLookup{"pipeline_slug": "silk-prod"}
	result := profile.Match(claims)

	assert.True(t, result.Matched)
	assert.Equal(t, []ClaimMatch{
		{Claim: "pipeline_slug", Value: "silk-prod"},
	}, result.Matches)
	assert.Nil(t, result.Attempt)
	assert.NoError(t, result.Err)
}

func TestAuthorizedProfile_Match_ClaimValueMismatch(t *testing.T) {
	matcher := ExactMatcher("pipeline_slug", "silk-prod")
	attrs := OrganizationProfileAttr{
		Repositories: []string{"acme/silk"},
	}
	profile := NewAuthorizedProfile(matcher, attrs)

	claims := mapClaimLookup{"pipeline_slug": "cotton-prod"}
	result := profile.Match(claims)

	assert.False(t, result.Matched)
	assert.Empty(t, result.Matches)
	require.NotNil(t, result.Attempt)
	assert.Equal(t, MatchAttempt{
		Claim:       "pipeline_slug",
		Pattern:     "silk-prod",
		ActualValue: "cotton-prod",
	}, *result.Attempt)
	assert.NoError(t, result.Err)
}

func TestAuthorizedProfile_Match_ClaimNotFound(t *testing.T) {
	matcher := ExactMatcher("pipeline_slug", "silk-prod")
	attrs := OrganizationProfileAttr{
		Repositories: []string{"acme/silk"},
	}
	profile := NewAuthorizedProfile(matcher, attrs)

	claims := mapClaimLookup{}
	result := profile.Match(claims)

	assert.False(t, result.Matched)
	assert.Empty(t, result.Matches)
	require.NotNil(t, result.Attempt)
	assert.Equal(t, MatchAttempt{
		Claim:       "pipeline_slug",
		Pattern:     "silk-prod",
		ActualValue: "",
	}, *result.Attempt)
	assert.NoError(t, result.Err)
}

func TestAuthorizedProfile_Match_ValidationError(t *testing.T) {
	matcher := ExactMatcher("pipeline_slug", "silk-prod")
	attrs := OrganizationProfileAttr{
		Repositories: []string{"acme/silk"},
	}
	profile := NewAuthorizedProfile(matcher, attrs)

	// Use validating lookup with invalid claim value
	baseLookup := mapClaimLookup{"pipeline_slug": "test\tvalue"}
	validating := NewValidatingLookup(baseLookup)

	result := profile.Match(validating)

	assert.False(t, result.Matched)
	assert.Empty(t, result.Matches)
	assert.Nil(t, result.Attempt)
	require.Error(t, result.Err)

	var valErr ClaimValidationError
	require.ErrorAs(t, result.Err, &valErr)
}

// TestProfileStoreOf tests the generic ProfileStoreOf type
func TestProfileStoreOf_NewAndGet_OrganizationProfile(t *testing.T) {
	matcher := ExactMatcher("pipeline_slug", "silk-prod")
	profiles := map[string]AuthorizedProfile[OrganizationProfileAttr]{
		"test-profile": NewAuthorizedProfile(matcher, OrganizationProfileAttr{
			Repositories: []string{"acme/silk"},
			Permissions:  []string{"contents:read"},
		}),
	}

	store := NewProfileStoreOf(profiles, nil)

	profile, err := store.Get("test-profile")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/silk"}, profile.Attrs.Repositories)
	assert.Equal(t, []string{"contents:read"}, profile.Attrs.Permissions)
}

func TestProfileStoreOf_NewAndGet_PipelineProfile(t *testing.T) {
	matcher := CompositeMatcher()
	profiles := map[string]AuthorizedProfile[PipelineProfileAttr]{
		"test-profile": NewAuthorizedProfile(matcher, PipelineProfileAttr{}),
	}

	store := NewProfileStoreOf(profiles, nil)

	profile, err := store.Get("test-profile")
	require.NoError(t, err)
	assert.Equal(t, PipelineProfileAttr{}, profile.Attrs)
}

func TestProfileStoreOf_Get_NotFound(t *testing.T) {
	store := NewProfileStoreOf[OrganizationProfileAttr](nil, nil)

	_, err := store.Get("nonexistent")
	require.Error(t, err)

	var notFoundErr ProfileNotFoundError
	require.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "nonexistent", notFoundErr.Name)
}

func TestProfileStoreOf_Get_Unavailable(t *testing.T) {
	invalidProfiles := map[string]error{
		"invalid-profile": errors.New("validation failed"),
	}

	store := NewProfileStoreOf[OrganizationProfileAttr](nil, invalidProfiles)

	_, err := store.Get("invalid-profile")
	require.Error(t, err)

	var unavailErr ProfileUnavailableError
	require.ErrorAs(t, err, &unavailErr)
	assert.Equal(t, "invalid-profile", unavailErr.Name)
	assert.Equal(t, "validation failed", unavailErr.Cause.Error())
}

func TestProfileStoreOf_Immutability(t *testing.T) {
	matcher := ExactMatcher("pipeline_slug", "silk-prod")
	sourceProfiles := map[string]AuthorizedProfile[OrganizationProfileAttr]{
		"test-profile": NewAuthorizedProfile(matcher, OrganizationProfileAttr{
			Repositories: []string{"acme/silk"},
			Permissions:  []string{"contents:read"},
		}),
	}

	store := NewProfileStoreOf(sourceProfiles, nil)

	// Get the profile before modification
	profileBefore, err := store.Get("test-profile")
	require.NoError(t, err)

	// Modify the source map
	delete(sourceProfiles, "test-profile")

	// Profile should still be accessible from store
	profileAfter, err := store.Get("test-profile")
	require.NoError(t, err)
	assert.Equal(t, profileBefore.Attrs.Repositories, profileAfter.Attrs.Repositories)
}

// TestProfiles tests the Profiles type
func TestProfiles_NewProfiles(t *testing.T) {
	matcher := ExactMatcher("pipeline_slug", "silk-prod")
	orgProfiles := NewProfileStoreOf(
		map[string]AuthorizedProfile[OrganizationProfileAttr]{
			"test-profile": NewAuthorizedProfile(matcher, OrganizationProfileAttr{
				Repositories: []string{"acme/silk"},
			}),
		},
		nil,
	)

	pipelineDefaults := []string{"contents:read"}
	digest := "test-digest"

	profiles := NewProfiles(orgProfiles, pipelineDefaults, digest)

	assert.True(t, profiles.IsLoaded())
	assert.Equal(t, digest, profiles.digest)
}

func TestProfiles_GetOrgProfile_Success(t *testing.T) {
	matcher := ExactMatcher("pipeline_slug", "silk-prod")
	orgProfiles := NewProfileStoreOf(
		map[string]AuthorizedProfile[OrganizationProfileAttr]{
			"test-profile": NewAuthorizedProfile(matcher, OrganizationProfileAttr{
				Repositories: []string{"acme/silk"},
				Permissions:  []string{"contents:read"},
			}),
		},
		nil,
	)

	profiles := NewProfiles(orgProfiles, []string{"contents:read"}, "digest")

	profile, err := profiles.GetOrgProfile("test-profile")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/silk"}, profile.Attrs.Repositories)
	assert.Equal(t, []string{"contents:read"}, profile.Attrs.Permissions)
}

func TestProfiles_GetOrgProfile_NotLoaded(t *testing.T) {
	// Create empty Profiles (zero value simulates not loaded)
	profiles := Profiles{}

	_, err := profiles.GetOrgProfile("any-profile")
	require.Error(t, err)

	var notLoadedErr ProfileStoreNotLoadedError
	require.ErrorAs(t, err, &notLoadedErr)
}

func TestProfiles_GetPipelineDefaults_Configured(t *testing.T) {
	orgProfiles := NewProfileStoreOf[OrganizationProfileAttr](nil, nil)
	customDefaults := []string{"contents:read", "pull_requests:write"}

	profiles := NewProfiles(orgProfiles, customDefaults, "digest")

	defaults := profiles.GetPipelineDefaults()
	assert.Equal(t, customDefaults, defaults)
}

func TestProfiles_GetPipelineDefaults_Fallback(t *testing.T) {
	orgProfiles := NewProfileStoreOf[OrganizationProfileAttr](nil, nil)
	emptyDefaults := []string{}

	profiles := NewProfiles(orgProfiles, emptyDefaults, "digest")

	defaults := profiles.GetPipelineDefaults()
	assert.Equal(t, []string{"contents:read"}, defaults)
}

func TestProfiles_Immutability_SourceSlice(t *testing.T) {
	orgProfiles := NewProfileStoreOf[OrganizationProfileAttr](nil, nil)
	sourceDefaults := []string{"contents:read", "pull_requests:write"}

	profiles := NewProfiles(orgProfiles, sourceDefaults, "digest")

	// Modify source slice
	sourceDefaults[0] = "contents:write"
	sourceDefaults = append(sourceDefaults, "packages:read")

	// Profiles should be unchanged
	defaults := profiles.GetPipelineDefaults()
	assert.Equal(t, []string{"contents:read", "pull_requests:write"}, defaults)
}

func TestProfiles_Immutability_ReturnedSlice(t *testing.T) {
	orgProfiles := NewProfileStoreOf[OrganizationProfileAttr](nil, nil)
	sourceDefaults := []string{"contents:read", "pull_requests:write"}

	profiles := NewProfiles(orgProfiles, sourceDefaults, "digest")

	// Get defaults and modify returned slice
	defaults1 := profiles.GetPipelineDefaults()
	defaults1[0] = "contents:write"
	defaults1 = append(defaults1, "packages:read")

	// Get defaults again - should be unchanged
	defaults2 := profiles.GetPipelineDefaults()
	assert.Equal(t, []string{"contents:read", "pull_requests:write"}, defaults2)
}

func TestProfiles_IsLoaded(t *testing.T) {
	tests := []struct {
		name     string
		profiles Profiles
		expected bool
	}{
		{
			name: "loaded profiles",
			profiles: NewProfiles(
				NewProfileStoreOf[OrganizationProfileAttr](nil, nil),
				[]string{"contents:read"},
				"digest",
			),
			expected: true,
		},
		{
			name:     "unloaded profiles (zero value)",
			profiles: Profiles{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.profiles.IsLoaded())
		})
	}
}

func TestProfiles_Methods_Consistency(t *testing.T) {
	// Verify that all Profiles methods work together correctly
	matcher := CompositeMatcher()
	orgProfiles := NewProfileStoreOf(
		map[string]AuthorizedProfile[OrganizationProfileAttr]{
			"valid-profile": NewAuthorizedProfile(matcher, OrganizationProfileAttr{
				Repositories: []string{"acme/test"},
				Permissions:  []string{"contents:read"},
			}),
		},
		map[string]error{
			"invalid-profile": errors.New("validation failed"),
		},
	)

	pipelineDefaults := []string{"contents:read", "pull_requests:write"}
	digest := "test-digest-12345"

	profiles := NewProfiles(orgProfiles, pipelineDefaults, digest)

	// IsLoaded should be true
	assert.True(t, profiles.IsLoaded())

	// GetOrgProfile should work for valid profile
	validProfile, err := profiles.GetOrgProfile("valid-profile")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/test"}, validProfile.Attrs.Repositories)

	// GetOrgProfile should return error for invalid profile
	_, err = profiles.GetOrgProfile("invalid-profile")
	require.Error(t, err)
	var unavailErr ProfileUnavailableError
	require.ErrorAs(t, err, &unavailErr)

	// GetPipelineDefaults should return configured defaults
	assert.Equal(t, pipelineDefaults, profiles.GetPipelineDefaults())

	// Digest should be accessible (indirectly via IsLoaded check)
	assert.Equal(t, digest, profiles.digest)
}

// TestNewAuthorizedProfile verifies the constructor
func TestNewAuthorizedProfile(t *testing.T) {
	matcher := ExactMatcher("pipeline_slug", "silk-prod")
	attrs := OrganizationProfileAttr{
		Repositories: []string{"acme/silk"},
		Permissions:  []string{"contents:read"},
	}

	profile := NewAuthorizedProfile(matcher, attrs)

	// Verify attributes are stored
	assert.Equal(t, attrs.Repositories, profile.Attrs.Repositories)
	assert.Equal(t, attrs.Permissions, profile.Attrs.Permissions)

	// Verify matcher works
	claims := mapClaimLookup{"pipeline_slug": "silk-prod"}
	result := profile.Match(claims)
	assert.True(t, result.Matched)
}

// TestProfileStoreOf_Mixed verifies handling of both valid and invalid profiles
func TestProfileStoreOf_Mixed(t *testing.T) {
	matcher := ExactMatcher("pipeline_slug", "silk-prod")
	validProfiles := map[string]AuthorizedProfile[OrganizationProfileAttr]{
		"valid-profile": NewAuthorizedProfile(matcher, OrganizationProfileAttr{
			Repositories: []string{"acme/silk"},
		}),
	}
	invalidProfiles := map[string]error{
		"invalid-profile": errors.New("compilation failed"),
	}

	store := NewProfileStoreOf(validProfiles, invalidProfiles)

	// Valid profile should be accessible
	profile, err := store.Get("valid-profile")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/silk"}, profile.Attrs.Repositories)

	// Invalid profile should return ProfileUnavailableError
	_, err = store.Get("invalid-profile")
	require.Error(t, err)
	var unavailErr ProfileUnavailableError
	require.ErrorAs(t, err, &unavailErr)
	assert.Equal(t, "invalid-profile", unavailErr.Name)

	// Nonexistent profile should return ProfileNotFoundError
	_, err = store.Get("nonexistent")
	require.Error(t, err)
	var notFoundErr ProfileNotFoundError
	require.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "nonexistent", notFoundErr.Name)
}
