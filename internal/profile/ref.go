package profile

import (
	"fmt"
	"strings"

	"github.com/chinmina/chinmina-bridge/internal/jwt"
)

// ProfileType identifies the scope of a profile.
type ProfileType int

const (
	ProfileTypeRepo ProfileType = iota // Pipeline-scoped profiles
	ProfileTypeOrg                     // Organization-scoped profiles
)

// String returns the string representation of the ProfileType.
func (pt ProfileType) String() string {
	switch pt {
	case ProfileTypeRepo:
		return "repo"
	case ProfileTypeOrg:
		return "org"
	default:
		return "unknown"
	}
}

// ProfileRef uniquely identifies a profile request.
type ProfileRef struct {
	Organization string      // Buildkite organization slug
	Type         ProfileType // repo or org
	Name         string      // Profile name (e.g., "default", "write-packages")
	PipelineID   string      // Only set for ProfileTypeRepo
}

// NewProfileRef constructs a ProfileRef from Buildkite claims and a profile string.
// If profileStr is empty, it defaults to "repo:default".
// The profile string must be in the format "type:name" where type is "repo" or "org".
func NewProfileRef(claims jwt.BuildkiteClaims, profileStr string) (ProfileRef, error) {
	// Default to repo:default if no profile specified
	if profileStr == "" {
		profileStr = "repo:default"
	}

	// Split on colon to extract type and name
	profileTypeStr, profileName, found := strings.Cut(profileStr, ":")
	if !found || profileTypeStr == "" || profileName == "" {
		return ProfileRef{}, fmt.Errorf("invalid profile format: expected 'type:name', got '%s'", profileStr)
	}

	// Determine profile type
	var profileType ProfileType
	switch profileTypeStr {
	case "repo":
		profileType = ProfileTypeRepo
	case "org":
		profileType = ProfileTypeOrg
	default:
		return ProfileRef{}, fmt.Errorf("invalid profile type '%s': expected 'repo' or 'org'", profileTypeStr)
	}

	// Build the reference
	ref := ProfileRef{
		Organization: claims.OrganizationSlug,
		Type:         profileType,
		Name:         profileName,
	}

	// Only set PipelineID for repo profiles
	if profileType == ProfileTypeRepo {
		ref.PipelineID = claims.PipelineID
	}

	return ref, nil
}

// String returns the canonical URN format for this ProfileRef.
// Format for repo profiles: profile://organization/org-name/pipeline/pipeline-id/profile-name
// Format for org profiles: profile://organization/org-name/profile/profile-name
func (pr ProfileRef) String() string {
	switch pr.Type {
	case ProfileTypeRepo:
		return fmt.Sprintf("profile://organization/%s/pipeline/%s/%s", pr.Organization, pr.PipelineID, pr.Name)
	case ProfileTypeOrg:
		return fmt.Sprintf("profile://organization/%s/profile/%s", pr.Organization, pr.Name)
	default:
		return "profile://unknown"
	}
}

// ShortString returns the short format for this ProfileRef.
// Format: "type:name" (e.g., "repo:default", "org:profile-name")
func (pr ProfileRef) ShortString() string {
	return fmt.Sprintf("%s:%s", pr.Type.String(), pr.Name)
}

// ParseProfileRef parses a URN format string back to a ProfileRef.
// This is primarily useful for testing roundtrips.
func ParseProfileRef(s string) (ProfileRef, error) {
	// Both repo and org formats use the same prefix
	rest, found := strings.CutPrefix(s, "profile://organization/")
	if !found {
		return ProfileRef{}, fmt.Errorf("invalid profile ref format: expected to start with 'profile://organization/'")
	}

	// Split by "/" to extract components
	parts := strings.Split(rest, "/")
	if len(parts) < 3 {
		return ProfileRef{}, fmt.Errorf("invalid profile ref format: expected at least 3 components after organization/")
	}

	org := parts[0]

	// Check if it's a repo or org profile
	if len(parts) >= 4 && parts[1] == "pipeline" {
		// Repo profile: organization/org-name/pipeline/pipeline-id/profile-name
		pipelineID := parts[2]
		profileName := parts[3]

		return ProfileRef{
			Organization: org,
			Type:         ProfileTypeRepo,
			Name:         profileName,
			PipelineID:   pipelineID,
		}, nil
	} else if parts[1] == "profile" {
		// Org profile: organization/org-name/profile/profile-name
		profileName := parts[2]

		return ProfileRef{
			Organization: org,
			Type:         ProfileTypeOrg,
			Name:         profileName,
			PipelineID:   "",
		}, nil
	}

	return ProfileRef{}, fmt.Errorf("invalid profile ref format: could not determine profile type from '%s'", s)
}
