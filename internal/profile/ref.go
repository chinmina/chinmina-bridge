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

const (
	ProfileNameDefault = "default" // Default profile name
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
	PipelineSlug string      // Only set for ProfileTypeRepo
}

// NewProfileRef constructs a ProfileRef from Buildkite claims, an expected profile type, and a profile string.
// If profileStr is empty and expectedType is ProfileTypeRepo, it defaults to "default".
// If profileStr is empty and expectedType is ProfileTypeOrg, it returns an error.
// If profileStr contains a colon, it must be in the format "type:name" and the type must match expectedType.
// If profileStr does not contain a colon, it uses expectedType with profileStr as the name.
func NewProfileRef(claims jwt.BuildkiteClaims, expectedType ProfileType, profileStr string) (ProfileRef, error) {
	profileType, profileName, err := resolveProfileTypeAndName(expectedType, profileStr)
	if err != nil {
		return ProfileRef{}, err
	}

	// Build the reference
	ref := ProfileRef{
		Organization: claims.OrganizationSlug,
		Type:         profileType,
		Name:         profileName,
	}

	// Only set PipelineID and PipelineSlug for repo profiles
	if profileType == ProfileTypeRepo {
		ref.PipelineID = claims.PipelineID
		ref.PipelineSlug = claims.PipelineSlug
	}

	return ref, nil
}

// resolveProfileTypeAndName determines the profile type and name from the input parameters.
// Returns the resolved type, name, and any error encountered during resolution.
func resolveProfileTypeAndName(expectedType ProfileType, profileStr string) (ProfileType, string, error) {
	if profileStr == "" {
		return handleEmptyProfileString(expectedType)
	}

	profileTypeStr, name, hasTypePrefix := strings.Cut(profileStr, ":")
	if !hasTypePrefix {
		return expectedType, profileStr, nil
	}

	if profileTypeStr == "" || name == "" {
		return 0, "", fmt.Errorf("invalid profile format: expected 'type:name', got '%s'", profileStr)
	}

	parsedType, err := parseProfileType(profileTypeStr)
	if err != nil {
		return 0, "", err
	}

	if parsedType != expectedType {
		return 0, "", fmt.Errorf("profile type mismatch: expected '%s' but got '%s'", expectedType.String(), parsedType.String())
	}

	return parsedType, name, nil
}

// handleEmptyProfileString handles the case where no profile string is provided.
// Repo profiles default to "default", org profiles return an error.
func handleEmptyProfileString(expectedType ProfileType) (ProfileType, string, error) {
	if expectedType == ProfileTypeOrg {
		return 0, "", fmt.Errorf("organization profiles have no default: profile name required")
	}
	return expectedType, ProfileNameDefault, nil
}

// parseProfileType converts a string to a ProfileType.
func parseProfileType(typeStr string) (ProfileType, error) {
	switch typeStr {
	case "repo":
		return ProfileTypeRepo, nil
	case "org":
		return ProfileTypeOrg, nil
	default:
		return 0, fmt.Errorf("invalid profile type '%s': expected 'repo' or 'org'", typeStr)
	}
}

// String returns the canonical URN format for this ProfileRef.
// Format for repo profiles: profile://organization/org-name/pipeline/pipeline-id/pipeline-slug/profile/profile-name
// Format for org profiles: profile://organization/org-name/profile/profile-name
func (pr ProfileRef) String() string {
	switch pr.Type {
	case ProfileTypeRepo:
		return fmt.Sprintf("profile://organization/%s/pipeline/%s/%s/profile/%s", pr.Organization, pr.PipelineID, pr.PipelineSlug, pr.Name)
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
// Supports both new format (with pipeline-slug and /profile/ segment) and old format (backward compatibility).
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
	if parts[1] == "pipeline" {
		// Repo profile - detect format based on structure
		if len(parts) >= 6 && parts[4] == "profile" {
			// New format: organization/org-name/pipeline/pipeline-id/pipeline-slug/profile/profile-name
			pipelineID := parts[2]
			pipelineSlug := parts[3]
			profileName := parts[5]

			return ProfileRef{
				Organization: org,
				Type:         ProfileTypeRepo,
				Name:         profileName,
				PipelineID:   pipelineID,
				PipelineSlug: pipelineSlug,
			}, nil
		} else if len(parts) >= 4 {
			// Old format (backward compatibility): organization/org-name/pipeline/pipeline-id/profile-name
			pipelineID := parts[2]
			profileName := parts[3]

			return ProfileRef{
				Organization: org,
				Type:         ProfileTypeRepo,
				Name:         profileName,
				PipelineID:   pipelineID,
				PipelineSlug: "", // Not available in old format
			}, nil
		}
	} else if parts[1] == "profile" {
		// Org profile: organization/org-name/profile/profile-name
		profileName := parts[2]

		return ProfileRef{
			Organization: org,
			Type:         ProfileTypeOrg,
			Name:         profileName,
			PipelineID:   "",
			PipelineSlug: "",
		}, nil
	}

	return ProfileRef{}, fmt.Errorf("invalid profile ref format: could not determine profile type from '%s'", s)
}
