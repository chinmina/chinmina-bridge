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
//
// ScopedRepository narrows an already-authorised org profile to a single
// repository. It is caller-supplied at request time and is never granted by
// the profile itself: the profile's match rules decide whether the caller
// may invoke the profile at all, and GitHub is the final enforcement
// boundary for whether a specific repository is reachable. Honouring
// caller-supplied scope without additional cross-checks is therefore safe.
// Note the blast radius: a caller-scoped profile lets any matching caller
// obtain a token for any single repository the App installation can reach,
// with that profile's permissions — there is no per-repository allow-list.
// Only applicable to ProfileTypeOrg; repo profiles are never scoped.
type ProfileRef struct {
	Organization     string      // Buildkite organization slug
	Type             ProfileType // repo or org
	Name             string      // Profile name (e.g., "default", "write-packages")
	PipelineID       string      // Only set for ProfileTypeRepo
	PipelineSlug     string      // Only set for ProfileTypeRepo
	ScopedRepository string      // Only set for caller-scoped ProfileTypeOrg requests
}

// NewProfileRef constructs a ProfileRef from Buildkite claims, an expected profile type,
// and a profile string.
// If profileStr is empty and expectedType is ProfileTypeRepo, it defaults to "default".
// If profileStr is empty and expectedType is ProfileTypeOrg, it returns an error.
// If profileStr contains a colon, it must be in the format "type:name" and the type must match expectedType.
// If profileStr does not contain a colon, it uses expectedType with profileStr as the name.
//
// The returned ref never carries a repository scope. ScopedRepository is the
// sole responsibility of the ProfileRefBuilder at the handler boundary, which
// resolves and validates caller-supplied scope (profile-type × scope-value
// rules) before assigning the field. Keeping that logic in one place avoids a
// second, unvalidated write path through this constructor.
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
// Caller-scoped org profiles append /repository/repo-name.
func (pr ProfileRef) String() string {
	switch pr.Type {
	case ProfileTypeRepo:
		return fmt.Sprintf("profile://organization/%s/pipeline/%s/%s/profile/%s", pr.Organization, pr.PipelineID, pr.PipelineSlug, pr.Name)
	case ProfileTypeOrg:
		base := fmt.Sprintf("profile://organization/%s/profile/%s", pr.Organization, pr.Name)
		if pr.ScopedRepository != "" {
			return base + "/repository/" + pr.ScopedRepository
		}
		return base
	default:
		return "profile://unknown"
	}
}

// ShortString returns the short format for this ProfileRef.
// Format: "type:name" (e.g., "repo:default", "org:profile-name").
// Caller-scoped org profiles render as "org:profile-name/repo-name".
// The "/" separator is unambiguous: repository scope values reject "/" at
// the handler boundary, and profile names cannot contain "/".
func (pr ProfileRef) ShortString() string {
	if pr.ScopedRepository != "" {
		return fmt.Sprintf("%s:%s/%s", pr.Type.String(), pr.Name, pr.ScopedRepository)
	}
	return fmt.Sprintf("%s:%s", pr.Type.String(), pr.Name)
}
