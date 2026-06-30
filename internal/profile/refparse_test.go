package profile

import (
	"fmt"
	"strings"
)

// ParseProfileRef parses a URN format string back to a ProfileRef.
//
// This is a TEST-ONLY helper: it lives in a _test.go file so it is never
// compiled into the production binary and cannot become a load-bearing part of
// the package's public API. Its sole purpose is to verify that ProfileRef.String()
// round-trips. Production code never reconstructs a ProfileRef from its URN; refs
// are always built from request inputs via NewProfileRef / the ProfileRefBuilder.
//
// Supports both new format (with pipeline-slug and /profile/ segment) and old
// format (backward compatibility).
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
		// Optionally scoped: organization/org-name/profile/profile-name/repository/repo-name
		profileName := parts[2]

		ref := ProfileRef{
			Organization: org,
			Type:         ProfileTypeOrg,
			Name:         profileName,
		}

		if len(parts) == 3 {
			return ref, nil
		}

		if len(parts) == 5 && parts[3] == "repository" && parts[4] != "" {
			ref.ScopedRepository = parts[4]
			return ref, nil
		}

		return ProfileRef{}, fmt.Errorf("invalid profile ref format: malformed org profile suffix in '%s'", s)
	}

	return ProfileRef{}, fmt.Errorf("invalid profile ref format: could not determine profile type from '%s'", s)
}
