package profile

import (
	"context"
	"fmt"
	"strings"
)

// GitHubClient defines the interface needed for fetching profile content.
type GitHubClient interface {
	GetFileContent(ctx context.Context, owner, repo, path string) (string, error)
}

// retrieve fetches profile content from GitHub using the GitHub client.
func retrieve(ctx context.Context, gh GitHubClient, orgProfileLocation string) (string, error) {
	// get the profile
	owner, repo, path, err := decomposePath(orgProfileLocation)
	if err != nil {
		return "", err
	}

	profile, err := gh.GetFileContent(ctx, owner, repo, path)
	if err != nil {
		return "", fmt.Errorf("organization profile load failed from %s: %w", orgProfileLocation, err)
	}

	return profile, nil
}

// ValidateLocation reports whether a profile location is well formed, without
// contacting GitHub. Startup blocks until the profile at this location loads,
// so a location that can never resolve has to be rejected up front: otherwise a
// typo is indistinguishable from an outage and retries forever.
func ValidateLocation(profileLocation string) error {
	_, _, _, err := decomposePath(profileLocation)
	return err
}

// decomposePath splits the profile location into owner, repo, and path components.
// Expects format: "owner:repo:path_seg1/path_seg2/..."
// Example: "cultureamp:chinmina:docs/profile.yaml"
//
// Every component is required: an empty one produces a request GitHub can only
// reject, so it is a malformed location rather than a missing file.
func decomposePath(profileLocation string) (string, string, string, error) {
	location := strings.SplitN(profileLocation, ":", 3)

	if len(location) != 3 {
		return "", "", "", fmt.Errorf("invalid profile location format %q: expected owner:repo:path", profileLocation)
	}

	orgName, repoName, filePath := location[0], location[1], location[2]

	if orgName == "" || repoName == "" || filePath == "" {
		return "", "", "", fmt.Errorf("invalid profile location format %q: owner, repo and path are all required", profileLocation)
	}

	return orgName, repoName, filePath, nil
}
