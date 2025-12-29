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

// decomposePath splits the profile location into owner, repo, and path components.
// Expects format: "owner:repo:path_seg1/path_seg2/..."
// Example: "cultureamp:chinmina:docs/profile.yaml"
func decomposePath(profileLocation string) (string, string, string, error) {
	location := strings.SplitN(profileLocation, ":", 3)

	if len(location) != 3 {
		return "", "", "", fmt.Errorf("invalid profile location format %q: expected owner:repo:path", profileLocation)
	}

	orgName, repoName, filePath := location[0], location[1], location[2]

	return orgName, repoName, filePath, nil
}
