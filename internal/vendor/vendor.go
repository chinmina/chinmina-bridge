package vendor

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/profile"
)

type ProfileTokenVendor func(ctx context.Context, ref profile.ProfileRef, repo string) (*ProfileToken, error)

// Given a pipeline, return the https version of the repository URL
type RepositoryLookup func(ctx context.Context, organizationSlug, pipelineSlug string) (string, error)

// Vend a token for the given repository URL. The URL must be a https URL to a
// GitHub repository that the vendor has permissions to access.
type TokenVendor func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error)

type ProfileToken struct {
	OrganizationSlug       string    `json:"organizationSlug"`
	Profile                string    `json:"profile"`
	RequestedRepositoryURL string    `json:"repositoryUrl"`
	Repositories           []string  `json:"repositories"`
	Permissions            []string  `json:"permissions"`
	Token                  string    `json:"token"`
	Expiry                 time.Time `json:"expiry"`
}

func (t ProfileToken) URL() (*url.URL, error) {
	url, err := url.Parse(t.RequestedRepositoryURL)
	if err != nil {
		return nil, err
	}

	if !url.IsAbs() {
		return nil, fmt.Errorf("repository URL must be absolute: %s", t.RequestedRepositoryURL)
	}

	return url, nil
}

func (t ProfileToken) ExpiryUnix() string {
	return strconv.FormatInt(t.Expiry.UTC().Unix(), 10)
}

var sshUrl = regexp.MustCompile(`^git@github\.com:([^/].+)$`)

func TranslateSSHToHTTPS(url string) string {
	groups := sshUrl.FindStringSubmatch(url)
	if groups == nil {
		return url
	}

	return fmt.Sprintf("https://github.com/%s", groups[1])
}
