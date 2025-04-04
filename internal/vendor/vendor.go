package vendor

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/jwt"

	"github.com/rs/zerolog/log"
)

type ProfileTokenVendor func(ctx context.Context, claims jwt.BuildkiteClaims, repo string, profile string) (*ProfileToken, error)

// Given a pipeline, return the https version of the repository URL
type RepositoryLookup func(ctx context.Context, organizationSlug, pipelineSlug string) (string, error)

// Vend a token for the given repository URL. The URL must be a https URL to a
// GitHub repository that the vendor has permissions to access.
type TokenVendor func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error)

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

// New creates a vendor that will supply a token for the pipeline. The
// (optional) requestedRepoURL is the URL of the repository that the token is
// being asked for. If supplied, it must match the repository URL of the
// pipeline.
func New(
	repoLookup RepositoryLookup,
	tokenVendor TokenVendor,
	orgProfile *github.ProfileStore,
) ProfileTokenVendor {
	return func(ctx context.Context, claims jwt.BuildkiteClaims, requestedRepoURL string, profile string) (*ProfileToken, error) {
		var token string
		var expiry time.Time

		// Vend a non-default profile.
		// This is not the standard use case at the time of development, but
		// should be moving forward.
		if profile != "default" {
			// use the ProfileStore to get the requested provile and validate it
			profileConf, err := orgProfile.GetProfileFromStore(profile)
			if err != nil {
				log.Warn().Str("pipeline", claims.PipelineSlug).Str("profile", profile).Msg("requested profile was not found")
				return nil, fmt.Errorf("could not find profile %s: %w", profile, err)
			}
			// Check that the requested repository is in the profile
			repo, err := url.Parse(requestedRepoURL)
			if err != nil {
				return nil, fmt.Errorf("could not parse requested repo URL %s: %w", requestedRepoURL, err)
			}
			_, repository := github.RepoForURL(*repo)
			if profileConf.HasRepository(repository) {
				// use the github api to vend a token for the repository
				token, expiry, err = tokenVendor(ctx, profileConf.Repositories, profileConf.Repositories)
				if err != nil {
					return nil, fmt.Errorf("could not issue token for repository %s: %w", requestedRepoURL, err)
				}
			}
			log.Info().
				Str("organization", claims.OrganizationSlug).
				Str("profile", profile).
				Str("repo", requestedRepoURL).
				Msg("token issued")

			return &ProfileToken{
				OrganizationSlug:       claims.OrganizationSlug,
				RequestedRepositoryURL: requestedRepoURL,
				Repositories:           profileConf.Repositories,
				Permissions:            profileConf.Permissions,
				Profile:                profile,
				Token:                  token,
				Expiry:                 expiry,
			}, nil
		} else {
			// Vend the default profile. This is the behaviour that we expect
			// due to the current state of the buildkite plugin. This will
			// eventually change, but we need to perform the song and dance
			// around determining the repository in this case.

			// use buildkite api to find the repository for the pipeline
			pipelineRepoURL, err := repoLookup(ctx, claims.OrganizationSlug, claims.PipelineSlug)
			if err != nil {
				return nil, fmt.Errorf("could not find repository for pipeline %s: %w", claims.PipelineSlug, err)
			}

			// allow HTTPS credentials if the pipeline is configured for an equivalent SSH URL
			pipelineRepoURL = TranslateSSHToHTTPS(pipelineRepoURL)

			if requestedRepoURL != "" && pipelineRepoURL != requestedRepoURL {
				// git is asking for a different repo than we can handle: return nil
				// to indicate that the handler should return a successful (but
				// empty) response.
				log.Info().Msgf("no token issued: repo mismatch. pipeline(%s) != requested(%s)\n", pipelineRepoURL, requestedRepoURL)
				return nil, nil
			}
			// use the github api to vend a token for the repository
			token, expiry, err = tokenVendor(ctx, []string{pipelineRepoURL}, []string{"contents:read"})
			if err != nil {
				return nil, fmt.Errorf("could not issue token for repository %s: %w", pipelineRepoURL, err)
			}
			log.Info().
				Str("organization", claims.OrganizationSlug).
				Str("profile", profile).
				Str("repo", requestedRepoURL).
				Msg("token issued")

			return &ProfileToken{
				OrganizationSlug:       claims.OrganizationSlug,
				RequestedRepositoryURL: pipelineRepoURL,
				Repositories:           []string{pipelineRepoURL},
				Permissions:            []string{"contents:read"},
				Profile:                profile,
				Token:                  token,
				Expiry:                 expiry,
			}, nil
		}

	}
}

var sshUrl = regexp.MustCompile(`^git@github\.com:([^/].+)$`)

func TranslateSSHToHTTPS(url string) string {
	groups := sshUrl.FindStringSubmatch(url)
	if groups == nil {
		return url
	}

	return fmt.Sprintf("https://github.com/%s", groups[1])
}
