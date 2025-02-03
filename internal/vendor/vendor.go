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

type PipelineTokenVendor func(ctx context.Context, claims jwt.BuildkiteClaims, repo string) (*PipelineRepositoryToken, error)

// Given a pipeline, return the https version of the repository URL
type RepositoryLookup func(ctx context.Context, organizationSlug, pipelineSlug string) (string, error)

// Vend a token for the given repository URL. The URL must be a https URL to a
// GitHub repository that the vendor has permissions to access.
type TokenVendor func(ctx context.Context, repositoryURL string) (string, time.Time, error)

// Retrieve an organization profile from the current state of the GitHub client
type ConfigurationStore func(ctx context.Context, profileChan chan (*github.ProfileConfig)) (*github.ProfileConfig, error)

type PipelineRepositoryToken struct {
	OrganizationSlug string    `json:"organizationSlug"`
	PipelineSlug     string    `json:"pipelineSlug"`
	RepositoryURL    string    `json:"repositoryUrl"`
	Token            string    `json:"token"`
	Expiry           time.Time `json:"expiry"`
}

func (t PipelineRepositoryToken) URL() (*url.URL, error) {
	url, err := url.Parse(t.RepositoryURL)
	if err != nil {
		return nil, err
	}

	if !url.IsAbs() {
		return nil, fmt.Errorf("repository URL must be absolute: %s", t.RepositoryURL)
	}

	return url, nil
}

func (t PipelineRepositoryToken) ExpiryUnix() string {
	return strconv.FormatInt(t.Expiry.UTC().Unix(), 10)
}

// New creates a vendor that will supply a token for the pipeline. The
// (optional) requestedRepoURL is the URL of the repository that the token is
// being asked for. If supplied, it must match the repository URL of the
// pipeline.
func New(
	repoLookup RepositoryLookup,
	tokenVendor TokenVendor,
	orgProfile ConfigurationStore,
) PipelineTokenVendor {
	return func(ctx context.Context, claims jwt.BuildkiteClaims, requestedRepoURL string) (*PipelineRepositoryToken, error) {

		// Load the configuration from the GitHub client
		// TODO: actually handle the profile
		// 	_, err = orgProfile(ctx, profileChan)
		//	if err != nil {
		//		log.Info().Err(err).Msg("organization profile not found, continuing")
		//	}
		//

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
		token, expiry, err := tokenVendor(ctx, pipelineRepoURL)
		if err != nil {
			return nil, fmt.Errorf("could not issue token for repository %s: %w", pipelineRepoURL, err)
		}

		log.Info().
			Str("organization", claims.OrganizationSlug).
			Str("pipeline", claims.PipelineSlug).
			Str("repo", requestedRepoURL).
			Msg("token issued")

		return &PipelineRepositoryToken{
			OrganizationSlug: claims.OrganizationSlug,
			PipelineSlug:     claims.PipelineSlug,
			RepositoryURL:    pipelineRepoURL,
			Token:            token,
			Expiry:           expiry,
		}, nil
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
