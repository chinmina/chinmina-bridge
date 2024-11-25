package buildkite

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/buildkite/go-buildkite/v3/buildkite"
	"github.com/chinmina/chinmina-bridge/internal/config"
)

type PipelineLookup struct {
	token  string
	apiURL *url.URL
}

func New(cfg config.BuildkiteConfig) (p PipelineLookup, err error) {
	if cfg.Token == "" {
		err = errors.New("token must be configured for Buildkite API access")
		return
	}
	p.token = cfg.Token

	if cfg.ApiURL != "" {
		u, perr := url.Parse(cfg.ApiURL)
		if perr != nil {
			err = fmt.Errorf("could not parse Buildkite API URL: %w", perr)
			return
		}
		p.apiURL = u
	}

	return
}

func (p PipelineLookup) RepositoryLookup(ctx context.Context, organizationSlug, pipelineSlug string) (string, error) {
	client := p.createClient(ctx)
	pipeline, _, err := client.Pipelines.Get(organizationSlug, pipelineSlug)
	if err != nil {
		return "", fmt.Errorf("failed to get pipeline called %s/%s: %w", organizationSlug, pipelineSlug, err)

	}

	repo := pipeline.Repository
	if repo == nil {
		return "", fmt.Errorf("no configured repository for pipeline %s/%s", organizationSlug, pipelineSlug)
	}

	return *repo, nil
}

// createClient creates a new Buildkite API client. A client is required for
// every invocation, so the current context can be included in the request.
// Without this, HTTP client traces are not attached to their parent request.
func (p PipelineLookup) createClient(ctx context.Context) *buildkite.Client {
	def := http.DefaultTransport

	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		req = req.WithContext(ctx)
		return def.RoundTrip(req)
	})

	transport := buildkite.TokenAuthTransport{
		APIToken:  p.token,
		Transport: rt,
	}

	client := buildkite.NewClient(
		transport.Client(),
	)

	if p.apiURL != nil {
		transport.APIHost = p.apiURL.Host
		client.BaseURL = p.apiURL
	}

	return client
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
