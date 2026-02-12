package github

import (
	"net/http"

	"github.com/jferrl/go-githubauth/v2"
	"golang.org/x/oauth2"
)

// InstallationTokenSourceOption configures the installation token source.
type InstallationTokenSourceOption func(*installationTokenSourceOptions)

type installationTokenSourceOptions struct {
	httpClient    *http.Client
	enterpriseURL string
}

// WithHTTPClient sets the HTTP client for GitHub API calls.
func WithHTTPClient(client *http.Client) InstallationTokenSourceOption {
	return func(o *installationTokenSourceOptions) {
		o.httpClient = client
	}
}

// WithEnterpriseURL sets the GitHub Enterprise Server URL.
func WithEnterpriseURL(url string) InstallationTokenSourceOption {
	return func(o *installationTokenSourceOptions) {
		o.enterpriseURL = url
	}
}

// NewInstallationTokenSource creates an oauth2.TokenSource that produces GitHub App
// installation tokens. It uses the provided app token source to authenticate as the
// app, then exchanges for installation-specific tokens via the GitHub API.
//
// The appTokenSource should be created via NewAppTokenSource() which handles caching.
// The returned TokenSource handles its own caching via go-githubauth.
func NewInstallationTokenSource(installationID int64, appTokenSource oauth2.TokenSource, opts ...InstallationTokenSourceOption) oauth2.TokenSource {
	options := &installationTokenSourceOptions{}
	for _, opt := range opts {
		opt(options)
	}

	// Build options for go-githubauth
	var installOpts []githubauth.InstallationTokenSourceOpt

	if options.httpClient != nil {
		installOpts = append(installOpts, githubauth.WithHTTPClient(options.httpClient))
	}

	if options.enterpriseURL != "" {
		installOpts = append(installOpts, githubauth.WithEnterpriseURL(options.enterpriseURL))
	}

	// Create the installation token source using go-githubauth
	// go-githubauth internally wraps this in ReuseTokenSource
	return githubauth.NewInstallationTokenSource(
		installationID,
		appTokenSource,
		installOpts...,
	)
}
