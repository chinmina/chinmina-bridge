package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-github/v81/github"
	"github.com/rs/zerolog/log"
)

type Client struct {
	client         *github.Client
	installationID int64
}

type ClientConfig struct {
	TransportFactory func(context.Context, config.GithubConfig, http.RoundTripper) (http.RoundTripper, error)
}

type ClientOption func(*ClientConfig)

func WithAppTransport(clientConfig *ClientConfig) {
	clientConfig.TransportFactory = func(ctx context.Context, cfg config.GithubConfig, wrapped http.RoundTripper) (http.RoundTripper, error) {
		return createAppTransport(ctx, cfg, wrapped)
	}
}

func WithTokenTransport(clientConfig *ClientConfig) {
	clientConfig.TransportFactory = func(ctx context.Context, cfg config.GithubConfig, wrapped http.RoundTripper) (http.RoundTripper, error) {
		appTransport, err := createAppTransport(ctx, cfg, wrapped)
		if err != nil {
			return nil, err
		}

		transport := ghinstallation.NewFromAppsTransport(appTransport, cfg.InstallationID)
		return transport, nil
	}
}

func New(ctx context.Context, cfg config.GithubConfig, config ...ClientOption) (Client, error) {
	clientConfig := &ClientConfig{}
	WithAppTransport(clientConfig)

	for _, c := range config {
		c(clientConfig)
	}

	// We're calling "installation_token", which is JWT authenticated, so we use
	// the AppsTransport.
	authTransport, err := clientConfig.TransportFactory(ctx, cfg, http.DefaultTransport)
	if err != nil {
		return Client{}, fmt.Errorf("could not create GitHub transport: %w", err)
	}

	// Create a client for use with the application credentials. This client
	// will be used concurrently.
	client := github.NewClient(
		&http.Client{
			Transport: authTransport,
		},
	)

	// for testing use
	if cfg.APIURL != "" {
		apiURL := cfg.APIURL
		if !strings.HasSuffix(apiURL, "/") {
			apiURL += "/"
		}
		u, _ := url.Parse(apiURL)
		client.BaseURL = u
	}

	return Client{
		client,
		cfg.InstallationID,
	}, nil
}

func createAppTransport(ctx context.Context, cfg config.GithubConfig, wrapped http.RoundTripper) (*ghinstallation.AppsTransport, error) {
	signer, err := createSigner(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("could not create signer for GitHub transport: %w", err)
	}

	// We're calling "installation_token", which is JWT authenticated, so we use
	// the AppsTransport.
	appInstallationTransport, err := ghinstallation.NewAppsTransportWithOptions(
		wrapped,
		cfg.ApplicationID,
		ghinstallation.WithSigner(signer),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create GitHub transport: %w", err)
	}
	return appInstallationTransport, nil
}

func (c Client) GetFileContent(ctx context.Context, owner string, repo string, path string) (string, error) {
	fileContents, directoryContents, _, err := c.client.Repositories.GetContents(ctx, owner, repo, path, nil)

	if err != nil {
		return "", err
	}

	if directoryContents != nil {
		return "", fmt.Errorf("path %s in repo %s/%s is a directory, expected a file", path, owner, repo)
	}

	if fileContents != nil {
		// success, return downloaded content
		return fileContents.GetContent()
	}

	return "", fmt.Errorf("path %s in repo %s/%s returned no content", path, owner, repo)
}

func (c Client) CreateAccessToken(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
	tokenPermissions, err := scopesToPermissions(scopes)
	if err != nil {
		return "", time.Time{}, err
	}

	tok, r, err := c.client.Apps.CreateInstallationToken(ctx, c.installationID,
		&github.InstallationTokenOptions{
			Repositories: repoNames,
			Permissions:  tokenPermissions,
		},
	)
	if err != nil {
		return "", time.Time{}, err
	}

	log.Info().Int("limit", r.Rate.Limit).Int("remaining", r.Rate.Remaining).Msg("github token API rate")

	return tok.GetToken(), tok.GetExpiresAt().Time, nil
}

func createSigner(ctx context.Context, cfg config.GithubConfig) (ghinstallation.Signer, error) {
	if cfg.PrivateKeyARN != "" {
		return NewAWSKMSSigner(ctx, cfg.PrivateKeyARN)
	}

	if cfg.PrivateKey != "" {
		key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(cfg.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("could not parse private key: %s", err)
		}

		return ghinstallation.NewRSASigner(jwt.SigningMethodRS256, key), nil
	}

	return nil, errors.New("no private key configuration specified")
}

func RepoForURL(u url.URL) (string, string) {
	if u.Hostname() != "github.com" || u.Path == "" {
		return "", ""
	}

	return RepoForPath(u.Path)
}

func RepoForPath(path string) (string, string) {
	path, _ = strings.CutSuffix(path, ".git")
	qualified, _ := strings.CutPrefix(path, "/")
	org, repo, ok := strings.Cut(qualified, "/")
	if !ok {
		return "", ""
	}

	return org, repo
}

func GetRepoNames(repositoryURLs []string) ([]string, error) {
	repoNames := []string{}

	for _, repoURL := range repositoryURLs {
		u, err := url.Parse(repoURL)
		if err != nil {
			log.Warn().
				Str("repoURL", repoURL).
				Msg("failed to parse repository URL, skipping this repository")
			continue
		}

		_, repoName := RepoForURL(*u)
		if repoName == "" {
			log.Warn().
				Str("repoURL", repoURL).
				Msg("failed to extract repo name from URL, skipping this repository")
			continue
		}

		repoNames = append(repoNames, repoName)
	}

	if len(repoNames) == 0 {
		return repoNames, errors.New("no valid repository URLs found")
	}

	return repoNames, nil
}

var getPermissionsMapper = sync.OnceValue(func() *FieldMapper[github.InstallationPermissions] {
	return MustFieldMapper[github.InstallationPermissions]()
})

var validPermissionActions = []string{"read", "write"}

// ValidateScope validates a colon-separated scope string in the format "field:action".
// It checks that the field exists in InstallationPermissions and that the action is
// one of the allowed values ("read" or "write").
// Returns an error if the scope is malformed or contains invalid field or action values.
func ValidateScope(scope string) error {
	field, action, hasAction := strings.Cut(scope, ":")
	if !hasAction {
		return fmt.Errorf("malformed scope %q: expected format \"field:action\"", scope)
	}

	mapper := getPermissionsMapper()
	if !mapper.Has(field) {
		return fmt.Errorf("invalid permission field %q", field)
	}

	if !slices.Contains(validPermissionActions, action) {
		return fmt.Errorf("invalid permission action %q: must be one of %v", action, validPermissionActions)
	}

	return nil
}

// scopesToPermissions converts validated scopes to InstallationPermissions.
// ValidateScope should be called on each scope before calling this function to
// improve error reporting. If validated, errors from this function are
// unlikely.
func scopesToPermissions(scopes []string) (*github.InstallationPermissions, error) {
	mapper := getPermissionsMapper()
	permissions, err := mapper.SetAll(scopes)
	if err != nil {
		return &github.InstallationPermissions{}, fmt.Errorf("failed to set permissions: %w", err)
	}
	return &permissions, nil
}
