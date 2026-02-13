package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	appconfig "github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/google/go-github/v82/github"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

type Client struct {
	client         *github.Client
	installationID int64
}

func New(ctx context.Context, cfg appconfig.GithubConfig, config ...ClientOption) (Client, error) {
	clientConfig := &ClientConfig{}

	// default to App transport, as the primary use case is minting installation
	// tokens
	WithAppTransport(clientConfig)

	for _, c := range config {
		c(clientConfig)
	}

	authTransport, err := clientConfig.TransportFactory(ctx, cfg, http.DefaultTransport)
	if err != nil {
		return Client{}, fmt.Errorf("could not create GitHub transport: %w", err)
	}

	// Create a client with the configured credentials. This client will be used
	// concurrently.
	client := github.NewClient(
		&http.Client{
			Transport: authTransport,
		},
	)

	if cfg.APIURL != "" {
		u, err := url.Parse(normalizeAPIURL(cfg.APIURL))
		if err != nil {
			return Client{}, fmt.Errorf("parse GitHub API URL %q: %w", cfg.APIURL, err)
		}
		client.BaseURL = u
	}

	return Client{
		client,
		cfg.InstallationID,
	}, nil
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

type ClientConfig struct {
	TransportFactory func(context.Context, appconfig.GithubConfig, http.RoundTripper) (http.RoundTripper, error)
}

type ClientOption func(*ClientConfig)

func WithAppTransport(clientConfig *ClientConfig) {
	clientConfig.TransportFactory = createAppTransport
}

func WithTokenTransport(clientConfig *ClientConfig) {
	clientConfig.TransportFactory = func(ctx context.Context, cfg appconfig.GithubConfig, wrapped http.RoundTripper) (http.RoundTripper, error) {
		signingKey, err := createSigningKey(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("create signing key: %w", err)
		}

		appTokenSource := NewAppTokenSource(signingKey, strconv.FormatInt(cfg.ApplicationID, 10))

		installOpts := []InstallationTokenSourceOption{
			WithHTTPClient(&http.Client{Transport: wrapped}),
		}
		if cfg.APIURL != "" {
			installOpts = append(installOpts, WithEnterpriseURL(normalizeAPIURL(cfg.APIURL)))
		}

		tokenSource := NewInstallationTokenSource(
			cfg.InstallationID,
			appTokenSource,
			installOpts...,
		)

		transport := &oauth2.Transport{
			Source: tokenSource,
			Base:   wrapped,
		}
		return transport, nil
	}
}

func createAppTransport(ctx context.Context, cfg appconfig.GithubConfig, wrapped http.RoundTripper) (http.RoundTripper, error) {
	signingKey, err := createSigningKey(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("could not create signing key for GitHub transport: %w", err)
	}

	// Create App JWT token source for authenticating as the GitHub App
	// NewAppTokenSource wraps in ReuseTokenSource internally
	appTokenSource := NewAppTokenSource(signingKey, strconv.FormatInt(cfg.ApplicationID, 10))

	transport := &oauth2.Transport{
		Source: appTokenSource,
		Base:   wrapped,
	}
	return transport, nil
}

// createSigningKey returns the appropriate signing key based on configuration.
// Returns either a jwk.Key for PEM-based signing or a kmsSigningKey for AWS
// KMS-based signing.
func createSigningKey(ctx context.Context, cfg appconfig.GithubConfig) (any, error) {
	if cfg.PrivateKeyARN != "" {
		return createKMSSigningKey(ctx, cfg.PrivateKeyARN)
	}

	if cfg.PrivateKey != "" {
		return parsePrivateKeyPEM(cfg.PrivateKey)
	}

	return nil, fmt.Errorf("no private key configuration specified")
}

// createKMSSigningKey creates a KMS signing key using the AWS SDK.
func createKMSSigningKey(ctx context.Context, arn string) (kmsSigningKey, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return kmsSigningKey{}, fmt.Errorf("load AWS config: %w", err)
	}

	client := kms.NewFromConfig(awsCfg)

	return kmsSigningKey{
		ctx:    ctx,
		client: client,
		arn:    arn,
	}, nil
}

// normalizeAPIURL ensures the API URL has a trailing slash as required by
// GitHub client libraries.
func normalizeAPIURL(apiURL string) string {
	if !strings.HasSuffix(apiURL, "/") {
		return apiURL + "/"
	}
	return apiURL
}

// parsePrivateKeyPEM parses a PEM-encoded RSA private key using jwx.
// Handles both PKCS1 and PKCS8 formats automatically.
func parsePrivateKeyPEM(pemKey string) (jwk.Key, error) {
	key, err := jwk.ParseKey([]byte(pemKey), jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("parse PEM key: %w", err)
	}
	return key, nil
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
