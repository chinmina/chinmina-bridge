package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-github/v61/github"
	"github.com/rs/zerolog/log"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type Client struct {
	client         *github.Client
	installationID int64
}

type ClientConfig struct {
	transportFactory func(context.Context, config.GithubConfig, http.RoundTripper) (http.RoundTripper, error)
}

type ClientOption func(*ClientConfig)

func WithAppTransport(clientConfig *ClientConfig) {
	clientConfig.transportFactory = func(ctx context.Context, cfg config.GithubConfig, wrapped http.RoundTripper) (http.RoundTripper, error) {
		return createAppTransport(ctx, cfg, wrapped)
	}
}

func WithTokenTransport(clientConfig *ClientConfig) {
	clientConfig.transportFactory = func(ctx context.Context, cfg config.GithubConfig, wrapped http.RoundTripper) (http.RoundTripper, error) {
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
	authTransport, err := clientConfig.transportFactory(ctx, cfg, http.DefaultTransport)
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
	if cfg.ApiURL != "" {
		apiURL := cfg.ApiURL
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

func (c Client) CreateAccessToken(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
	repoNames := []string{}

	for _, repoURL := range repositoryURLs {
		u, err := url.Parse(repoURL)
		if err != nil {
			return "", time.Time{}, err
		}

		_, repoName := RepoForURL(*u)
		repoNames = append(repoNames, repoName)
	}

	tokenPermissions := ScopesToPermissions(scopes)

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

func ScopesToPermissions(scopes []string) *github.InstallationPermissions {
	validPermissionActions := []string{"read", "write"}

	permissions := &github.InstallationPermissions{}
	permissionsValue := reflect.ValueOf(permissions).Elem()

	for _, scope := range scopes {
		parts := strings.Split(scope, ":")
		if len(parts) != 2 {
			log.Warn().
				Str("scope", scope).
				Msg("malformed scope detected, skipping permission. Ensure that the permissions follows the convention of <aspect>:<action>")
			continue
		}

		// Capitalise the key so it matches the field name in the struct
		c := cases.Title(language.English)
		key := c.String(parts[0])
		value := parts[1]
		field := permissionsValue.FieldByName(key)

		isValidAspect := true
		isValidAction := true
		// Check if the scope includes a field in the InstallationPermissions struct
		if !field.IsValid() {
			isValidAspect = false
			log.Warn().
				Str("field", field.String()).
				Msg("invalid permission aspect detected, skipping permission. Ensure that you use aspects as defined here: https://pkg.go.dev/github.com/google/go-github/v61@v61.0.0/github#InstallationPermissions")
		}

		// Check if the scope includes one of the valid permission actions
		if !contains(validPermissionActions, value) {
			isValidAction = false
			log.Warn().
				Str("permission", value).
				Msg("invalid permission action detected, skipping permission. Ensure that your action is one of the following: [read, write]")
		}

		// If both are valid the scope is valid, so set this permission
		if isValidAspect && isValidAction {
			field.Set(reflect.ValueOf(github.String(value)))
		}
	}

	return permissions
}

func contains(slice []string, item string) bool {
	for _, element := range slice {
		if element == item {
			return true
		}
	}
	return false
}
