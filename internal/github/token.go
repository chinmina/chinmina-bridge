package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-github/v61/github"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

type Client struct {
	client         *github.Client
	installationID int64
}

func New(ctx context.Context, cfg config.GithubConfig) (Client, error) {
	signer, err := createSigner(ctx, cfg)
	if err != nil {
		return Client{}, fmt.Errorf("could not create signer for GitHub transport: %w", err)
	}

	// We're calling "installation_token", which is JWT authenticated, so we use
	// the AppsTransport.
	appInstallationTransport, err := ghinstallation.NewAppsTransportWithOptions(
		http.DefaultTransport,
		cfg.ApplicationID,
		ghinstallation.WithSigner(signer),
	)
	if err != nil {
		return Client{}, fmt.Errorf("could not create GitHub transport: %w", err)
	}

	// Create a client for use with the application credentials. This client
	// will be used concurrently.
	client := github.NewClient(
		&http.Client{
			Transport: appInstallationTransport,
		},
	)

	// for testing use
	if cfg.ApiURL != "" {
		apiURL := cfg.ApiURL
		if !strings.HasSuffix(apiURL, "/") {
			apiURL += "/"
		}

		appInstallationTransport.BaseURL = cfg.ApiURL
		u, _ := url.Parse(apiURL)
		client.BaseURL = u
	}

	return Client{
		client,
		cfg.InstallationID,
	}, nil
}

func (c *Client) CreateAccessToken(ctx context.Context, repositoryURL string) (string, time.Time, error) {
	u, err := url.Parse(repositoryURL)
	if err != nil {
		return "", time.Time{}, err
	}

	_, repoName := RepoForURL(*u)

	tok, r, err := c.client.Apps.CreateInstallationToken(ctx, c.installationID,
		&github.InstallationTokenOptions{
			Repositories: []string{repoName},
			Permissions: &github.InstallationPermissions{
				Contents: github.String("read"),
			},
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

func (c *Client) NewWithTokenAuth(ctx context.Context, owner string, repo string) (*github.Client, error) {
	token, _, err := c.CreateAccessToken(ctx, "https://github.com/"+owner+"/"+repo)
	if err != nil {
		log.Info().Err(err).Str("repo", repo).Str("owner", owner).Msg("could not create token to load organization profile")
		return &github.Client{}, err
	}

	// Configure the http client with the token
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)

	// Set up a client to use the token. There's a bit of a dance here to ensure this remains testable
	// using our existing mocks
	client := github.NewClient(tc)
	return client, nil
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
