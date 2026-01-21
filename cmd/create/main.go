// This command is only used for local testing: it is executed by the local
// credential helper used to run commands with a locally-signed JWT against a
// local server.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	localjwt "github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	Audience         string `env:"UTIL_AUDIENCE, default=test-audience"`
	Subject          string `env:"UTIL_SUBJECT, default=test-subject"`
	Issuer           string `env:"UTIL_ISSUER, default=https://local.testing"`
	OrganizationSlug string `env:"UTIL_BUILDKITE_ORGANIZATION_SLUG, required"`
	PipelineSlug     string `env:"UTIL_BUILDKITE_PIPELINE_SLUG, required"`
}

func main() {
	cfg := Config{}
	err := envconfig.Process(context.Background(), &cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading config: %v\n", err)
		os.Exit(1)
	}

	jwksPath := ".development/keys/jwk-sig-testing-priv.json"

	jwksBytes, err := os.ReadFile(jwksPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading jwks: %v\n", err)
		os.Exit(1)
	}

	jwksKey, err := jwk.ParseKey(jwksBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading jwks: %v\n", err)
		os.Exit(1)
	}

	// Create token with standard claims
	token := jwt.New()
	_ = token.Set(jwt.AudienceKey, []string{cfg.Audience})
	_ = token.Set(jwt.SubjectKey, cfg.Subject)
	_ = token.Set(jwt.IssuerKey, cfg.Issuer)

	// Add timing claims
	token = validity(token)

	// Add Buildkite claims using SetOnToken
	claims := localjwt.BuildkiteClaims{
		OrganizationSlug: cfg.OrganizationSlug,
		PipelineSlug:     cfg.PipelineSlug,
		PipelineID:       cfg.PipelineSlug + "UUID",
		BuildNumber:      123,
		BuildBranch:      "main",
		BuildCommit:      "abc123",
		StepKey:          "step1",
		JobID:            "job1",
		AgentID:          "agent1",
	}
	if err := claims.SetOnToken(token); err != nil {
		fmt.Fprintf(os.Stderr, "error setting Buildkite claims: %v\n", err)
		os.Exit(1)
	}

	tokenStr, err := createJWT(jwksKey, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating JWT: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s", tokenStr)
}

func createJWT(key jwk.Key, token jwt.Token) (string, error) {
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

func validity(token jwt.Token) jwt.Token {
	now := time.Now().UTC()

	_ = token.Set(jwt.IssuedAtKey, now)
	_ = token.Set(jwt.NotBeforeKey, now.Add(-1*time.Minute))
	_ = token.Set(jwt.ExpirationKey, now.Add(1*time.Minute))

	return token
}
