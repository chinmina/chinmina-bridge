// This command is only used for local testing: it is executed by the local
// credential helper used to run commands with a locally-signed JWT against a
// local server.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/json"
	"github.com/go-jose/go-jose/v4/jwt"

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

	jwksKey := jose.JSONWebKey{}
	err = json.Unmarshal(jwksBytes, &jwksKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading jwks: %v\n", err)
		os.Exit(1)
	}

	jwt, err := createJWT(&jwksKey, validity(jwt.Claims{
		Audience: []string{cfg.Audience},
		Subject:  cfg.Subject,
		Issuer:   cfg.Issuer,
	}), localjwt.BuildkiteClaims{
		OrganizationSlug: cfg.OrganizationSlug,
		PipelineSlug:     cfg.PipelineSlug,
		PipelineID:       cfg.PipelineSlug + "UUID",
		BuildNumber:      123,
		BuildBranch:      "main",
		BuildCommit:      "abc123",
		StepKey:          "step1",
		JobID:            "job1",
		AgentID:          "agent1",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating JWT: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s", jwt)
}

func createJWT(jwk *jose.JSONWebKey, claims ...any) (string, error) {
	key := jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
		Key:       jwk,
	}

	signer, err := jose.NewSigner(
		key,
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", err
	}

	builder := jwt.Signed(signer)

	for _, claim := range claims {
		builder = builder.Claims(claim)
	}

	token, err := builder.Serialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

func validity(claims jwt.Claims) jwt.Claims {
	now := time.Now().UTC()

	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.NotBefore = jwt.NewNumericDate(now.Add(-1 * time.Minute))
	claims.Expiry = jwt.NewNumericDate(now.Add(1 * time.Minute))

	return claims
}
