package jwt

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
)

// registeredClaimsValidator ensures that the basic claims that we rely on are
// part of the supplied claims. It also ensures that the the token has a valid
// time period. The core validation takes care of enforcing the active and
// expiry dates: this simply ensures that they're present.
func registeredClaimsValidator(next jwtmiddleware.ValidateToken) jwtmiddleware.ValidateToken {
	return func(ctx context.Context, token string) (interface{}, error) {

		claims, err := next(ctx, token)
		if err != nil {
			return nil, err
		}

		validatedClaims, ok := claims.(*validator.ValidatedClaims)
		if !ok {
			return nil, fmt.Errorf("could not cast claims to validator.ValidatedClaims")
		}

		reg := validatedClaims.RegisteredClaims

		if len(reg.Audience) == 0 {
			return nil, fmt.Errorf("audience claim not present")
		}

		if reg.Issuer == "" {
			return nil, fmt.Errorf("issuer claim not present")
		}

		if reg.Subject == "" {
			return nil, fmt.Errorf("subject claim not present")
		}

		if reg.NotBefore == 0 || reg.Expiry == 0 {
			return nil, fmt.Errorf("token has no validity period")
		}

		return claims, nil
	}
}

// ClaimValueLookup provides zero-allocation claim value lookup.
type ClaimValueLookup interface {
	Lookup(claim string) (value string, found bool)
}

// BuildkiteClaims define the additional claims that Builkite includes in the
// JWT.
//
// See: https://buildkite.com/docs/agent/v3/cli-oidc#claims
type BuildkiteClaims struct {
	OrganizationSlug string `json:"organization_slug"`
	PipelineSlug     string `json:"pipeline_slug"`
	PipelineID       string `json:"pipeline_id"`
	BuildNumber      int    `json:"build_number"`
	BuildBranch      string `json:"build_branch"`
	BuildTag         string `json:"build_tag"`
	BuildCommit      string `json:"build_commit"`
	StepKey          string `json:"step_key"`
	JobId            string `json:"job_id"`
	AgentId          string `json:"agent_id"`
	ClusterID        string `json:"cluster_id"`
	ClusterName      string `json:"cluster_name"`
	QueueID          string `json:"queue_id"`
	QueueKey         string `json:"queue_key"`
	AgentTags        map[string]string `json:"-"`

	expectedOrganizationSlug string
}

// Validate ensures that the expected claims are present in the token, and that
// the organization slug matches the configured value.
func (c *BuildkiteClaims) Validate(ctx context.Context) error {

	fields := [][]string{
		{"organization_slug", c.OrganizationSlug},
		{"pipeline_slug", c.PipelineSlug},
		{"pipeline_id", c.PipelineID},
		{"build_number", strconv.Itoa(c.BuildNumber)},
		{"build_branch", c.BuildBranch},
		{"build_commit", c.BuildCommit},
		// step_key may be nil
		{"job_id", c.JobId},
		{"agent_id", c.AgentId},
	}

	missing := []string{}

	for _, pair := range fields {
		if pair[1] == "" {
			missing = append(missing, pair[0])
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing expected claim(s): %s", strings.Join(missing, ", "))
	}

	if c.expectedOrganizationSlug != "" && c.expectedOrganizationSlug != c.OrganizationSlug {
		return fmt.Errorf("expecting token issued for organization %s", c.expectedOrganizationSlug)
	}

	return nil
}

// buildkiteCustomClaims sets up OIDC custom claims for a Buildkite-issued JWT.
func buildkiteCustomClaims(expectedOrganizationSlug string) func() validator.CustomClaims {
	return func() validator.CustomClaims {
		return &BuildkiteClaims{
			expectedOrganizationSlug: expectedOrganizationSlug,
		}
	}
}
