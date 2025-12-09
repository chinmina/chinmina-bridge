package jwt

import (
	"context"
	"encoding/json"
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

// UnmarshalJSON implements custom JSON unmarshaling to handle agent_tag: prefixed fields.
func (c *BuildkiteClaims) UnmarshalJSON(data []byte) error {
	// Parse into map to access all fields
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Process each field
	c.AgentTags = make(map[string]string)
	for key, value := range raw {
		if err := c.setField(key, value); err != nil {
			return err
		}
	}

	return nil
}

// setField maps a JWT field name to the appropriate struct field.
// Returns an error if a known field has the wrong type.
// Unknown fields are silently ignored.
func (c *BuildkiteClaims) setField(key string, value interface{}) error {
	switch key {
	case "organization_slug":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("organization_slug: expected string, got %T", value)
		}
		c.OrganizationSlug = v
	case "pipeline_slug":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("pipeline_slug: expected string, got %T", value)
		}
		c.PipelineSlug = v
	case "pipeline_id":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("pipeline_id: expected string, got %T", value)
		}
		c.PipelineID = v
	case "build_number":
		v, ok := value.(float64)
		if !ok {
			return fmt.Errorf("build_number: expected number, got %T", value)
		}
		c.BuildNumber = int(v)
	case "build_branch":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("build_branch: expected string, got %T", value)
		}
		c.BuildBranch = v
	case "build_tag":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("build_tag: expected string, got %T", value)
		}
		c.BuildTag = v
	case "build_commit":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("build_commit: expected string, got %T", value)
		}
		c.BuildCommit = v
	case "step_key":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("step_key: expected string, got %T", value)
		}
		c.StepKey = v
	case "job_id":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("job_id: expected string, got %T", value)
		}
		c.JobId = v
	case "agent_id":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("agent_id: expected string, got %T", value)
		}
		c.AgentId = v
	case "cluster_id":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("cluster_id: expected string, got %T", value)
		}
		c.ClusterID = v
	case "cluster_name":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("cluster_name: expected string, got %T", value)
		}
		c.ClusterName = v
	case "queue_id":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("queue_id: expected string, got %T", value)
		}
		c.QueueID = v
	case "queue_key":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("queue_key: expected string, got %T", value)
		}
		c.QueueKey = v
	default:
		// Handle agent_tag: prefix
		if tagName, found := strings.CutPrefix(key, "agent_tag:"); found {
			strVal, ok := value.(string)
			if !ok {
				return fmt.Errorf("agent_tag:%s: expected string, got %T", tagName, value)
			}
			c.AgentTags[tagName] = strVal
		}
		// Unknown fields silently ignored
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
