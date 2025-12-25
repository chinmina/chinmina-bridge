package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
)

var (
	// ErrClaimNotFound indicates a required claim was not found in the claims lookup
	ErrClaimNotFound = errors.New("claim not found")
)

// buildkiteCustomClaims sets up OIDC custom claims for a Buildkite-issued JWT.
func buildkiteCustomClaims(expectedOrganizationSlug string) func() validator.CustomClaims {
	return func() validator.CustomClaims {
		return &BuildkiteClaims{
			expectedOrganizationSlug: expectedOrganizationSlug,
		}
	}
}

// registeredClaimsValidator ensures that the basic claims that we rely on are
// part of the supplied claims. It also ensures that the the token has a valid
// time period. The core validation takes care of enforcing the active and
// expiry dates: this simply ensures that they're present.
func registeredClaimsValidator(next jwtmiddleware.ValidateToken) jwtmiddleware.ValidateToken {
	return func(ctx context.Context, token string) (any, error) {

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

// BuildkiteClaims define the additional claims that Builkite includes in the
// JWT.
//
// See: https://buildkite.com/docs/agent/v3/cli-oidc#claims
type BuildkiteClaims struct {
	OrganizationSlug string            `json:"organization_slug"`
	PipelineSlug     string            `json:"pipeline_slug"`
	PipelineID       string            `json:"pipeline_id"`
	BuildNumber      int               `json:"build_number"`
	BuildBranch      string            `json:"build_branch"`
	BuildTag         string            `json:"build_tag"`
	BuildCommit      string            `json:"build_commit"`
	StepKey          string            `json:"step_key"`
	JobId            string            `json:"job_id"`
	AgentId          string            `json:"agent_id"`
	ClusterID        string            `json:"cluster_id"`
	ClusterName      string            `json:"cluster_name"`
	QueueID          string            `json:"queue_id"`
	QueueKey         string            `json:"queue_key"`
	AgentTags        map[string]string `json:"-"` // handled in UnmarshalJSON

	expectedOrganizationSlug string `json:"-"` // not part of JWT
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

// JSON JWT claims unmarshaling with agent_tag: prefix handling
//
// Custom unmarshaling is implemented because struct-tag based approaches don't
// allow us to extract fields prefixed with "agent_tag:" into the AgentTags map.
// This will be easier when JSONv2 is shipped.
//
// This implementation uses a generic switch approach with setField[T] for type
// conversion. It was chosen after benchmarking 5 different implementations for
// optimal balance of performance and maintainability:
//
//   - Current approach (switch + generic setField): 14.0µs/op, baseline performance, ~50 lines of code
//   - Setter map with constant: 14.2µs/op (+2% slower), slightly more flexible but minimal difference
//   - Manual type assertions (original): 14.0µs/op, identical performance but ~200 lines of repetitive code
//   - Double unmarshal (with a "shadow" type): 20.0µs/op (+43% slower), eliminated as too slow
//   - Token-based decoder: 17.9µs/op (+28% slower, +88% memory), eliminated as too slow and complex
//
// The generic approach eliminates repetitive type checking while maintaining
// identical performance characteristics.

// UnmarshalJSON implements custom JSON unmarshaling to handle agent_tag: prefixed fields.
func (c *BuildkiteClaims) UnmarshalJSON(data []byte) error {
	// Parse into map to access all fields
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Process each field
	c.AgentTags = make(map[string]string)
	for key, value := range raw {
		if err := c.setClaimField(key, value); err != nil {
			return err
		}
	}

	return nil
}

// setClaimField maps a JWT field name to the appropriate struct field.
// Returns an error if a known field has the wrong type.
// Unknown fields are silently ignored.
func (c *BuildkiteClaims) setClaimField(key string, value any) error {
	var err error
	switch key {
	case "organization_slug":
		err = setField(&c.OrganizationSlug, value)
	case "pipeline_slug":
		err = setField(&c.PipelineSlug, value)
	case "pipeline_id":
		err = setField(&c.PipelineID, value)
	case "build_number":
		err = setField(&c.BuildNumber, value)
	case "build_branch":
		err = setField(&c.BuildBranch, value)
	case "build_tag":
		err = setField(&c.BuildTag, value)
	case "build_commit":
		err = setField(&c.BuildCommit, value)
	case "step_key":
		err = setField(&c.StepKey, value)
	case "job_id":
		err = setField(&c.JobId, value)
	case "agent_id":
		err = setField(&c.AgentId, value)
	case "cluster_id":
		err = setField(&c.ClusterID, value)
	case "cluster_name":
		err = setField(&c.ClusterName, value)
	case "queue_id":
		err = setField(&c.QueueID, value)
	case "queue_key":
		err = setField(&c.QueueKey, value)
	default:
		// Handle agent_tag: prefix
		if tagName, found := strings.CutPrefix(key, "agent_tag:"); found {
			strVal, convErr := convertValue[string](value)
			if convErr != nil {
				return fmt.Errorf("agent_tag:%s: %w", tagName, convErr)
			}
			c.AgentTags[tagName] = strVal
		}

		// Unknown fields silently ignored
		return nil
	}

	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}

// Lookup implements ClaimValueLookup interface for BuildkiteClaims.
// Returns (value, nil) when claim is present and populated.
// Returns ("", error) for optional claims when not present or for unknown claims.
func (c BuildkiteClaims) Lookup(claim string) (string, error) {
	switch claim {
	case "organization_slug":
		return c.OrganizationSlug, nil
	case "pipeline_slug":
		return c.PipelineSlug, nil
	case "pipeline_id":
		return c.PipelineID, nil
	case "build_number":
		return strconv.Itoa(c.BuildNumber), nil
	case "build_branch":
		return c.BuildBranch, nil
	case "build_tag":
		return lookupOptional(c.BuildTag)
	case "build_commit":
		return c.BuildCommit, nil
	case "cluster_id":
		return lookupOptional(c.ClusterID)
	case "cluster_name":
		return lookupOptional(c.ClusterName)
	case "queue_id":
		return lookupOptional(c.QueueID)
	case "queue_key":
		return lookupOptional(c.QueueKey)
	default:
		// Handle agent_tag: prefix dynamically
		if agentTag, found := strings.CutPrefix(claim, "agent_tag:"); found {
			if val, ok := c.AgentTags[agentTag]; ok {
				return val, nil
			}
		}
		return "", ErrClaimNotFound
	}
}

// convertValue converts any to target type T, handling JSON number conversion.
// This function is inlined by the compiler for each concrete type T.
func convertValue[T comparable](value any) (T, error) {
	var zero T

	// return zero value for an expclicit nil
	if value == nil {
		return zero, nil
	}

	// Handle JSON number (float64) to int conversion
	switch any(zero).(type) {
	case int:
		if f, ok := value.(float64); ok {
			return any(int(f)).(T), nil
		}
	}

	// Default: direct type assertion
	v, ok := value.(T)
	if !ok {
		return zero, fmt.Errorf("expected %T, got %T", zero, value)
	}

	return v, nil
}

// setField is a generic setter that converts and assigns value to target.
// This function is inlined by the compiler for each concrete type T.
func setField[T comparable](target *T, value any) error {
	v, err := convertValue[T](value)
	if err != nil {
		return err
	}
	*target = v
	return nil
}

// lookupOptional returns (value, nil) if the value is non-empty, otherwise ("", ErrClaimNotFound).
func lookupOptional(value string) (string, error) {
	if value != "" {
		return value, nil
	}
	return "", ErrClaimNotFound
}
