package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

var (
	// ErrClaimNotFound indicates a required claim was not found in the claims lookup
	ErrClaimNotFound = errors.New("claim not found")
)

// FieldPresent tracks whether a JSON field was present with a non-null value.
// Used for registered claims that must be present but whose values are
// validated elsewhere (by the JWT middleware itself).
type FieldPresent struct {
	valued bool
}

func (f FieldPresent) Valued() bool {
	return f.valued
}

// buildkiteCustomClaims sets up OIDC custom claims for a Buildkite-issued JWT.
func buildkiteCustomClaims(expectedOrganizationSlug string) func() *BuildkiteClaims {
	return func() *BuildkiteClaims {
		return &BuildkiteClaims{
			expectedOrganizationSlug: expectedOrganizationSlug,
		}
	}
}

// BuildkiteClaims define the additional claims that Builkite includes in the
// JWT.
//
// See: https://buildkite.com/docs/agent/v3/cli-oidc#claims
type BuildkiteClaims struct {
	// Registered claims - validation only, no getters needed
	// The JWT middleware validates the actual values; we just check presence
	// These fields are populated via UnmarshalJSON's setClaimField method
	subject   string
	notBefore FieldPresent
	expiry    FieldPresent

	OrganizationSlug string            `json:"organization_slug"`
	PipelineSlug     string            `json:"pipeline_slug"`
	PipelineID       string            `json:"pipeline_id"`
	BuildNumber      int               `json:"build_number"`
	BuildBranch      string            `json:"build_branch"`
	BuildTag         string            `json:"build_tag"`
	BuildCommit      string            `json:"build_commit"`
	StepKey          string            `json:"step_key"`
	JobID            string            `json:"job_id"`
	AgentID          string            `json:"agent_id"`
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
	// Validate registered claims are present
	if c.subject == "" {
		return errors.New("subject claim not present")
	}
	if !c.notBefore.Valued() {
		return errors.New("nbf claim not present")
	}
	if !c.expiry.Valued() {
		return errors.New("exp claim not present")
	}

	fields := [][]string{
		{"organization_slug", c.OrganizationSlug},
		{"pipeline_slug", c.PipelineSlug},
		{"pipeline_id", c.PipelineID},
		{"build_number", strconv.Itoa(c.BuildNumber)},
		{"build_branch", c.BuildBranch},
		{"build_commit", c.BuildCommit},
		// step_key may be nil
		{"job_id", c.JobID},
		{"agent_id", c.AgentID},
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

// SetOnToken sets all non-empty BuildkiteClaims fields on the given JWT token.
// Empty string fields are skipped to reduce token size.
// BuildNumber is always set since 0 is a valid value.
func (c BuildkiteClaims) SetOnToken(token jwt.Token) error {
	claims := []struct {
		key   string
		value any
		skip  bool
	}{
		{"organization_slug", c.OrganizationSlug, c.OrganizationSlug == ""},
		{"pipeline_slug", c.PipelineSlug, c.PipelineSlug == ""},
		{"pipeline_id", c.PipelineID, c.PipelineID == ""},
		{"build_number", c.BuildNumber, false}, // always set (0 is valid)
		{"build_branch", c.BuildBranch, c.BuildBranch == ""},
		{"build_commit", c.BuildCommit, c.BuildCommit == ""},
		{"build_tag", c.BuildTag, c.BuildTag == ""},
		{"step_key", c.StepKey, c.StepKey == ""},
		{"job_id", c.JobID, c.JobID == ""},
		{"agent_id", c.AgentID, c.AgentID == ""},
		{"cluster_id", c.ClusterID, c.ClusterID == ""},
		{"cluster_name", c.ClusterName, c.ClusterName == ""},
		{"queue_id", c.QueueID, c.QueueID == ""},
		{"queue_key", c.QueueKey, c.QueueKey == ""},
	}

	for _, claim := range claims {
		if claim.skip {
			continue
		}
		if err := token.Set(claim.key, claim.value); err != nil {
			return fmt.Errorf("failed to set %s: %w", claim.key, err)
		}
	}

	for k, v := range c.AgentTags {
		if err := token.Set("agent_tag:"+k, v); err != nil {
			return fmt.Errorf("failed to set agent_tag:%s: %w", k, err)
		}
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
	case "sub":
		err = setField(&c.subject, value)
	case "nbf":
		// FieldPresent: any non-nil value means the field was valued
		if value != nil {
			c.notBefore.valued = true
		}
	case "exp":
		// FieldPresent: any non-nil value means the field was valued
		if value != nil {
			c.expiry.valued = true
		}
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
		err = setField(&c.JobID, value)
	case "agent_id":
		err = setField(&c.AgentID, value)
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
