package jwt

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
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
	// These fields are populated via decodeClaimField
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

// lookupOptional returns (value, nil) if the value is non-empty, otherwise ("", ErrClaimNotFound).
func lookupOptional(value string) (string, error) {
	if value != "" {
		return value, nil
	}
	return "", ErrClaimNotFound
}

// UnmarshalJSONFrom implements the json/v2 UnmarshalerFrom interface,
// providing a token-based streaming decoder for BuildkiteClaims.
func (c *BuildkiteClaims) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	// Reject non-object JSON before advancing the decoder. Without this check,
	// invalid input like arrays or scalars would advance decoder state before
	// confirming the input is an object, breaking the structured error handling
	// that json/v2 expects.
	if kind := dec.PeekKind(); kind != '{' {
		return &json.SemanticError{JSONKind: kind}
	}
	// Consume opening '{'.
	if _, err := dec.ReadToken(); err != nil {
		return err
	}

	c.AgentTags = make(map[string]string)

	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return err
		}
		if tok.Kind() == jsontext.KindEndObject {
			return nil
		}
		// Object keys are always strings; tok.String() returns the unescaped key.
		if err := c.decodeClaimField(tok.String(), dec); err != nil {
			return err
		}
	}
}

// decodeClaimField reads the next JSON value from dec and stores it in the
// appropriate field of c. Unknown fields are silently ignored.
func (c *BuildkiteClaims) decodeClaimField(key string, dec *jsontext.Decoder) error {
	// Handle agent_tag: prefix before the switch.
	if tagName, found := strings.CutPrefix(key, "agent_tag:"); found {
		var strVal string
		if err := json.UnmarshalDecode(dec, &strVal); err != nil {
			return err
		}
		c.AgentTags[tagName] = strVal
		return nil
	}

	switch key {
	case "sub":
		return json.UnmarshalDecode(dec, &c.subject)
	case "nbf":
		// FieldPresent: any non-null value means the field was valued.
		if dec.PeekKind() != jsontext.KindNull {
			c.notBefore.valued = true
		}
		return dec.SkipValue()
	case "exp":
		// FieldPresent: any non-null value means the field was valued.
		if dec.PeekKind() != jsontext.KindNull {
			c.expiry.valued = true
		}
		return dec.SkipValue()
	case "organization_slug":
		return json.UnmarshalDecode(dec, &c.OrganizationSlug)
	case "pipeline_slug":
		return json.UnmarshalDecode(dec, &c.PipelineSlug)
	case "pipeline_id":
		return json.UnmarshalDecode(dec, &c.PipelineID)
	case "build_number":
		return json.UnmarshalDecode(dec, &c.BuildNumber)
	case "build_branch":
		return json.UnmarshalDecode(dec, &c.BuildBranch)
	case "build_tag":
		return json.UnmarshalDecode(dec, &c.BuildTag)
	case "build_commit":
		return json.UnmarshalDecode(dec, &c.BuildCommit)
	case "step_key":
		return json.UnmarshalDecode(dec, &c.StepKey)
	case "job_id":
		return json.UnmarshalDecode(dec, &c.JobID)
	case "agent_id":
		return json.UnmarshalDecode(dec, &c.AgentID)
	case "cluster_id":
		return json.UnmarshalDecode(dec, &c.ClusterID)
	case "cluster_name":
		return json.UnmarshalDecode(dec, &c.ClusterName)
	case "queue_id":
		return json.UnmarshalDecode(dec, &c.QueueID)
	case "queue_key":
		return json.UnmarshalDecode(dec, &c.QueueKey)
	default:
		// Unknown fields silently ignored.
		return dec.SkipValue()
	}
}
