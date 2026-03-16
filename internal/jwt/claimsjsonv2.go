//go:build fastunmarshal

package jwt

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"strings"
)

// UnmarshalJSONFrom implements the json/v2 UnmarshalerFrom interface,
// providing a token-based streaming decoder for BuildkiteClaims.
// When built with -tags=fastunmarshal, the json/v2 runtime selects this
// method over the UnmarshalJSON([]byte) path.
func (c *BuildkiteClaims) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
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
// appropriate field of c, mirroring the logic of setClaimField.
func (c *BuildkiteClaims) decodeClaimField(key string, dec *jsontext.Decoder) error {
	// Handle agent_tag: prefix before the switch.
	if tagName, found := strings.CutPrefix(key, "agent_tag:"); found {
		var strVal string
		if err := jsonv2.UnmarshalDecode(dec, &strVal); err != nil {
			return fmt.Errorf("agent_tag:%s: %w", tagName, err)
		}
		c.AgentTags[tagName] = strVal
		return nil
	}

	switch key {
	case "sub":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.subject))
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
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.OrganizationSlug))
	case "pipeline_slug":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.PipelineSlug))
	case "pipeline_id":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.PipelineID))
	case "build_number":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.BuildNumber))
	case "build_branch":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.BuildBranch))
	case "build_tag":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.BuildTag))
	case "build_commit":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.BuildCommit))
	case "step_key":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.StepKey))
	case "job_id":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.JobID))
	case "agent_id":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.AgentID))
	case "cluster_id":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.ClusterID))
	case "cluster_name":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.ClusterName))
	case "queue_id":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.QueueID))
	case "queue_key":
		return wrapFieldError(key, jsonv2.UnmarshalDecode(dec, &c.QueueKey))
	default:
		// Unknown fields silently ignored.
		return dec.SkipValue()
	}
}

func wrapFieldError(key string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", key, err)
}
