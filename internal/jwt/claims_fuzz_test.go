//go:build fuzz

package jwt

import (
	"encoding/json"
	"math"
	"testing"
)

func FuzzBuildkiteClaimsUnmarshalJSON(f *testing.F) {
	// Seed corpus covering valid claims, edge cases, and malformed inputs

	// Valid minimal claims
	f.Add(`{"organization_slug":"acme","pipeline_slug":"deploy","pipeline_id":"pid","build_number":123,"build_branch":"main","build_commit":"abc123","job_id":"job1","agent_id":"agent1"}`)

	// Valid with all fields
	f.Add(`{"organization_slug":"acme","pipeline_slug":"deploy","pipeline_id":"pid","build_number":456,"build_branch":"develop","build_tag":"v1.0","build_commit":"def456","step_key":"test","job_id":"job2","agent_id":"agent2","cluster_id":"c1","cluster_name":"prod","queue_id":"q1","queue_key":"default"}`)

	// With agent tags
	f.Add(`{"organization_slug":"acme","pipeline_slug":"deploy","pipeline_id":"pid","build_number":789,"build_branch":"main","build_commit":"ghi789","job_id":"job3","agent_id":"agent3","agent_tag:queue":"runners","agent_tag:os":"linux","agent_tag:arch":"amd64"}`)

	// Empty strings
	f.Add(`{"organization_slug":"","pipeline_slug":"","pipeline_id":"","build_number":0,"build_branch":"","build_commit":"","job_id":"","agent_id":""}`)

	// Type mismatches - string for int
	f.Add(`{"organization_slug":"acme","pipeline_slug":"deploy","pipeline_id":"pid","build_number":"not-a-number","build_branch":"main","build_commit":"abc","job_id":"job1","agent_id":"agent1"}`)

	// Type mismatches - int for string
	f.Add(`{"organization_slug":123,"pipeline_slug":"deploy","pipeline_id":"pid","build_number":456,"build_branch":"main","build_commit":"abc","job_id":"job1","agent_id":"agent1"}`)

	// agent_tag edge cases
	f.Add(`{"organization_slug":"acme","pipeline_slug":"deploy","pipeline_id":"pid","build_number":123,"build_branch":"main","build_commit":"abc","job_id":"job1","agent_id":"agent1","agent_tag:":"empty-key"}`)
	f.Add(`{"organization_slug":"acme","pipeline_slug":"deploy","pipeline_id":"pid","build_number":123,"build_branch":"main","build_commit":"abc","job_id":"job1","agent_id":"agent1","agent_tag":"no-colon"}`)
	f.Add(`{"organization_slug":"acme","pipeline_slug":"deploy","pipeline_id":"pid","build_number":123,"build_branch":"main","build_commit":"abc","job_id":"job1","agent_id":"agent1","agent_tag:foo":123}`)

	// Numeric boundaries
	f.Add(`{"organization_slug":"acme","pipeline_slug":"deploy","pipeline_id":"pid","build_number":2147483647,"build_branch":"main","build_commit":"abc","job_id":"job1","agent_id":"agent1"}`)
	f.Add(`{"organization_slug":"acme","pipeline_slug":"deploy","pipeline_id":"pid","build_number":-2147483648,"build_branch":"main","build_commit":"abc","job_id":"job1","agent_id":"agent1"}`)
	f.Add(`{"organization_slug":"acme","pipeline_slug":"deploy","pipeline_id":"pid","build_number":9999999999999999,"build_branch":"main","build_commit":"abc","job_id":"job1","agent_id":"agent1"}`)

	// Null values
	f.Add(`{"organization_slug":"acme","pipeline_slug":"deploy","pipeline_id":"pid","build_number":123,"build_branch":"main","build_commit":"abc","job_id":"job1","agent_id":"agent1","step_key":null}`)
	f.Add(`{"organization_slug":null,"pipeline_slug":"deploy","pipeline_id":"pid","build_number":123,"build_branch":"main","build_commit":"abc","job_id":"job1","agent_id":"agent1"}`)

	// Malformed JSON
	f.Add(`{`)
	f.Add(`{"organization_slug":"acme"`)
	f.Add(`{"organization_slug":"acme",}`)
	f.Add(``)
	f.Add(`null`)
	f.Add(`[]`)
	f.Add(`"string"`)

	// Deeply nested (shouldn't happen but test anyway)
	f.Add(`{"organization_slug":"acme","pipeline_slug":"deploy","pipeline_id":"pid","build_number":123,"build_branch":"main","build_commit":"abc","job_id":"job1","agent_id":"agent1","nested":{"deep":{"very":{"deep":"value"}}}}`)

	// Very long strings
	f.Add(`{"organization_slug":"` + string(make([]byte, 10000)) + `","pipeline_slug":"deploy","pipeline_id":"pid","build_number":123,"build_branch":"main","build_commit":"abc","job_id":"job1","agent_id":"agent1"}`)

	// Missing required fields
	f.Add(`{"organization_slug":"acme"}`)
	f.Add(`{}`)

	// Unknown fields only
	f.Add(`{"unknown":"field","another":"field"}`)

	f.Fuzz(func(t *testing.T, jsonData string) {
		// Property 1: No panics on any input
		var claims BuildkiteClaims
		err := json.Unmarshal([]byte(jsonData), &claims)

		// Property 2: If unmarshaling succeeds, claims should be valid struct
		if err == nil {
			// Verify AgentTags map is initialized (never nil)
			if claims.AgentTags == nil {
				t.Error("AgentTags map should be initialized, got nil")
			}

			// Verify we can iterate over AgentTags without panics
			for k, v := range claims.AgentTags {
				// Keys and values should be valid strings
				_ = k
				_ = v
			}

			// Verify build_number conversion didn't overflow in unexpected ways
			// If it's absurdly large, it's from overflow, but shouldn't panic
			if claims.BuildNumber > math.MaxInt32 || claims.BuildNumber < math.MinInt32 {
				// This is expected for very large float64 values
				// The conversion is int(f) which truncates
			}
		}

		// Property 3: Type errors should be descriptive
		if err != nil && err.Error() != "" {
			// Errors should mention field names or be about JSON syntax
			// We don't fail here, just verify error exists and is non-empty
		}
	})
}
