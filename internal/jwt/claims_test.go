package jwt

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildkiteClaims_Validate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		claims := &BuildkiteClaims{
			OrganizationSlug:         "org",
			PipelineSlug:             "pipeline",
			PipelineID:               "pipeline_uuid",
			BuildNumber:              123,
			BuildBranch:              "main",
			BuildCommit:              "abc123",
			StepKey:                  "step1",
			JobId:                    "job1",
			AgentId:                  "agent1",
			expectedOrganizationSlug: "org",
		}

		err := claims.Validate(context.Background())

		assert.NoError(t, err)
	})

	t.Run("missing claims", func(t *testing.T) {
		claims := &BuildkiteClaims{}

		err := claims.Validate(context.Background())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing expected claim(s)")
	})

	t.Run("wrong org", func(t *testing.T) {
		claims := &BuildkiteClaims{
			PipelineSlug: "pipeline",
			PipelineID:   "pipeline_uuid",
			BuildNumber:  123,
			BuildBranch:  "main",
			BuildCommit:  "abc123",
			StepKey:      "step1",
			JobId:        "job1",
			AgentId:      "agent1",

			OrganizationSlug:         "wrong",
			expectedOrganizationSlug: "right",
		}

		err := claims.Validate(context.Background())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expecting token issued for organization")
	})
}

func TestBuildkiteClaims_NewFields(t *testing.T) {
	cases := []struct {
		name     string
		jsonData string
		expected BuildkiteClaims
	}{
		{
			name: "cluster and queue fields unmarshal from JSON",
			jsonData: `{
				"organization_slug": "acme",
				"pipeline_slug": "pipeline",
				"pipeline_id": "pipeline_uuid",
				"build_number": 123,
				"build_branch": "main",
				"build_commit": "abc123",
				"job_id": "job1",
				"agent_id": "agent1",
				"cluster_id": "cluster-123",
				"cluster_name": "prod-cluster",
				"queue_id": "queue-456",
				"queue_key": "default"
			}`,
			expected: BuildkiteClaims{
				OrganizationSlug: "acme",
				PipelineSlug:     "pipeline",
				PipelineID:       "pipeline_uuid",
				BuildNumber:      123,
				BuildBranch:      "main",
				BuildCommit:      "abc123",
				JobId:            "job1",
				AgentId:          "agent1",
				ClusterID:        "cluster-123",
				ClusterName:      "prod-cluster",
				QueueID:          "queue-456",
				QueueKey:         "default",
			},
		},
		{
			name: "new fields are optional",
			jsonData: `{
				"organization_slug": "acme",
				"pipeline_slug": "pipeline",
				"pipeline_id": "pipeline_uuid",
				"build_number": 123,
				"build_branch": "main",
				"build_commit": "abc123",
				"job_id": "job1",
				"agent_id": "agent1"
			}`,
			expected: BuildkiteClaims{
				OrganizationSlug: "acme",
				PipelineSlug:     "pipeline",
				PipelineID:       "pipeline_uuid",
				BuildNumber:      123,
				BuildBranch:      "main",
				BuildCommit:      "abc123",
				JobId:            "job1",
				AgentId:          "agent1",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var claims BuildkiteClaims
			err := json.Unmarshal([]byte(tt.jsonData), &claims)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, claims)
		})
	}
}
