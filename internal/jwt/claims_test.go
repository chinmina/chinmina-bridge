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
				AgentTags:        map[string]string{},
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
				AgentTags:        map[string]string{},
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

func TestBuildkiteClaims_UnmarshalJSON_AgentTags(t *testing.T) {
	cases := []struct {
		name     string
		jsonData string
		expected BuildkiteClaims
	}{
		{
			name: "agent tags are extracted from agent_tag: prefixed fields",
			jsonData: `{
				"organization_slug": "acme",
				"pipeline_slug": "pipeline",
				"pipeline_id": "pipeline_uuid",
				"build_number": 123,
				"build_branch": "main",
				"build_commit": "abc123",
				"job_id": "job1",
				"agent_id": "agent1",
				"agent_tag:queue": "runners",
				"agent_tag:os": "linux",
				"agent_tag:arch": "amd64"
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
				AgentTags: map[string]string{
					"queue": "runners",
					"os":    "linux",
					"arch":  "amd64",
				},
			},
		},
		{
			name: "empty agent tags map when no agent_tag: fields",
			jsonData: `{
				"organization_slug": "acme",
				"pipeline_slug": "pipeline",
				"pipeline_id": "pipeline_uuid",
				"build_number": 456,
				"build_branch": "develop",
				"build_commit": "def456",
				"job_id": "job2",
				"agent_id": "agent2"
			}`,
			expected: BuildkiteClaims{
				OrganizationSlug: "acme",
				PipelineSlug:     "pipeline",
				PipelineID:       "pipeline_uuid",
				BuildNumber:      456,
				BuildBranch:      "develop",
				BuildCommit:      "def456",
				JobId:            "job2",
				AgentId:          "agent2",
				AgentTags:        map[string]string{},
			},
		},
		{
			name: "unknown fields are silently ignored",
			jsonData: `{
				"organization_slug": "acme",
				"pipeline_slug": "pipeline",
				"pipeline_id": "pipeline_uuid",
				"build_number": 789,
				"build_branch": "feature",
				"build_commit": "ghi789",
				"job_id": "job3",
				"agent_id": "agent3",
				"unknown_field": "ignored",
				"another_unknown": 12345
			}`,
			expected: BuildkiteClaims{
				OrganizationSlug: "acme",
				PipelineSlug:     "pipeline",
				PipelineID:       "pipeline_uuid",
				BuildNumber:      789,
				BuildBranch:      "feature",
				BuildCommit:      "ghi789",
				JobId:            "job3",
				AgentId:          "agent3",
				AgentTags:        map[string]string{},
			},
		},
		{
			name: "mixed standard fields, cluster fields, and agent tags",
			jsonData: `{
				"organization_slug": "acme",
				"pipeline_slug": "pipeline",
				"pipeline_id": "pipeline_uuid",
				"build_number": 999,
				"build_branch": "main",
				"build_commit": "abc999",
				"job_id": "job4",
				"agent_id": "agent4",
				"cluster_id": "cluster-xyz",
				"queue_key": "production",
				"agent_tag:env": "prod",
				"agent_tag:region": "us-west-2"
			}`,
			expected: BuildkiteClaims{
				OrganizationSlug: "acme",
				PipelineSlug:     "pipeline",
				PipelineID:       "pipeline_uuid",
				BuildNumber:      999,
				BuildBranch:      "main",
				BuildCommit:      "abc999",
				JobId:            "job4",
				AgentId:          "agent4",
				ClusterID:        "cluster-xyz",
				QueueKey:         "production",
				AgentTags: map[string]string{
					"env":    "prod",
					"region": "us-west-2",
				},
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
func TestBuildkiteClaims_UnmarshalJSON_TypeError(t *testing.T) {
	cases := []struct {
		name          string
		jsonData      string
		expectedError string
	}{
		{
			name: "string field with wrong type",
			jsonData: `{
				"organization_slug": 123,
				"pipeline_slug": "pipeline",
				"pipeline_id": "pipeline_uuid",
				"build_number": 123,
				"build_branch": "main",
				"build_commit": "abc123",
				"job_id": "job1",
				"agent_id": "agent1"
			}`,
			expectedError: "organization_slug: expected string, got float64",
		},
		{
			name: "build_number with wrong type",
			jsonData: `{
				"organization_slug": "acme",
				"pipeline_slug": "pipeline",
				"pipeline_id": "pipeline_uuid",
				"build_number": "not-a-number",
				"build_branch": "main",
				"build_commit": "abc123",
				"job_id": "job1",
				"agent_id": "agent1"
			}`,
			expectedError: "build_number: expected number, got string",
		},
		{
			name: "agent_tag with wrong type",
			jsonData: `{
				"organization_slug": "acme",
				"pipeline_slug": "pipeline",
				"pipeline_id": "pipeline_uuid",
				"build_number": 123,
				"build_branch": "main",
				"build_commit": "abc123",
				"job_id": "job1",
				"agent_id": "agent1",
				"agent_tag:queue": 456
			}`,
			expectedError: "agent_tag:queue: expected string, got float64",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var claims BuildkiteClaims
			err := json.Unmarshal([]byte(tt.jsonData), &claims)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestBuildkiteClaims_Lookup(t *testing.T) {
	claims := BuildkiteClaims{
		OrganizationSlug: "acme",
		PipelineSlug:     "pipeline",
		PipelineID:       "pipeline-123",
		BuildNumber:      456,
		BuildBranch:      "main",
		BuildTag:         "v1.0.0",
		BuildCommit:      "abc123",
		ClusterID:        "cluster-xyz",
		ClusterName:      "prod-cluster",
		QueueID:          "queue-789",
		QueueKey:         "default",
		AgentTags: map[string]string{
			"queue":  "runners",
			"os":     "linux",
			"region": "us-west-2",
		},
	}

	t.Run("success cases", func(t *testing.T) {
		tests := []struct {
			name          string
			claim         string
			expectedValue string
			expectedFound bool
		}{
			{"organization_slug", "organization_slug", "acme", true},
			{"pipeline_slug", "pipeline_slug", "pipeline", true},
			{"pipeline_id", "pipeline_id", "pipeline-123", true},
			{"build_number", "build_number", "456", true},
			{"build_branch", "build_branch", "main", true},
			{"build_tag", "build_tag", "v1.0.0", true},
			{"build_commit", "build_commit", "abc123", true},
			{"cluster_id", "cluster_id", "cluster-xyz", true},
			{"cluster_name", "cluster_name", "prod-cluster", true},
			{"queue_id", "queue_id", "queue-789", true},
			{"queue_key", "queue_key", "default", true},
			{"agent_tag:queue", "agent_tag:queue", "runners", true},
			{"agent_tag:os", "agent_tag:os", "linux", true},
			{"agent_tag:region", "agent_tag:region", "us-west-2", true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				value, found := claims.Lookup(tt.claim)
				assert.Equal(t, tt.expectedValue, value)
				assert.Equal(t, tt.expectedFound, found)
			})
		}
	})

	t.Run("optional claims when empty", func(t *testing.T) {
		emptyClaims := BuildkiteClaims{
			OrganizationSlug: "acme",
			PipelineSlug:     "pipeline",
			PipelineID:       "pipeline-123",
			BuildNumber:      456,
			BuildBranch:      "main",
			BuildCommit:      "abc123",
			// Optional fields left empty
		}

		tests := []struct {
			name  string
			claim string
		}{
			{"build_tag empty", "build_tag"},
			{"cluster_id empty", "cluster_id"},
			{"cluster_name empty", "cluster_name"},
			{"queue_id empty", "queue_id"},
			{"queue_key empty", "queue_key"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				value, found := emptyClaims.Lookup(tt.claim)
				assert.Equal(t, "", value)
				assert.False(t, found, "optional claim should return false when empty")
			})
		}
	})

	t.Run("unknown claims", func(t *testing.T) {
		tests := []struct {
			name  string
			claim string
		}{
			{"unknown claim", "unknown_claim"},
			{"step_key not exposed", "step_key"},
			{"job_id not exposed", "job_id"},
			{"agent_id not exposed", "agent_id"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				value, found := claims.Lookup(tt.claim)
				assert.Equal(t, "", value)
				assert.False(t, found)
			})
		}
	})

	t.Run("agent tag not present", func(t *testing.T) {
		value, found := claims.Lookup("agent_tag:nonexistent")
		assert.Equal(t, "", value)
		assert.False(t, found)
	})

	t.Run("empty agent tags map", func(t *testing.T) {
		emptyClaims := BuildkiteClaims{
			OrganizationSlug: "acme",
			PipelineSlug:     "pipeline",
			PipelineID:       "pipeline-123",
			BuildNumber:      789,
			BuildBranch:      "feature",
			BuildCommit:      "def456",
			AgentTags:        map[string]string{},
		}

		value, found := emptyClaims.Lookup("agent_tag:queue")
		assert.Equal(t, "", value)
		assert.False(t, found)
	})
}
