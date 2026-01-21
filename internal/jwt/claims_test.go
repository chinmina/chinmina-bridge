package jwt

import (
	"context"
	"encoding/json"
	"testing"

	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildkiteClaims_Validate_Success(t *testing.T) {
	cases := []struct {
		name   string
		claims *BuildkiteClaims
	}{
		{
			name: "valid",
			claims: &BuildkiteClaims{
				subject:                  "organization:org:pipeline:pipeline:ref:main:commit:abc123",
				notBefore:                FieldPresent{valued: true},
				expiry:                   FieldPresent{valued: true},
				OrganizationSlug:         "org",
				PipelineSlug:             "pipeline",
				PipelineID:               "pipeline_uuid",
				BuildNumber:              123,
				BuildBranch:              "main",
				BuildCommit:              "abc123",
				StepKey:                  "step1",
				JobID:                    "job1",
				AgentID:                  "agent1",
				expectedOrganizationSlug: "org",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claims.Validate(context.Background())
			assert.NoError(t, err)
		})
	}
}

func TestBuildkiteClaims_Validate_Failure(t *testing.T) {
	cases := []struct {
		name              string
		claims            *BuildkiteClaims
		expectedErrorText string
	}{
		{
			name: "missing claims",
			claims: &BuildkiteClaims{
				subject:   "test",
				notBefore: FieldPresent{valued: true},
				expiry:    FieldPresent{valued: true},
			},
			expectedErrorText: "missing expected claim(s)",
		},
		{
			name: "wrong org",
			claims: &BuildkiteClaims{
				subject:                  "test",
				notBefore:                FieldPresent{valued: true},
				expiry:                   FieldPresent{valued: true},
				OrganizationSlug:         "wrong",
				PipelineSlug:             "pipeline",
				PipelineID:               "pipeline_uuid",
				BuildNumber:              123,
				BuildBranch:              "main",
				BuildCommit:              "abc123",
				StepKey:                  "step1",
				JobID:                    "job1",
				AgentID:                  "agent1",
				expectedOrganizationSlug: "right",
			},
			expectedErrorText: "expecting token issued for organization",
		},
		{
			name: "missing subject",
			claims: &BuildkiteClaims{
				notBefore:                FieldPresent{valued: true},
				expiry:                   FieldPresent{valued: true},
				OrganizationSlug:         "org",
				PipelineSlug:             "pipeline",
				PipelineID:               "pipeline_uuid",
				BuildNumber:              123,
				BuildBranch:              "main",
				BuildCommit:              "abc123",
				JobID:                    "job1",
				AgentID:                  "agent1",
				expectedOrganizationSlug: "org",
			},
			expectedErrorText: "subject claim not present",
		},
		{
			name: "missing nbf",
			claims: &BuildkiteClaims{
				subject:                  "test",
				expiry:                   FieldPresent{valued: true},
				OrganizationSlug:         "org",
				PipelineSlug:             "pipeline",
				PipelineID:               "pipeline_uuid",
				BuildNumber:              123,
				BuildBranch:              "main",
				BuildCommit:              "abc123",
				JobID:                    "job1",
				AgentID:                  "agent1",
				expectedOrganizationSlug: "org",
			},
			expectedErrorText: "nbf claim not present",
		},
		{
			name: "missing exp",
			claims: &BuildkiteClaims{
				subject:                  "test",
				notBefore:                FieldPresent{valued: true},
				OrganizationSlug:         "org",
				PipelineSlug:             "pipeline",
				PipelineID:               "pipeline_uuid",
				BuildNumber:              123,
				BuildBranch:              "main",
				BuildCommit:              "abc123",
				JobID:                    "job1",
				AgentID:                  "agent1",
				expectedOrganizationSlug: "org",
			},
			expectedErrorText: "exp claim not present",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claims.Validate(context.Background())
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErrorText)
		})
	}
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
				JobID:            "job1",
				AgentID:          "agent1",
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
				JobID:            "job1",
				AgentID:          "agent1",
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
				JobID:            "job1",
				AgentID:          "agent1",
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
				JobID:            "job2",
				AgentID:          "agent2",
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
				JobID:            "job3",
				AgentID:          "agent3",
				AgentTags:        map[string]string{},
			},
		},
		{
			name: "handles explicitly null fields",
			jsonData: `{
				"organization_slug": "acme",
				"pipeline_slug": "pipeline",
				"pipeline_id": "pipeline_uuid",
				"build_number": 123,
				"build_branch": "main",
				"build_commit": "abc123",
				"job_id": "job1",
				"agent_id": "agent1",
				"step_key": null
			}`,
			expected: BuildkiteClaims{
				OrganizationSlug: "acme",
				PipelineSlug:     "pipeline",
				PipelineID:       "pipeline_uuid",
				BuildNumber:      123,
				BuildBranch:      "main",
				BuildCommit:      "abc123",
				JobID:            "job1",
				AgentID:          "agent1",
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
				JobID:            "job4",
				AgentID:          "agent4",
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
			expectedError: "build_number: expected int, got string",
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
		}{
			{"organization_slug", "organization_slug", "acme"},
			{"pipeline_slug", "pipeline_slug", "pipeline"},
			{"pipeline_id", "pipeline_id", "pipeline-123"},
			{"build_number", "build_number", "456"},
			{"build_branch", "build_branch", "main"},
			{"build_tag", "build_tag", "v1.0.0"},
			{"build_commit", "build_commit", "abc123"},
			{"cluster_id", "cluster_id", "cluster-xyz"},
			{"cluster_name", "cluster_name", "prod-cluster"},
			{"queue_id", "queue_id", "queue-789"},
			{"queue_key", "queue_key", "default"},
			{"agent_tag:queue", "agent_tag:queue", "runners"},
			{"agent_tag:os", "agent_tag:os", "linux"},
			{"agent_tag:region", "agent_tag:region", "us-west-2"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				value, err := claims.Lookup(tt.claim)
				assert.Equal(t, tt.expectedValue, value)
				assert.NoError(t, err)
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
				value, err := emptyClaims.Lookup(tt.claim)
				assert.Equal(t, "", value)
				assert.ErrorIs(t, err, ErrClaimNotFound, "optional claim should return ErrClaimNotFound when empty")
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
				value, err := claims.Lookup(tt.claim)
				assert.Equal(t, "", value)
				assert.ErrorIs(t, err, ErrClaimNotFound)
			})
		}
	})

	t.Run("agent tag not present", func(t *testing.T) {
		value, err := claims.Lookup("agent_tag:nonexistent")
		assert.Equal(t, "", value)
		assert.ErrorIs(t, err, ErrClaimNotFound)
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

		value, err := emptyClaims.Lookup("agent_tag:queue")
		assert.Equal(t, "", value)
		assert.ErrorIs(t, err, ErrClaimNotFound)
	})
}

func TestBuildkiteClaims_SetOnToken(t *testing.T) {
	t.Run("sets all populated fields", func(t *testing.T) {
		claims := BuildkiteClaims{
			OrganizationSlug: "acme",
			PipelineSlug:     "pipeline",
			PipelineID:       "pipeline-123",
			BuildNumber:      456,
			BuildBranch:      "main",
			BuildCommit:      "abc123",
			BuildTag:         "v1.0.0",
			StepKey:          "build",
			JobID:            "job-789",
			AgentID:          "agent-xyz",
			ClusterID:        "cluster-1",
			ClusterName:      "prod",
			QueueID:          "queue-1",
			QueueKey:         "default",
			AgentTags: map[string]string{
				"os":   "linux",
				"arch": "amd64",
			},
		}

		token := jwxjwt.New()
		err := claims.SetOnToken(token)
		require.NoError(t, err)

		// Verify all fields are set
		assertClaim(t, token, "organization_slug", "acme")
		assertClaim(t, token, "pipeline_slug", "pipeline")
		assertClaim(t, token, "pipeline_id", "pipeline-123")
		assertClaimInt(t, token, "build_number", 456)
		assertClaim(t, token, "build_branch", "main")
		assertClaim(t, token, "build_commit", "abc123")
		assertClaim(t, token, "build_tag", "v1.0.0")
		assertClaim(t, token, "step_key", "build")
		assertClaim(t, token, "job_id", "job-789")
		assertClaim(t, token, "agent_id", "agent-xyz")
		assertClaim(t, token, "cluster_id", "cluster-1")
		assertClaim(t, token, "cluster_name", "prod")
		assertClaim(t, token, "queue_id", "queue-1")
		assertClaim(t, token, "queue_key", "default")
		assertClaim(t, token, "agent_tag:os", "linux")
		assertClaim(t, token, "agent_tag:arch", "amd64")
	})

	t.Run("skips empty string fields", func(t *testing.T) {
		claims := BuildkiteClaims{
			OrganizationSlug: "acme",
			PipelineSlug:     "pipeline",
			PipelineID:       "pipeline-123",
			BuildNumber:      456,
			BuildBranch:      "main",
			BuildCommit:      "abc123",
			// Leave optional fields empty
		}

		token := jwxjwt.New()
		err := claims.SetOnToken(token)
		require.NoError(t, err)

		// Verify required fields are set
		assertClaim(t, token, "organization_slug", "acme")
		assertClaimInt(t, token, "build_number", 456)

		// Verify empty fields are not set
		assertClaimMissing(t, token, "build_tag")
		assertClaimMissing(t, token, "step_key")
		assertClaimMissing(t, token, "cluster_id")
		assertClaimMissing(t, token, "cluster_name")
		assertClaimMissing(t, token, "queue_id")
		assertClaimMissing(t, token, "queue_key")
	})

	t.Run("build_number zero is valid", func(t *testing.T) {
		claims := BuildkiteClaims{
			OrganizationSlug: "acme",
			PipelineSlug:     "pipeline",
			PipelineID:       "pipeline-123",
			BuildNumber:      0, // explicitly zero
			BuildBranch:      "main",
			BuildCommit:      "abc123",
		}

		token := jwxjwt.New()
		err := claims.SetOnToken(token)
		require.NoError(t, err)

		assertClaimInt(t, token, "build_number", 0)
	})

	t.Run("handles nil agent tags map", func(t *testing.T) {
		claims := BuildkiteClaims{
			OrganizationSlug: "acme",
			PipelineSlug:     "pipeline",
			PipelineID:       "pipeline-123",
			BuildNumber:      1,
			BuildBranch:      "main",
			BuildCommit:      "abc123",
			AgentTags:        nil,
		}

		token := jwxjwt.New()
		err := claims.SetOnToken(token)
		require.NoError(t, err)

		// Should not error and should not set any agent_tag: fields
		assertClaimMissing(t, token, "agent_tag:anything")
	})
}

// assertClaim verifies a string claim value on the token.
func assertClaim(t *testing.T, token jwxjwt.Token, key, expected string) {
	t.Helper()
	var val string
	err := token.Get(key, &val)
	require.NoError(t, err, "expected claim %q to be present", key)
	assert.Equal(t, expected, val, "claim %q", key)
}

// assertClaimInt verifies an integer claim value on the token.
func assertClaimInt(t *testing.T, token jwxjwt.Token, key string, expected int) {
	t.Helper()
	var val int
	err := token.Get(key, &val)
	require.NoError(t, err, "expected claim %q to be present", key)
	assert.Equal(t, expected, val, "claim %q", key)
}

// assertClaimMissing verifies a claim is not present on the token.
func assertClaimMissing(t *testing.T, token jwxjwt.Token, key string) {
	t.Helper()
	var val any
	err := token.Get(key, &val)
	assert.Error(t, err, "expected claim %q to be absent", key)
}
