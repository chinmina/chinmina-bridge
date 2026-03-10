package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/loginfra"
	"github.com/gkampitakis/go-snaps/match"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedExpiry is a deterministic timestamp used in snapshot tests to avoid
// non-deterministic output. The expiryRemaining field must be matched with
// match.Any since it depends on time.Now().
var fixedExpiry = time.Unix(1893456000, 0) // 2029-12-31

// serializeSlogEntry writes the entry via slog.JSONHandler and returns the raw JSON bytes.
// The time field is removed for deterministic snapshots; the level is formatted
// via ReplaceLevel so audit entries appear as "audit" in the output.
func serializeSlogEntry(entry audit.Entry) []byte {
	var buf bytes.Buffer
	replaceLevel := loginfra.ReplaceLevel(map[slog.Level]string{audit.SlogLevel: audit.SlogLevelName})
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.Level(-100),
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Remove the time field to keep snapshots deterministic.
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return replaceLevel(groups, a)
		},
	})
	logger := slog.New(handler)
	logger.LogAttrs(context.Background(), audit.SlogLevel, "audit_event", entry.SlogAttrs()...)
	return buf.Bytes()
}

// --- LogValuer ---

func TestSlogClaimMatchLogValue(t *testing.T) {
	cm := audit.ClaimMatch{Claim: "pipeline_slug", Value: "silk-prod"}
	v := cm.LogValue()

	require.Equal(t, slog.KindGroup, v.Kind())
	attrs := v.Group()
	require.Len(t, attrs, 2)

	assert.Equal(t, slog.String("claim", "pipeline_slug"), attrs[0])
	assert.Equal(t, slog.String("value", "silk-prod"), attrs[1])
}

func TestSlogClaimFailureLogValue(t *testing.T) {
	cf := audit.ClaimFailure{Claim: "pipeline_slug", Pattern: ".*-release", Value: "silk-staging"}
	v := cf.LogValue()

	require.Equal(t, slog.KindGroup, v.Kind())
	attrs := v.Group()
	require.Len(t, attrs, 3)

	assert.Equal(t, slog.String("claim", "pipeline_slug"), attrs[0])
	assert.Equal(t, slog.String("pattern", ".*-release"), attrs[1])
	assert.Equal(t, slog.String("value", "silk-staging"), attrs[2])
}

// --- Entry.SlogAttrs snapshot tests ---

func TestSlogEntryAttrs(t *testing.T) {
	tests := []struct {
		name     string
		entry    audit.Entry
		matchers []match.JSONMatcher
	}{
		{
			name:  "minimal entry",
			entry: audit.Entry{},
		},
		{
			name: "unauthorized request with error",
			entry: audit.Entry{
				Method:     "POST",
				Path:       "/token",
				Authorized: false,
				Error:      "access denied",
			},
		},
		{
			name: "with pipeline details",
			entry: audit.Entry{
				OrganizationSlug: "acme",
				PipelineSlug:     "main-pipeline",
				JobID:            "job-123",
				BuildNumber:      42,
				BuildBranch:      "main",
			},
		},
		{
			name: "pipeline group elided when empty",
			entry: audit.Entry{
				Method: "GET",
				Path:   "/healthcheck",
			},
		},
		{
			name: "with authorization expiry",
			entry: audit.Entry{
				Authorized:     true,
				AuthSubject:    "buildkite:org:acme",
				AuthExpirySecs: fixedExpiry.Unix(),
			},
			matchers: []match.JSONMatcher{
				match.Any("authorization.expiryRemaining"),
			},
		},
		{
			name: "with token fields no expiry",
			entry: audit.Entry{
				RequestedProfile:    "org/repo",
				RequestedRepository: "https://github.com/org/repo",
				VendedRepository:    "https://github.com/org/vended-repo",
				Repositories:        []string{"org/repo"},
				Permissions:         []string{"contents:read"},
			},
		},
		{
			name: "with token and expiry",
			entry: audit.Entry{
				RequestedRepository: "https://github.com/org/repo",
				ExpirySecs:          fixedExpiry.Unix(),
			},
			matchers: []match.JSONMatcher{
				match.Any("token.expiryRemaining"),
			},
		},
		{
			name: "with claim matches",
			entry: audit.Entry{
				RequestedRepository: "https://github.com/org/repo",
				ClaimsMatched: []audit.ClaimMatch{
					{Claim: "pipeline_slug", Value: "silk-prod"},
					{Claim: "build_branch", Value: "main"},
				},
			},
		},
		{
			name: "with claim failures",
			entry: audit.Entry{
				RequestedRepository: "https://github.com/org/repo",
				ClaimsFailed: []audit.ClaimFailure{
					{Claim: "pipeline_slug", Pattern: ".*-release", Value: "silk-staging"},
				},
			},
		},
		{
			name: "empty matches array included",
			entry: audit.Entry{
				RequestedRepository: "https://github.com/org/repo",
				ClaimsMatched:       []audit.ClaimMatch{},
			},
		},
		{
			name: "nil matches array omitted",
			entry: audit.Entry{
				RequestedRepository: "https://github.com/org/repo",
				// ClaimsMatched is nil — token group still appears due to requestedRepository
			},
		},
		{
			name: "hashed token present when set",
			entry: audit.Entry{
				RequestedRepository: "https://github.com/org/repo",
				HashedToken:         "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
			},
		},
		{
			name: "hashed token absent when empty",
			entry: audit.Entry{
				RequestedRepository: "https://github.com/org/repo",
			},
		},
		{
			name: "fully populated",
			entry: audit.Entry{
				Method:              "POST",
				Path:                "/token",
				Status:              200,
				SourceIP:            "10.0.0.1",
				UserAgent:           "test/1.0",
				OrganizationSlug:    "acme",
				PipelineSlug:        "main-pipeline",
				JobID:               "job-123",
				BuildNumber:         42,
				BuildBranch:         "main",
				Authorized:          true,
				AuthSubject:         "buildkite:org:acme",
				AuthIssuer:          "https://agent.buildkite.com",
				AuthAudience:        []string{"https://buildkite.com"},
				AuthExpirySecs:      fixedExpiry.Unix(),
				RequestedProfile:    "org/repo",
				RequestedRepository: "https://github.com/org/repo",
				VendedRepository:    "https://github.com/org/vended-repo",
				HashedToken:         "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
				Repositories:        []string{"org/repo"},
				Permissions:         []string{"contents:read"},
				ExpirySecs:          fixedExpiry.Unix(),
				ClaimsMatched:       []audit.ClaimMatch{{Claim: "pipeline_slug", Value: "main-pipeline"}},
				ClaimsFailed:        []audit.ClaimFailure{{Claim: "build_branch", Pattern: "release-.*", Value: "main"}},
				Error:               "partial failure",
			},
			matchers: []match.JSONMatcher{
				match.Any("authorization.expiryRemaining"),
				match.Any("token.expiryRemaining"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snaps.MatchJSON(t, serializeSlogEntry(tt.entry), tt.matchers...)
		})
	}
}

// TestSlogEntryAttrsStructure verifies the JSON field names produced by the
// array serialization helpers (slogMatchSlice / slogFailureSlice) by checking
// the parsed JSON structure directly, independent of snapshot state.
func TestSlogEntryAttrsStructure(t *testing.T) {
	entry := audit.Entry{
		RequestedRepository: "https://github.com/org/repo",
		ClaimsMatched: []audit.ClaimMatch{
			{Claim: "pipeline_slug", Value: "silk-prod"},
		},
		ClaimsFailed: []audit.ClaimFailure{
			{Claim: "build_branch", Pattern: "release-.*", Value: "main"},
		},
	}

	data := serializeSlogEntry(entry)
	var result map[string]any
	require.NoError(t, json.Unmarshal(data, &result))

	token, ok := result["token"].(map[string]any)
	require.True(t, ok, "token group should be present")

	matches, ok := token["matches"].([]any)
	require.True(t, ok, "matches should be an array")
	require.Len(t, matches, 1)
	m := matches[0].(map[string]any)
	assert.Equal(t, "pipeline_slug", m["claim"])
	assert.Equal(t, "silk-prod", m["value"])
	assert.NotContains(t, m, "pattern", "ClaimMatch should not have pattern field")

	failures, ok := token["attemptedPatterns"].([]any)
	require.True(t, ok, "attemptedPatterns should be an array")
	require.Len(t, failures, 1)
	f := failures[0].(map[string]any)
	assert.Equal(t, "build_branch", f["claim"])
	assert.Equal(t, "release-.*", f["pattern"])
	assert.Equal(t, "main", f["value"])

	// Verify time fields on authorization when AuthExpirySecs is set.
	entry2 := audit.Entry{
		Authorized:     true,
		AuthExpirySecs: time.Unix(1893456000, 0).Unix(),
	}
	data2 := serializeSlogEntry(entry2)
	var result2 map[string]any
	require.NoError(t, json.Unmarshal(data2, &result2))
	auth := result2["authorization"].(map[string]any)
	assert.Contains(t, auth, "expiry", "expiry should be set when AuthExpirySecs > 0")
	assert.Contains(t, auth, "expiryRemaining", "expiryRemaining should be set when AuthExpirySecs > 0")
}
