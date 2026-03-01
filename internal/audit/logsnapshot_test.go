package audit_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/gkampitakis/go-snaps/match"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/rs/zerolog"
)

// fixedExpiry is a deterministic timestamp used in snapshot tests to avoid
// non-deterministic output. The expiryRemaining field must be matched with
// match.Any since it depends on time.Now().
var fixedExpiry = time.Unix(1893456000, 0) // 2029-12-31

func TestAuditEntrySnapshots(t *testing.T) {
	serialize := func(entry audit.Entry) []byte {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		logger.Log().EmbedObject(&entry).Send()
		return buf.Bytes()
	}

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
			name: "empty matches array",
			entry: audit.Entry{
				RequestedRepository: "https://github.com/org/repo",
				ClaimsMatched:       []audit.ClaimMatch{},
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
			snaps.MatchJSON(t, serialize(tt.entry), tt.matchers...)
		})
	}
}

func TestAuditEndEventSnapshot(t *testing.T) {
	// Call Middleware to trigger zerologConfiguration, which registers the
	// LevelFieldMarshalFunc that formats level 20 as "audit".
	_ = audit.Middleware()

	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	ctx := logger.WithContext(context.Background())
	ctx, entry := audit.Context(ctx)

	entry.Method = "POST"
	entry.Path = "/token"
	entry.Status = 200
	entry.SourceIP = "10.0.0.1"
	entry.UserAgent = "buildkite-agent/3.0"
	entry.Authorized = true
	entry.AuthSubject = "buildkite:org:acme"
	entry.AuthIssuer = "https://agent.buildkite.com"
	entry.AuthAudience = []string{"https://buildkite.com"}
	entry.AuthExpirySecs = fixedExpiry.Unix()
	entry.OrganizationSlug = "acme"
	entry.PipelineSlug = "main-pipeline"
	entry.JobID = "job-123"
	entry.BuildNumber = 42
	entry.BuildBranch = "main"
	entry.RequestedProfile = "org/repo"
	entry.RequestedRepository = "https://github.com/org/repo"
	entry.VendedRepository = "https://github.com/org/vended-repo"
	entry.Repositories = []string{"org/repo"}
	entry.Permissions = []string{"contents:read"}
	entry.ExpirySecs = fixedExpiry.Unix()
	entry.ClaimsMatched = []audit.ClaimMatch{{Claim: "pipeline_slug", Value: "main-pipeline"}}

	entry.End(ctx)()

	snaps.MatchJSON(t, buf.Bytes(),
		match.Any("authorization.expiryRemaining"),
		match.Any("token.expiryRemaining"),
	)
}
