# Security and Audit Logging

[← Back to Index](./org-profiles-claim-match-index.md)

## Security Analysis

### Bypass Prevention

Automatic `\A(?:...)\z` anchoring prevents all known bypass attacks:

| Attack | User Pattern | Anchored Pattern | Result |
|--------|--------------|------------------|--------|
| Alternation | `silk\|cotton` | `\A(?:silk\|cotton)\z` | ✓ Matches exactly "silk" or "cotton" |
| User anchors | `^silk$` | `\A(?:^silk$)\z` | ✓ Redundant but harmless |
| Multiline mode | `(?m)^silk$` | `\A(?:(?m)^silk$)\z` | ✓ Outer `\A\z` constrains to full string |
| Unanchored | `prod` | `\A(?:prod)\z` | ✓ Matches only "prod", not "not-prod" |

### Claim Trust Levels

| Claim | Trust Level | Notes |
|-------|-------------|-------|
| `pipeline_slug`, `pipeline_id` | High | Assigned by Buildkite |
| `build_number` | High | Assigned by Buildkite |
| `build_branch`, `build_tag` | Medium | User-controlled via git |
| `agent_tag:*` | Medium | Configured by operators |
| `cluster_id`, `cluster_name`, `queue_id`, `queue_key` | High | Assigned by Buildkite (cluster features) |

**Recommendation**: Use high-trust claims for authorization. Medium-trust claims acceptable for secondary conditions.

### Remaining Risks

| Risk | Example | Mitigation |
|------|---------|------------|
| Overly broad pattern | `.*prod.*` matches "reproduce" | Central review + audit logs |
| Typo in pattern | `(silk\|sil)` unintended match | Testing + audit logs |
| Empty match rules misuse | Profile accessible to all | Monitor audit logs for empty matches |

**Defense in depth**: Technical controls (anchoring, validation) + social controls (review, audit logs)

## Audit Logging

### Successful Access

```json
{
  "level": "audit",
  "event": "profile_accessed",
  "timestamp": "2025-01-15T10:30:45Z",
  "profile_name": "release-pipelines",
  "pipeline_slug": "silk-release",
  "build_number": 123,
  "matches": [
    {"claim": "pipeline_slug", "value": "silk-release"}
  ],
  "repositories": ["acme/shared-infra", "acme/release-tools"],
  "permissions": ["contents:write", "packages:write"]
}
```

### Access Denied (Match Failed)

```json
{
  "level": "error",
  "event": "profile_access_denied",
  "timestamp": "2025-01-15T10:31:00Z",
  "profile_name": "release-pipelines",
  "pipeline_slug": "silk-staging",
  "build_number": 124,
  "matches": [],
  "attempted_patterns": [
    {"claim": "pipeline_slug", "pattern": ".*-release", "value": "silk-staging", "matched": false}
  ],
  "error": "profile match conditions not met"
}
```

### Profile with No Match Rules

```json
{
  "level": "audit",
  "event": "profile_accessed",
  "timestamp": "2025-01-15T10:32:00Z",
  "profile_name": "shared-utilities-read",
  "pipeline_slug": "any-pipeline",
  "matches": [],
  "repositories": ["acme/shared-utilities"],
  "permissions": ["contents:read"]
}
```

**Key**: Empty `matches` array indicates no match rules (available to all).
