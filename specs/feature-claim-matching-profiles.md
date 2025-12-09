# Feature Documentation: Organization Profiles with Claim-Matching

## Executive Summary

This feature extends organization profiles in Chinmina Bridge to support claim-based access control. Profiles can now specify which Buildkite pipelines are authorized to use them by pattern matching on JWT claims (like pipeline slug or build branch).

**Business need**: There are limited use cases that organization profiles can satisfy without permission restrictions. This feature enables:
- Publishing to shared homebrew tap repositories
- Publishing packages to registries
- Creating releases across multiple related pipelines
- Cross-cutting deployment policies

**Key Benefits**:
- **Cross-cutting policies**: Single profile can cover multiple pipelines (e.g., all release pipelines)
- **Fine-grained control**: Match on multiple conditions (pipeline + branch + agent tags)
- **Strong security**: Automatic pattern anchoring prevents bypass attacks
- **Operational visibility**: Audit logs capture which claims matched for non-repudiation
- **Flexible patterns**: Regex matching enables alternation and precise matching rules

**Status**: Ready for implementation
**Scope**: Organization-level profiles only (pipeline-level profiles deferred to future work)

## Use Cases

### 1. Release Pipeline Access

**Scenario**: All pipelines ending in "-release" should have permission to publish packages.

**Configuration**:
```yaml
organization:
  profiles:
    - name: "release-publisher"
      match:
        - claim: pipeline_slug
          valuePattern: ".*-release"
      repositories: [acme/release-tools, acme/shared-infra]
      permissions: [contents:write, packages:write]
```

**Benefit**: Add new release pipelines without updating profile configuration.

### 2. Production-Only Deployment

**Scenario**: Only specific production pipelines on the main branch can deploy infrastructure.

**Configuration**:
```yaml
organization:
  profiles:
    - name: "prod-deploy"
      match:
        - claim: pipeline_slug
          valuePattern: "(silk|cotton)-prod"
        - claim: build_branch
          value: "main"
      repositories: [acme/infra]
      permissions: [contents:write, deployments:write]
```

**Benefit**: Enforce both pipeline and branch requirements in a single policy.

### 3. Baseline Shared Access

**Scenario**: All pipelines should have read access to shared utilities.

**Configuration**:
```yaml
organization:
  profiles:
    - name: "shared-utilities"
      match: []  # No conditions = available to all
      repositories: [acme/shared-utilities]
      permissions: [contents:read]
```

**Benefit**: Simplified baseline access without per-pipeline configuration.

## Configuration Reference

### Profile Structure

```yaml
organization:
  defaults:
    permissions: [contents:read]  # Existing: default permissions

  profiles:
    - name: "profile-name"  # Required: unique profile identifier
      match:  # Optional: empty = matches all pipelines
        - claim: "claim-name"  # Required: JWT claim to match
          value: "exact-value"  # Option 1: Exact string match
          # OR
          valuePattern: "regex-pattern"  # Option 2: RE2 regex match
      repositories:  # Required: list of owner/repo
        - owner/repo1
        - owner/repo2
      permissions:  # Required: GitHub token permissions
        - contents:write
        - packages:write
```

### Match Rules

**Claim Names** (allowed for matching):
- `pipeline_slug`: Pipeline's slug (e.g., "silk-prod")
- `pipeline_id`: Pipeline UUID
- `build_number`: Build number (converted to string)
- `build_branch`: Git branch name
- `build_tag`: Git tag (if present)
- `build_commit`: Git commit SHA
- `cluster_id`, `cluster_name`: Cluster identifiers (if using clusters)
- `queue_id`, `queue_key`: Queue identifiers (if using clusters)
- `agent_tag:NAME`: Dynamic agent tags (e.g., `agent_tag:queue`)

**Note**: The following JWT claims are present but NOT available for matching: `build_id`, `job_id`, `agent_id`, `step_key`

**Match Types**:

1. **Exact match** (`value`): Fastest, recommended for known values
   ```yaml
   match:
     - claim: pipeline_slug
       value: "silk-prod"  # Matches only "silk-prod"
   ```

2. **Regex match** (`valuePattern`): Flexible, for patterns
   ```yaml
   match:
     - claim: pipeline_slug
       valuePattern: ".*-release"  # Matches any pipeline ending in "-release"
   ```
   - Patterns are automatically anchored (full-string match required)
   - RE2 regex syntax (no backtracking, safe from ReDoS)
   - Purely literal patterns optimized to exact match performance

3. **Multiple conditions**: All must match (AND logic)
   ```yaml
   match:
     - claim: pipeline_slug
       valuePattern: "silk-.*"
     - claim: build_branch
       value: "main"
   # Both conditions required
   ```

4. **No conditions**: Matches all pipelines
   ```yaml
   match: []  # Available to any pipeline
   ```

## Request Flow

### Successful Request

**Request**:
```
POST /organization/token/release-publisher
Authorization: Bearer <buildkite-jwt-token>
```

**Process**:
1. Extract profile name from URL: "release-publisher"
2. Look up profile in configuration
3. Evaluate match rules against JWT claims
4. If match succeeds → vend token with profile's repos + permissions
5. Return token to pipeline

**Response** (200 OK):
```json
{
  "token": "ghs_...",
  "expires_at": "2025-01-15T11:30:00Z",
  "repositories": ["acme/release-tools", "acme/shared-infra"],
  "permissions": {"contents": "write", "packages": "write"}
}
```

### Failed Request (Match Conditions Not Met)

**Scenario**: Pipeline `silk-staging` requests profile "release-publisher" (which requires pipeline slug ending in "-release")

**Response** (403 Forbidden):
```json
{
  "error": "access denied: profile match conditions not met"
}
```

**Audit Log**:
```json
{
  "level": "error",
  "event": "profile_access_denied",
  "profile_name": "release-publisher",
  "pipeline_slug": "silk-staging",
  "matches": [],
  "attempted_patterns": [
    {"claim": "pipeline_slug", "pattern": ".*-release", "value": "silk-staging", "matched": false}
  ]
}
```

### Failed Request (Profile Not Found)

**Response** (404 Not Found):
```json
{
  "error": "profile not found"
}
```

### Failed Request (Profile Invalid)

**Scenario**: Profile failed validation at service startup (e.g., invalid regex)

**Response** (404 Not Found):
```json
{
  "error": "profile unavailable: validation failed"
}
```

## Security Model

### Automatic Pattern Anchoring

All regex patterns are automatically wrapped with `\A(?:...)\z` to enforce full-string matching:

**User provides**: `.*-release`
**System compiles**: `\A(?:.*-release)\z`

This prevents bypass attacks:
- ✓ Pattern `prod` matches only "prod", not "not-prod"
- ✓ Pattern `silk|cotton` matches exactly "silk" or "cotton", not substrings
- ✓ User-supplied anchors (`^...$`) are redundant but harmless

### Claim Trust Levels

| Claim | Trust Level | Recommendation |
|-------|-------------|----------------|
| `pipeline_slug`, `pipeline_id`, `build_number` | High | Safe for authorization |
| `cluster_id`, `queue_id` | High | Safe for authorization (cluster features) |
| `build_branch`, `build_tag` | Medium | Use for secondary conditions |
| `agent_tag:*` | Medium | Operator-controlled |

**Recommendation**: Use high-trust claims (pipeline_slug, pipeline_id, build_number) as primary authorization factors.

### Authorization Model

- **Profile name must be explicitly requested**: Intentionality is required (no automatic matching)
- **403 Forbidden on match failure**: Clear authorization signal vs 404 for missing profiles
- **Audit logs capture match details**: Non-repudiation for access attempts

## Validation and Error Handling

### Config Load Time

**Validations**:
- Profile names must be unique
- Match rules must have exactly one of `value` or `valuePattern`
- Claim names must be from allowed list
- Regex patterns must compile successfully
- Repositories list must be non-empty
- Permissions list must be non-empty

**Graceful Degradation**:
- Invalid profiles are **dropped** at load time with warning log
- Service **continues to start** with remaining valid profiles
- Accessing dropped profile returns 404 "profile unavailable: validation failed"

**Example Warning Log**:
```
WARN  profile validation failed, profile unavailable
      profile=broken-profile
      error="invalid regex pattern: missing closing ]: `[invalid(regex`"
```

### Request Time

**Validations**:
- JWT must be valid and signed by Buildkite
- Claim values must not contain control characters or whitespace
- Profile must exist and not be in failed state
- Match conditions must be satisfied (403 if not)

## Migration Guide

### Existing Organization Profiles

Existing organization profiles continue to work without changes. Claim-matching is an **additive feature**.

**Before** (static profile):
```yaml
organization:
  profiles:
    - name: "package-publisher"
      repositories: [acme/shared-infra]
      permissions: [packages:write]
```
This profile is available to **all** pipelines (no match rules).

**After** (add claim matching):
```yaml
organization:
  profiles:
    - name: "package-publisher"
      match:  # NEW: restrict to specific pipelines
        - claim: pipeline_slug
          valuePattern: ".*-(release|prod)"
      repositories: [acme/shared-infra]
      permissions: [packages:write]
```
Now only pipelines ending in "-release" or "-prod" can access it.

### Adoption Path

1. **Add profiles with claim matching** to organization configuration
2. **Test access** from matching and non-matching pipelines
3. **Monitor audit logs** to verify expected behavior
4. **Iterate** on patterns based on audit log findings

## Monitoring and Observability

### Audit Logs

**Successful Access**:
```json
{
  "level": "audit",
  "event": "profile_accessed",
  "profile_name": "release-publisher",
  "pipeline_slug": "silk-release",
  "build_number": 123,
  "matches": [
    {"claim": "pipeline_slug", "value": "silk-release"}
  ],
  "repositories": ["acme/shared-infra"],
  "permissions": ["contents:write", "packages:write"]
}
```

**Access Denied**:
```json
{
  "level": "error",
  "event": "profile_access_denied",
  "profile_name": "release-publisher",
  "pipeline_slug": "silk-staging",
  "matches": [],
  "attempted_patterns": [
    {"claim": "pipeline_slug", "pattern": ".*-release", "value": "silk-staging", "matched": false}
  ],
  "error": "profile match conditions not met"
}
```

**Profile with No Match Rules** (available to all):
```json
{
  "level": "audit",
  "event": "profile_accessed",
  "profile_name": "shared-utilities",
  "matches": [],
  "repositories": ["acme/shared-utilities"],
  "permissions": ["contents:read"]
}
```
Note: Empty `matches` array indicates no match rules (available to all pipelines).

### Key Metrics

**Recommended monitoring**:
- Profile access denials (403 responses)
- Profiles with empty match rules (monitor `matches: []` in audit logs)
- Failed profile loads at startup (watch for validation warnings)
- Access patterns per profile (which pipelines use which profiles)

## Performance Characteristics

### Match Performance

**Three-tier optimization**:
1. **Exact match** (`value` field): O(n) string comparison, ~50-100ns
2. **Literal pattern**: Regex detected as literal via `regexp.LiteralPrefix()`, same as exact match
3. **Regex pattern**: RE2 engine, O(n) linear time, ~1-5µs depending on complexity

**Example**:
- Pattern `silk-prod` (as `valuePattern`) → optimized to exact match
- Pattern `(silk|cotton)-prod` → uses regex engine

### Caching

Organization profiles use existing token caching (45-minute TTL):
- Cache key: `org:<profile-name>`
- No per-pipeline cache segmentation in this implementation
- Future: Pipeline profiles will require per-pipeline cache keys

## Limitations and Future Work

### Current Limitations

1. **Organization-level only**: Profiles apply organization-wide, not per-pipeline
2. **Static repository lists**: Cannot include "current pipeline's repository" dynamically
3. **No OR logic**: Multiple match rules use AND logic (all must match)
4. **No negation**: Cannot express "all except X"

### Future Enhancements

**Pipeline Profiles** (future specification):
- Profiles scoped to specific pipelines (Option 2 from DACI)
- Dynamic repository resolution (`buildkite://pipeline-repository`)
- Repository list defaulting to pipeline's own repo
- Specialized caching for dynamic repos

## Troubleshooting

### Problem: Profile returns 403 (access denied)

**Cause**: Pipeline doesn't match profile's conditions

**Resolution**:
1. Check audit logs for `attempted_patterns` to see what failed
2. Verify pipeline's claim values (pipeline_slug, build_branch, etc.)
3. Test pattern against claim value using regex tool
4. Update profile's match conditions if needed

### Problem: Profile returns 404 (unavailable: validation failed)

**Cause**: Profile failed validation at service startup

**Resolution**:
1. Check service startup logs for validation warnings
2. Fix invalid regex pattern, claim name, or configuration structure
3. Restart service to reload profiles
4. Verify profile loads successfully (no warnings)

### Problem: Profile matches too broadly

**Cause**: Overly broad regex pattern (e.g., `.*prod.*`)

**Resolution**:
1. Review audit logs to see unexpected matches
2. Make pattern more specific (e.g., `.*-prod$` instead of `.*prod.*`)
3. Test pattern with both expected and unexpected values
4. Note: Patterns are automatically anchored, but `.*` can still be overly broad

### Problem: Empty matches array in audit logs

**Cause**: Profile has no match rules (`match: []`)

**This is expected** if the profile intentionally allows all pipelines. If unintentional:
1. Review profile configuration
2. Add appropriate match rules
3. Profiles without match rules are accessible by all pipelines

## Questions and Answers

**Q: Can I use wildcards like `*-prod` in patterns?**
A: No. Use RE2 regex syntax instead: `.*-prod` (where `.*` matches any characters)

**Q: Are patterns case-sensitive?**
A: Yes. Pattern `Prod` won't match pipeline slug "prod".

**Q: Can I match on multiple values for one claim (OR logic)?**
A: Yes, use regex alternation: `valuePattern: "(silk|cotton|wool)-prod"`

**Q: What happens if two profiles match the same pipeline?**
A: Pipeline must explicitly request one profile by name. No ambiguity.

**Q: Can I test patterns before deploying?**
A: Currently, test in non-production environment. CLI validation tool is future enhancement.

**Q: What claims should I match on for authorization?**
A: Use high-trust claims like `pipeline_slug`, `pipeline_id`, or `build_number` as primary factors. `build_branch`, `build_tag`, and `agent_tag:*` are acceptable as secondary conditions. Note that `build_id`, `job_id`, `agent_id`, and `step_key` are NOT available for matching.

## Additional Resources

- **Technical Specification**: `organization-profiles-claim-match-spec.md` - Implementation details
- **Decision Document**: `repo-profiles-daci.md` - Options analysis and security evaluation
- **Existing Documentation**: Organization profiles configuration reference
