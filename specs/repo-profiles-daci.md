# DACI: Elevated Token Permissions for Buildkite Steps

## Decision Summary

Enable Buildkite pipeline steps to request GitHub tokens with permissions beyond the default `contents:read`.

## DACI Roles

| Role | Person | Notes |
|------|--------|-------|
| **Driver** | TBD | Responsible for driving the decision to completion |
| **Approver** | TBD | Final decision authority |
| **Contributors** | TBD | Provide input and expertise |
| **Informed** | TBD | Notified of the decision |

## Status

**Draft** — Evaluating options

## Context

Chinmina Bridge currently vends GitHub tokens with default permissions (`contents:read` or configured defaults). Some pipelines require elevated permissions for legitimate use cases:

- Writing packages to GitHub Packages registry
- Creating releases
- Pushing commits (e.g., automated version bumps)
- Managing pull requests

The current system has no mechanism for a pipeline step to request elevated permissions in a controlled way.

### Current Architecture

| Profile Type | Permission Source | Status |
|--------------|-------------------|--------|
| `repo:default` | `organization.defaults.permissions` | Implemented |
| `repo:<name>` | Not supported | Returns error |
| `org:<name>` | Profile's `permissions` array | Implemented |

Organization profiles (`org:*`) allow elevated permissions but grant access to repositories outside the pipeline's own repository, which is a different use case.

## Options

### Option 1: Organization-Level Permission Allow-List

**Mechanism**: Define an allow-list of permissions at the organization level. Any token request can include a comma-separated list of requested permissions. Permissions are granted if they appear in the allow-list.

**Configuration example**:
```yaml
organization:
  allowed_permissions:
    - contents:read
    - contents:write
    - packages:read
    - packages:write
```

**Request format**: `repo:default?permissions=contents:write,packages:write`

**Pros**:
- Simple to implement
- Simple to configure
- No per-pipeline configuration required

**Cons**:
- Any pipeline can request any allowed permission
- No scope isolation between pipelines
- Privilege creep as allow-list grows
- Cannot answer "which pipelines should have write access?"
- Accidental elevation possible via misconfigured steps

### Option 2: Pipeline-Level Named Profiles

**Mechanism**: Define profiles scoped to specific pipelines. Each profile has a name and permission set. Pipelines request a profile by name.

**Configuration example**:
```yaml
organization:
  defaults:
    permissions: [contents:read]

  pipelines:
    - id: "01234567-89ab-cdef-0123-456789abcdef"  # pipeline_id
      slug: "release-automation"                   # for documentation
      profiles:
        - name: "release"
          permissions: [contents:write, packages:write]
        - name: "read-packages"
          permissions: [contents:read, packages:read]
```

**Request format**: `repo:release`

**Pros**:
- Strong scope isolation — only specified pipeline can use its profiles
- Clear audit trail — profiles document intended permissions per pipeline
- Supports least-privilege — different profiles for different steps
- Low misconfiguration risk

**Cons**:
- More configuration required per pipeline
- Pipeline ID vs slug: slug can change, ID is immutable
- Orphaned profiles when pipelines are deleted

### Option 3: Claim-Matching Profiles

**Mechanism**: Define profiles with match expressions on JWT claims. A profile applies if all its match conditions are satisfied.

**Configuration example**:
```yaml
organization:
  defaults:
    permissions: [contents:read]

  profiles:
    - name: "silk-release"
      match:
        - claim: pipeline_slug
          pattern: "silk-*"
      permissions: [contents:write, packages:write]

    - name: "bridge-deploy"
      match:
        - claim: repository
          pattern: "https://github.com/chinmina/*-bridge"
      permissions: [contents:write]
```

**Request format**: `repo:silk-release`

**Pattern matching**: Simple glob-style wildcards only (`*` matches any characters). Not regex.

**Pros**:
- Flexible — single profile can cover multiple pipelines
- Good for cross-cutting policies (e.g., all release pipelines)
- Centralizes policy for related pipelines

**Cons**:
- Wildcards increase attack surface (new matching entities inherit permissions)
- Some claims are user-controlled (`build_branch`) — unsafe to match on
- Multiple matching profiles require precedence rules
- Higher complexity increases misconfiguration risk

### Option 3a: Organization Profiles with Claim-Matching

**Variant**: Extend organization profiles with claim-based access control using pattern matching.

**Scope**: Organization-level profiles only. Explicit repository lists. Dynamic repository resolution (`buildkite://pipeline-repository`) deferred to future "Pipeline Profiles" specification.

**Design summary**:
- Organization profiles with claim matching (uses existing `/organization/token/<profile>` endpoint)
- Two field types: `value` (exact match) and `valuePattern` (regex match)
- Automatic anchoring: Patterns wrapped in `\A(?:...)\z` at compile time
- Matcher-based implementation with zero-allocation interface
- Performance: Three-tier optimization (value → literal detection → full regex)
- Resilience: Invalid profiles dropped at load with warning, not startup failure
- Access control: 403 Forbidden when match conditions not met

**Key features**:
- **Flexibility**: Cross-cutting policies (e.g., all pipelines ending in "-release")
- **Security**: Automatic `\A(?:...)\z` wrapping prevents bypass attacks (alternation, multiline mode)
- **Performance**: `regexp.LiteralPrefix()` optimizes literal patterns to string comparison
- **Resilience**: Graceful degradation when profiles fail validation
- **Non-repudiation**: Audit logs include matched claim values for accountability

**Configuration example**:
```yaml
organization:
  profiles:
    # Exact string match (fastest)
    - name: "production-deploy"
      match:
        - claim: pipeline_slug
          value: "silk-prod"
      repositories: [acme/silk]
      permissions: [contents:write]

    # Regex with alternatives
    - name: "staging-deploy"
      match:
        - claim: pipeline_slug
          valuePattern: "(silk|cotton)-(staging|stg)"
      repositories: [acme/silk, acme/cotton]
      permissions: [contents:write]

    # Regex with wildcard (cross-cutting)
    - name: "release-pipelines"
      match:
        - claim: pipeline_slug
          valuePattern: ".*-release"
      repositories: [acme/shared-infra]
      permissions: [contents:write, packages:write]
```

**Request format**: `POST /organization/token/release-pipelines`

**Pros**:
- Flexible cross-cutting policies
- Strong security via automatic anchoring
- Three-tier performance optimization
- Graceful degradation
- 403 error provides clear authorization signal

**Cons**:
- Requires regex knowledge for auditing
- Overly broad patterns require social controls (central review)
- More complex than Option 2

**Detailed design**: See `organization-profiles-claim-match-spec.md` for complete technical specification.

## Security Evaluation

### Threat Model

| Threat | Description |
|--------|-------------|
| Compromised pipeline | Attacker gains control of a low-privilege pipeline and attempts to escalate |
| Malicious actor | Internal actor creates pipeline/repo to match elevated permission rules |
| Misconfiguration | Operator accidentally grants excessive permissions |
| Privilege creep | Permissions accumulate over time beyond what's needed |

### Option Comparison

| Criterion | Option 1: Allow-List | Option 2: Pipeline Profiles | Option 3: Wildcards | Option 3a: Regex (Restricted) |
|-----------|---------------------|----------------------------|---------------------|-------------------------------|
| **Isolation** | Poor — any pipeline can request | Good — scoped to pipeline | Medium — depends on pattern | Medium-High — precise boundaries |
| **Least Privilege** | Poor — all-or-nothing | Good — explicit per-pipeline | Medium — wildcards may over-grant | High — if patterns well-crafted |
| **Audit Trail** | Poor — no intent captured | Good — explicit config | Medium — patterns document intent | Medium — requires regex knowledge |
| **Misconfiguration Risk** | High | Low | Medium | Medium-High |
| **Operational Simplicity** | High | Medium | Medium | Low — regex complexity |
| **Auditability** | High | High | High — wildcards are simple | Medium — regex requires expertise |
| **Scalability** | High | Medium — grows with pipelines | High — patterns reduce config | High — patterns reduce config |

### Claim Trust Levels

For Option 3/3a, claims have different trust levels:

| Claim | Trust Level | Notes | Allowed for Matching |
|-------|-------------|-------|---------------------|
| `pipeline_slug` | High | Assigned by Buildkite, can be renamed | ✓ Yes |
| `pipeline_id` | High | Immutable, assigned by Buildkite | ✓ Yes |
| `build_number` | High | Assigned by Buildkite | ✓ Yes |
| `cluster_id`, `queue_id` | High | Assigned by Buildkite (cluster features) | ✓ Yes |
| `build_branch` | Medium | User-controlled via git | ✓ Yes (secondary) |
| `build_tag` | Medium | User-controlled via git | ✓ Yes (secondary) |
| `agent_tag:*` | Medium | Configured by operators | ✓ Yes (secondary) |
| `organization_slug` | High | Validated against config | ❌ No (already validated) |
| `job_id`, `agent_id`, `build_id` | High | Assigned by Buildkite | ❌ No (not needed) |
| `step_key` | Low | Defined in pipeline YAML | ❌ No (user-controlled) |

**Recommendation**: Use high-trust claims (pipeline_slug, pipeline_id, build_number) for primary authorization. Medium-trust claims acceptable as secondary conditions.

### Security Ranking

1. **Option 2** — Strongest security posture. Clear isolation boundaries, explicit configuration, easy to audit.
2. **Option 3a (Regex with automatic anchoring)** — Strong with pragmatic implementation. Automatic `\A(?:...)\z` wrapping prevents bypass attacks. Requires high-trust claims only and central registry review for overly broad patterns. Higher precision than wildcards, moderate audit complexity.
3. **Option 3 (Wildcards)** — Acceptable with restrictions on matchable claims. Simpler than regex, easier to audit, but less precise boundaries.
4. **Option 1** — Weakest. Defeats least-privilege principles.

**Key insight on regex**: RE2 eliminates ReDoS attacks, and automatic anchoring eliminates bypass attacks (alternation, multiline mode, missing anchors). Remaining risk is overly broad patterns (e.g., `.*prod.*`), which is addressable through central registry review and audit logging. The pragmatic approach provides strong security without implementation complexity.

## Recommendation

**Option 2 (Pipeline-Level Named Profiles)** as the primary mechanism.

**Rationale**:
- Provides strong isolation without complexity
- Clear audit trail of intended permissions
- Low risk of accidental over-granting
- Matches the existing profile model (`org:*` profiles)

**Future consideration**: Option 3 could be added later for cross-cutting policies, using Option 2's explicit profiles as the baseline and claim-matching as an overlay.

**Regex vs Wildcards**: If Option 3 is implemented, wildcards are recommended for initial release due to simplicity and auditability. Regex support (Option 3a) could be added later as an advanced feature with mandatory validation rules.

**Detailed design**: See `repository-profiles-spec.md` for complete technical specification of Option 2.

---

## Implementation Considerations

See `repository-profiles-spec.md` for detailed technical design, including:

- Data structures and configuration format
- Profile resolution logic and error handling
- Testing strategy and implementation phases
- Plugin changes required
- Documentation updates
- Migration path and backward compatibility

**Key implementation notes** (Option 2):
- Zero-impact deployment (all changes are optional/backward compatible)
- Existing `repo:default` behavior unchanged
- Profile lookup scoped to requesting pipeline for isolation
- 404-style errors prevent information leakage

### If Implementing Option 3a (Claim-Matching with Patterns)

See `organization-profiles-claim-match-spec.md` for detailed technical design, including:

- Configuration format with `value` and `valuePattern` fields
- Data structures (MatchRule with performance optimizations)
- Implementation algorithms (compilation, matching, validation)
- Graceful degradation (invalid profiles tracked in ProfileConfig at load time)
- Performance optimizations (`regexp.LiteralPrefix()` for literal patterns)
- Error handling and HTTP response codes
- Testing strategy
- Audit logging format
- Security analysis and bypass prevention
- Examples and use cases

**Key implementation notes** (Option 3a):
- Automatic anchoring: `\A(?:...)\z` prevents bypass attacks
- Graceful degradation: Invalid profiles dropped at load, service starts normally
- Three-tier performance: value → literal optimization → full regex
- Invalid profiles return "profile unavailable: validation failed" (HTTP 404)

## Open Questions

1. ~~Should we use `pipeline_slug` or `pipeline_id` as the identifier?~~
   - **Decided**: Use `pipeline_slug` for simpler configuration. ID matching can be added later if needed.

2. ~~Should pipelines have single or multiple profiles?~~
   - **Decided**: Multiple profiles per pipeline to support least-privilege per step.

3. Should there be governance controls (e.g., maximum permissions, approval workflows)?
   - **Proposed**: Start simple. The GitHub App's installation permissions are the ceiling. Add governance later if needed.

4. Should we proactively implement Option 3 (claim-matching) alongside Option 2?
   - **Proposed**: No. Implement Option 2 first, gather feedback, then consider Option 3 as an enhancement.

5. If implementing Option 3, should we support regex or only wildcards?
   - **Wildcards**: Simpler, easier to audit, lower misconfiguration risk
   - **Regex with restrictions**: Higher precision, better boundary control, but requires mandatory validation
   - **Proposed**: Start with wildcards. Add regex as advanced feature later with mandatory anchor requirements and claim restrictions.

## Decision

**Status**: Approved — Option 3a selected for implementation

**Chosen approach**: Organization Profiles with Claim-Matching (Option 3a)

**Rationale**:
- Provides flexible cross-cutting policies for multiple pipelines
- Strong security via automatic pattern anchoring
- Manageable initial scope (organization-level only)
- Pipeline-level profiles (Option 2) deferred as future enhancement
- Dynamic repository resolution deferred as future enhancement

**Implementation specification**: See `organization-profiles-claim-match-spec.md`

**Next steps**:
1. Implement per `organization-profiles-claim-match-spec.md`
2. Update documentation per `feature-claim-matching-profiles.md`
3. Future: Consider Option 2 (Pipeline Profiles) for even stronger isolation

## Appendix: JWT Claims Reference

From Buildkite OIDC documentation, these claims are available in the JWT:

| Claim | Description | Example | Available for Matching |
|-------|-------------|---------|----------------------|
| `organization_slug` | Buildkite org slug | `acme-corp` | ❌ No (validated in config) |
| `pipeline_slug` | Pipeline slug | `my-pipeline` | ✓ Yes |
| `pipeline_id` | Pipeline UUID | `01234567-...` | ✓ Yes |
| `build_number` | Build number | `123` | ✓ Yes |
| `build_branch` | Git branch | `main` | ✓ Yes |
| `build_tag` | Git tag (if present) | `v1.0.0` | ✓ Yes |
| `build_commit` | Git commit SHA | `abc123...` | ✓ Yes |
| `build_id` | Build UUID | `01234567-...` | ❌ No |
| `job_id` | Job UUID | `01234567-...` | ❌ No |
| `agent_id` | Agent UUID | `01234567-...` | ❌ No |
| `step_key` | Step key (if defined) | `deploy` | ❌ No |
| `cluster_id`, `cluster_name` | Cluster identifiers | `01234567-...`, `default` | ✓ Yes |
| `queue_id`, `queue_key` | Queue identifiers | `01234567-...`, `runners` | ✓ Yes |
| `agent_tag:*` | Dynamic agent tags | `agent_tag:queue` = `runners` | ✓ Yes |

**Note**: Only claims marked "✓ Yes" can be used in profile match rules. Other claims are present in the JWT but not exposed for matching.
