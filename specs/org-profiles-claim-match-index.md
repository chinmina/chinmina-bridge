# Organization Profiles with Claim-Matching

> **Quick Start**: This is the index for the claim-matching organization profiles specification. Navigate to detailed sections as needed.

## Overview

Enable Buildkite pipeline steps to request GitHub tokens with elevated permissions through organization-level profiles that use claim-based access control. Profiles specify which pipelines can use them via pattern matching on JWT claims.

**Business justification**: Enables use cases such as:
- Publishing to shared homebrew tap repositories
- Publishing packages to registries
- Creating releases across multiple related pipelines
- Cross-cutting deployment policies

**Scope**: Organization-level profiles only. Pipeline-level profiles are deferred to a future specification.

## Key Features

- Organization profiles with claim-based access control
- Match on JWT claims using exact strings or regex patterns
- Automatic pattern anchoring prevents bypass attacks
- Matcher-based implementation with zero-allocation interface
- Three-tier performance optimization (value → literal detection → regex)
- Graceful degradation when profiles fail validation
- 403 Forbidden when profile match conditions not met

## Design Summary

| Aspect | Implementation |
|--------|----------------|
| **Profile scope** | Organization-level only (explicit repository lists) |
| **Match types** | `value` (exact string) or `valuePattern` (RE2 regex) |
| **Anchoring** | Automatic `\A(?:...)\z` wrapping at compile time |
| **Performance** | Three-tier: value → literal detection → full regex |
| **Validation** | Failed profiles dropped at load with warning |
| **Security** | RE2 (no ReDoS) + anchoring (no bypass) + input validation |
| **Access control** | 403 Forbidden when match conditions not met |

## Request Flow

```
POST /organization/token/<profilename>
Authorization: Bearer <buildkite-jwt>
  ↓
Load profile → Validate JWT → Match claims → Generate token
  ↓
200 OK with token  OR  403 Forbidden (match failed)  OR  404 Not Found
```

## Detailed Sections

### [Configuration](./org-profiles-claim-match-config.md)
YAML configuration format, field definitions, request/response formats, and example profiles.

**When to read**: You need to understand how to configure profiles or what the API looks like.

### [Implementation](./org-profiles-claim-match-implementation.md)
Core implementation details: ClaimValueLookup interface, BuildkiteClaims struct, matcher implementations (ExactMatcher, RegexMatcher, CompositeMatcher).

**When to read**: You're implementing the feature or need to understand the internal architecture.

### [Validation & Error Handling](./org-profiles-claim-match-validation.md)
Configuration validation, runtime validation, graceful degradation, error responses, and profile resolution logic.

**When to read**: You need to understand how errors are handled or how validation works.

### [Testing Strategy](./org-profiles-claim-match-testing.md)
Unit test structure, integration tests, property-based tests, and test organization patterns.

**When to read**: You're writing tests for this feature.

### [Security & Audit](./org-profiles-claim-match-security.md)
Security analysis, bypass prevention, claim trust levels, audit logging structure, and remaining risks.

**When to read**: You need to understand security implications or audit log format.

### [Documentation & Guidance](./org-profiles-claim-match-docs.md)
User-facing documentation topics: governance, discoverability, pattern best practices, claim trust levels, and operational guidance.

**When to read**: You're writing user documentation or need to understand operational considerations.

## Quick Examples

### Exact Match (Fastest)
```yaml
- name: "production-deploy"
  match:
    - claim: pipeline_slug
      value: "silk-prod"
  repositories: [acme/silk]
  permissions: [contents:write]
```

### Regex with Alternation
```yaml
- name: "staging-deploy"
  match:
    - claim: pipeline_slug
      valuePattern: "(silk|cotton)-(staging|stg)"
  repositories: [acme/silk, acme/cotton]
  permissions: [contents:write]
```

### Multiple Match Rules (AND Logic)
```yaml
- name: "production-silk-only"
  match:
    - claim: pipeline_slug
      valuePattern: "silk-.*"
    - claim: build_branch
      value: "main"
  repositories: [acme/silk]
  permissions: [contents:write]
```

### No Match Rules (Available to All)
```yaml
- name: "shared-utilities-read"
  match: []
  repositories: [acme/shared-utilities]
  permissions: [contents:read]
```

## Out of Scope

The following features are explicitly **out of scope** and deferred to future work:

1. **Pipeline-level profiles**: Profiles scoped to specific pipelines
2. **Dynamic repository resolution**: `buildkite://pipeline-repository` special value
3. **Repository list defaults**: Defaulting to pipeline's own repository
4. **Caching optimization**: Specialized caching for profiles with dynamic repos

These will be addressed in a separate "Pipeline Profiles" specification.

## Open Questions

1. **CLI validation tool**: Should we add tooling for testing profiles before deployment?
   - Proposed: Consider for future enhancement, not critical for initial release

2. **Audit log detail**: Should logs include pattern details for successful matches?
   - Current: Only include claim/value pairs
   - Recommendation: Start simple, add if operators request it

3. **Profile limits**: Should we limit the number of profiles per organization?
   - Proposed: No limit initially. Add if performance issues arise.

4. **Empty match rules**: Should `match: []` be explicitly allowed or discouraged?
   - Proposed: Allow but document as requiring careful consideration
   - Audit logs flag these with empty matches array for monitoring
