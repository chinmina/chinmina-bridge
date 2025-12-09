# Technical Specification: Pipeline-Level Repository Profiles

## Overview

Enable Buildkite pipeline steps to request GitHub tokens with elevated permissions through named, pipeline-scoped profiles.

**Request format**: `repo:profile-name` (e.g., `repo:release`, `repo:publish`)

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Pipeline identifier | `pipeline_slug` | Simpler configuration. ID matching can be added later. All requests are audited. |
| Request format | `repo:profile-name` | Consistent with existing `repo:default` and `org:profile-name` patterns |
| Auth failure behavior | 404-style error | Don't reveal that a profile exists for a different pipeline |
| Profiles per pipeline | Multiple | Supports least-privilege: different profiles for different steps (e.g., `release`, `packages`) |

## Configuration Format

```yaml
organization:
  defaults:
    permissions: [contents:read]

  pipelines:
    - slug: "release-automation"
      profiles:
        - name: "release"
          permissions: [contents:write, packages:write]
        - name: "read-packages"
          permissions: [packages:read]

    - slug: "documentation-builder"
      profiles:
        - name: "pages"
          permissions: [contents:write, pages:write]
```

### Field Definitions

| Field | Required | Description |
|-------|----------|-------------|
| `pipelines` | No | List of pipeline configurations |
| `pipelines[].slug` | Yes | Buildkite pipeline slug (from JWT `pipeline_slug` claim) |
| `pipelines[].profiles` | Yes | List of named profiles for this pipeline |
| `pipelines[].profiles[].name` | Yes | Profile name (used in `repo:<name>` requests) |
| `pipelines[].profiles[].permissions` | Yes | List of GitHub permissions (e.g., `contents:write`) |

### Validation Rules

Enforced at config load time:

- `slug` must be non-empty
- `name` must be non-empty and unique within the pipeline
- `name` must not be `default` (reserved for organization defaults)
- `permissions` must be non-empty and contain valid permission strings

## Data Structures

### Extend ProfileConfig

**File**: `internal/github/profile.go`

```go
type ProfileConfig struct {
    Organization struct {
        Defaults struct {
            Permissions []string `yaml:"permissions"`
        } `yaml:"defaults"`
        Profiles []Profile `yaml:"profiles"`

        // NEW: Pipeline-scoped profiles
        Pipelines []PipelineConfig `yaml:"pipelines"`
    } `yaml:"organization"`
}
```

### New Types

```go
// PipelineConfig defines a pipeline and its available profiles
type PipelineConfig struct {
    Slug     string            `yaml:"slug"`
    Profiles []PipelineProfile `yaml:"profiles"`
}

// PipelineProfile defines a named permission set for a pipeline
// Note: No Repositories field - profiles always apply to the pipeline's own repository
type PipelineProfile struct {
    Name        string   `yaml:"name"`
    Permissions []string `yaml:"permissions"`
}
```

### ProfileStore Method

```go
// GetPipelineProfile retrieves a named profile for a specific pipeline
// Returns "profile not found" error if the pipeline or profile doesn't exist
func (p *ProfileStore) GetPipelineProfile(pipelineSlug, profileName string) (PipelineProfile, error) {
    p.mu.Lock()
    defer p.mu.Unlock()

    for _, pipeline := range p.config.Organization.Pipelines {
        if pipeline.Slug == pipelineSlug {
            for _, profile := range pipeline.Profiles {
                if profile.Name == profileName {
                    return profile, nil
                }
            }
        }
    }

    return PipelineProfile{}, errors.New("profile not found")
}
```

## Request Flow

```
1. Request arrives: POST /token with route param "repo:release"

2. Parse ProfileRef (handlers.go):
   - Type: ProfileTypeRepo
   - Name: "release"
   - PipelineSlug: (extracted from JWT claims)

3. Lookup profile (repovendor.go):
   - If name == "default": use organization defaults
   - Else: call profileStore.GetPipelineProfile(claims.PipelineSlug, name)
   - If not found → return error

4. Vend token (repovendor.go → github/token.go):
   - Repository: pipeline's repository (from Buildkite API)
   - Permissions: profile's permissions
   - Call github.Client.CreateAccessToken()

5. Return token
```

## Profile Resolution Logic

```go
func resolveRepoProfile(claims BuildkiteClaims, profileName string, config ProfileConfig) ([]string, error) {
    // Special case: "default" uses organization defaults
    if profileName == "default" {
        return config.GetDefaultPermissions(), nil
    }

    // Find pipeline matching the requesting pipeline's slug
    for _, pipeline := range config.Organization.Pipelines {
        if pipeline.Slug == claims.PipelineSlug {
            // Find requested profile within that pipeline
            for _, profile := range pipeline.Profiles {
                if profile.Name == profileName {
                    return profile.Permissions, nil
                }
            }
        }
    }

    // Not found - don't reveal whether pipeline exists or profile exists
    return nil, errors.New("profile not found")
}
```

### Key Behaviors

- Profile lookup is scoped to the requesting pipeline's slug
- A profile named "release" in pipeline A is invisible to pipeline B
- Unknown profile → generic "profile not found" error (no information leakage)
- `repo:default` continues to work as before (uses `organization.defaults.permissions`)

## Error Cases

| Scenario | HTTP Status | Response |
|----------|-------------|----------|
| Profile exists, pipeline matches | 200 | Token with profile permissions |
| Profile exists, pipeline doesn't match | 404 | `{"error": "profile not found"}` |
| Profile doesn't exist | 404 | `{"error": "profile not found"}` |
| Pipeline has no profiles configured | 404 | `{"error": "profile not found"}` |
| `repo:default` requested | 200 | Token with default permissions |
| Invalid permission in profile | 500 | `{"error": "invalid profile configuration"}` |

**Security note**: All failure cases return the same generic error to prevent information leakage about profile existence or pipeline configuration.

## Audit Logging

All token requests are already audited. For profile requests, enhance the audit entry:

```json
{
  "level": "audit",
  "profile_type": "repo",
  "profile_name": "release",
  "pipeline_slug": "release-automation",
  "permissions": ["contents:write", "packages:write"],
  "repository": "my-org/my-repo",
  "build_number": 123,
  "job_id": "01234567-89ab-cdef-0123-456789abcdef"
}
```

**Fields**:
- `profile_name`: The requested profile (or "default")
- `permissions`: The resolved permissions array
- Existing fields: pipeline_slug, repository, build_number, job_id, etc.

## Plugin Changes

**Repository**: `chinmina-github-buildkite-plugin`

### New Parameter

Add `profile` parameter to plugin configuration:

```yaml
steps:
  - label: "Deploy"
    plugins:
      - chinmina/github#v1:
          profile: release  # NEW: Optional profile name
```

### Plugin Behavior

- If `profile` is not specified: use `repo:default` (current behavior)
- If `profile` is specified: use `repo:<profile>` in the token request

### Plugin Implementation

```bash
# Construct profile ref
if [[ -n "${BUILDKITE_PLUGIN_CHINMINA_GITHUB_PROFILE:-}" ]]; then
  PROFILE_REF="repo:${BUILDKITE_PLUGIN_CHINMINA_GITHUB_PROFILE}"
else
  PROFILE_REF="repo:default"
fi

# Make token request
curl -X POST "${CHINMINA_URL}/token/${PROFILE_REF}" ...
```

## Implementation Plan

### Phase 1: Configuration Support

**Files**: `internal/github/profile.go`, `internal/github/profile_test.go`

1. Add `PipelineConfig` and `PipelineProfile` structs
2. Extend `ProfileConfig.Organization` with `Pipelines []PipelineConfig` field
3. Add config validation:
   - Pipeline slug non-empty
   - Profile names non-empty and unique within pipeline
   - Profile names cannot be "default"
   - Permissions non-empty
4. Add unit tests:
   - Valid YAML with pipeline profiles parses correctly
   - Duplicate profile names within a pipeline rejected
   - Profile named "default" rejected
   - Empty permissions rejected

### Phase 2: Profile Resolution

**Files**: `internal/github/profile.go`, `internal/vendor/repovendor.go`

1. Add `GetPipelineProfile(slug, name string)` method to `ProfileStore`
2. Update `NewRepoVendor`:
   - If `ref.Name != "default"`, call `profileStore.GetPipelineProfile(claims.PipelineSlug, ref.Name)`
   - Use returned profile's permissions
   - Wrap errors with context: `fmt.Errorf("could not find profile %s: %w", ref.Name, err)`
3. Add unit tests:
   - Profile lookup finds correct profile for pipeline
   - Profile lookup scoped to requesting pipeline
   - Profile not found returns error
   - "default" continues to use organization defaults

### Phase 3: Error Handling

**Files**: `internal/vendor/repovendor.go`, `handlers.go`, `handlers_test.go`

1. Return `errors.New("profile not found")` from `GetPipelineProfile`
2. Update `NewRepoVendor` to return appropriate error for profile not found
3. Update handlers to map profile errors to HTTP 404
4. Add unit tests:
   - Unknown profile → 404
   - Profile exists for different pipeline → 404
   - Error message doesn't reveal profile existence

### Phase 4: Audit Enhancement

**Files**: `internal/audit/audit.go`, related test files

1. Add `profile_name` field to audit entry struct
2. Add `permissions` array to audit entry struct
3. Update audit middleware to capture profile info from context
4. Add tests verifying audit log format for both default and named profiles

### Phase 5: Plugin Update

**Repository**: `chinmina-github-buildkite-plugin`

1. Add `profile` parameter to plugin configuration schema
2. Update plugin script to construct `repo:<profile>` requests
3. Update plugin README with examples
4. Add tests for profile parameter handling

### Phase 6: Documentation

**Repository**: Main docs (https://chinmina.github.io)

1. Add "Pipeline Profiles" guide to configuration section
2. Update token request examples to show profile usage
3. Add security considerations for elevated permissions
4. Add examples of common use cases

## Testing Strategy

### Unit Tests: Configuration

**File**: `internal/github/profile_test.go`

- Config parsing with pipelines section
- Validation rules:
  - Duplicate names within pipeline rejected
  - Reserved "default" name rejected
  - Empty slugs rejected
  - Empty permissions rejected
- `GetPipelineProfile` resolution logic
- Pipeline slug matching (case sensitive)

### Unit Tests: Token Vending

**File**: `internal/vendor/repovendor_test.go`

- Profile resolution for named profiles
- Fallback to defaults for "default" profile
- Error handling for unknown profiles
- Permission application from profiles
- Profile isolation between pipelines

### Integration Tests

**File**: `handlers_test.go`

- End-to-end token requests with named profiles
- HTTP 404 for unknown profiles
- HTTP 404 for profile from different pipeline
- Audit logging with profile names
- Profile isolation verification
- Token permissions match requested profile

### Test Data

Example test profile configuration:

```yaml
organization:
  defaults:
    permissions: [contents:read]

  pipelines:
    - slug: "test-pipeline-1"
      profiles:
        - name: "write"
          permissions: [contents:write]

    - slug: "test-pipeline-2"
      profiles:
        - name: "write"  # Same name, different pipeline - should be isolated
          permissions: [packages:write]
```

## Examples and Use Cases

### Example 1: Release Pipeline

**Use case**: Create GitHub releases and push tags.

**Configuration**:
```yaml
organization:
  defaults:
    permissions: [contents:read]

  pipelines:
    - slug: "release-automation"
      profiles:
        - name: "release"
          permissions:
            - contents:write
            - metadata:read
```

**Plugin usage**:
```yaml
steps:
  - label: "Create Release"
    command: "./scripts/create-release.sh"
    plugins:
      - chinmina/github#v1:
          profile: release
```

### Example 2: Package Publishing

**Use case**: Publish packages to GitHub Packages registry.

**Configuration**:
```yaml
organization:
  defaults:
    permissions: [contents:read]

  pipelines:
    - slug: "npm-publish"
      profiles:
        - name: "publish"
          permissions:
            - contents:read
            - packages:write
```

**Plugin usage**:
```yaml
steps:
  - label: "Publish Package"
    command: "npm publish"
    plugins:
      - chinmina/github#v1:
          profile: publish
```

### Example 3: Multi-Profile Pipeline

**Use case**: Different steps requiring different permission levels.

**Configuration**:
```yaml
organization:
  defaults:
    permissions: [contents:read]

  pipelines:
    - slug: "full-ci-cd"
      profiles:
        - name: "test"
          permissions:
            - contents:read
            - checks:write
        - name: "deploy"
          permissions:
            - contents:write
            - deployments:write
```

**Plugin usage**:
```yaml
steps:
  - label: "Run Tests"
    command: "make test"
    plugins:
      - chinmina/github#v1:
          profile: test

  - wait

  - label: "Deploy"
    command: "make deploy"
    plugins:
      - chinmina/github#v1:
          profile: deploy
```

## Migration and Backward Compatibility

### Existing Behavior Unchanged

Pipelines not configured with named profiles continue to work identically:

- Requests to `repo:default` use `organization.defaults.permissions` (or `contents:read` fallback)
- No changes required to existing configurations
- No changes required to existing plugin usage

### Migration Path

Organizations can adopt pipeline profiles incrementally:

1. **Add profile configuration**: Add pipeline profile to organization YAML
2. **Update plugin usage**: Add `profile: <name>` to specific steps
3. **Monitor audit logs**: Verify profile usage and permissions
4. **Expand adoption**: Add profiles for additional pipelines as needed

### Zero-Impact Deployment

- New YAML fields are optional
- Existing configs without `pipelines` section work identically
- Plugin's `profile` parameter is optional (defaults to `repo:default`)
- No breaking changes to existing functionality

## Security Considerations

### Isolation

- Profiles are scoped to specific pipeline slugs
- Pipeline A cannot access Pipeline B's profiles
- Error messages don't leak profile existence information

### Least Privilege

- Multiple profiles per pipeline enable different permissions for different steps
- Default behavior remains most restrictive (`contents:read`)
- Organization must explicitly grant elevated permissions

### Audit Trail

- All token requests are logged with profile name
- Resolved permissions included in audit logs
- Pipeline slug, build number, and job ID provide full context

### Attack Scenarios

| Scenario | Mitigation |
|----------|------------|
| Compromised pipeline tries to access another pipeline's profile | 404 error, no information leakage |
| Attacker renames pipeline to match elevated profile | Pipeline slug in JWT claims is authoritative |
| Misconfigured profile grants excessive permissions | Config validation enforces non-empty permissions; audit logs track usage |

## Open Questions

1. How should orphaned profiles (for deleted pipelines) be handled?
   - **Proposed**: Ignore at runtime, clean up manually. Could add a `chinmina validate-config` command later.

2. Should there be a maximum permission set that profiles cannot exceed?
   - **Proposed**: No. The GitHub App's installation permissions are the ceiling.

3. Should profile usage be logged at a different level than default token requests?
   - **Proposed**: No, same audit level. Include profile name in the log entry.

4. Should we support `pipeline_id` as well as `pipeline_slug`?
   - **Proposed**: Start with `pipeline_slug` for simplicity. Add `pipeline_id` support in a future iteration if needed.
