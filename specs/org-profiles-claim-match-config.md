# Configuration Format

[← Back to Index](./org-profiles-claim-match-index.md)

## Configuration Format

```yaml
organization:
  defaults:
    permissions: [contents:read]

  profiles:
    # Exact string match (fastest)
    - name: "production-deploy"
      match:
        - claim: pipeline_slug
          value: "silk-prod"
      repositories: [acme/silk]
      permissions: [contents:write, deployments:write]

    # Regex match with multiple alternatives
    - name: "staging-deploy"
      match:
        - claim: pipeline_slug
          valuePattern: "(silk|cotton)-(staging|stg)"
      repositories: [acme/silk, acme/cotton]
      permissions: [contents:write]

    # Regex match with wildcard (cross-cutting policy)
    - name: "release-pipelines"
      match:
        - claim: pipeline_slug
          valuePattern: ".*-release"
      repositories: [acme/shared-infra, acme/release-tools]
      permissions: [contents:write, packages:write]

    # Multiple match rules (AND logic)
    - name: "production-silk-only"
      match:
        - claim: pipeline_slug
          valuePattern: "silk-.*"
        - claim: build_branch
          value: "main"
      repositories: [acme/silk]
      permissions: [contents:write]

    # No match rules - available to all pipelines
    - name: "shared-utilities-read"
      match: []
      repositories: [acme/shared-utilities]
      permissions: [contents:read]

    # Invalid pattern - dropped at load time with warning
    - name: "broken-profile"
      match:
        - claim: pipeline_slug
          valuePattern: "[invalid(regex"  # Compile fails, profile unavailable
      repositories: [acme/foo]
      permissions: [contents:write]
```

## Field Definitions

| Field | Required | Description |
|-------|----------|-------------|
| `profiles` | No | List of organization profile configurations |
| `profiles[].name` | Yes | Profile name (used in token requests) |
| `profiles[].match` | No | List of match rules (all must match - AND logic). Empty = matches all. |
| `profiles[].match[].claim` | Yes | JWT claim name to match against |
| `profiles[].match[].value` | No* | Exact string to match (fastest) |
| `profiles[].match[].valuePattern` | No* | RE2 regex pattern to match (flexible) |
| `profiles[].repositories` | Yes | List of repository URLs (e.g., `owner/repo`) |
| `profiles[].permissions` | Yes | List of GitHub permissions |

*Exactly one of `value` or `valuePattern` must be specified per match rule.

## Request Format

Organization profiles use existing endpoints:

- **Token request**: `POST /organization/token/<profilename>`
- **Git credentials**: `POST /organization/git-credentials/<profilename>`

**Example**: Pipeline `silk-release` requests profile "release-pipelines"
```
POST /organization/token/release-pipelines
Authorization: Bearer <buildkite-jwt>
```

**Response** (success):
```json
{
  "token": "ghs_...",
  "expires_at": "2025-01-15T11:30:00Z",
  "repositories": ["acme/shared-infra", "acme/release-tools"],
  "permissions": {"contents": "write", "packages": "write"}
}
```

**Response** (match failure):
```json
{
  "error": "access denied: profile match conditions not met"
}
```
HTTP Status: 403 Forbidden

## Examples and Use Cases

### Example 1: Cross-Cutting Release Policy

**Use case**: All pipelines ending in "-release" can publish packages.

```yaml
organization:
  profiles:
    - name: "release-publisher"
      match:
        - claim: pipeline_slug
          valuePattern: ".*-release"
      repositories: [acme/shared-infra, acme/release-tools]
      permissions: [contents:write, packages:write]
```

**Matches**: `silk-release`, `cotton-release`, `main-release`
**Doesn't match**: `silk-deploy`, `pre-release-test`

### Example 2: Production-Only Policy

**Use case**: Only production pipelines on main branch can deploy.

```yaml
organization:
  profiles:
    - name: "production-deploy"
      match:
        - claim: pipeline_slug
          valuePattern: "(silk|cotton)-prod"
        - claim: build_branch
          value: "main"
      repositories: [acme/infra]
      permissions: [contents:write, deployments:write]
```

**Requires**: Both conditions must be true (AND logic)

### Example 3: Baseline Access for All

**Use case**: All pipelines can read shared utilities.

```yaml
organization:
  profiles:
    - name: "shared-utilities"
      match: []  # No conditions = available to all
      repositories: [acme/shared-utilities]
      permissions: [contents:read]
```

**Matches**: Any pipeline
