# Dynamic Repository Scoping for Chinmina Bridge

> Source: [GitHub Issue #246](https://github.com/chinmina/chinmina-bridge/issues/246)

## Problem Statement

AI coding agent workflows run from a central Buildkite pipeline (e.g. `agent-workflows`) that needs GitHub access to clone, push, open PRs, and comment — but against a different repository each time. Today, Chinmina Bridge requires a separate organization profile per repository, which doesn't scale. Every new target repository requires a new profile entry, a configuration update, and a profile refresh cycle. For workflows that operate across dozens or hundreds of repositories, this is operationally untenable.

A secondary problem exists with the current wildcard syntax: the `*` entry in the `repositories` list is terse and its meaning is not self-documenting. As the profile schema becomes more expressive, clearer naming is needed.

## Solution

Introduce two new YAML literals for the `repositories` field in organization profiles:

- **`{{caller-scoped-repository}}`** — the caller specifies a single repository at request time. The vended token is narrowed to that repository only. This lets one profile serve requests targeting any repository, one at a time.
- **`{{all-repositories}}`** — replaces the existing `*` wildcard with an unambiguous name. The token grants access to all repositories accessible to the GitHub App installation, as `*` does today.

The existing `*` wildcard is deprecated. It will continue to function as an alias for `{{all-repositories}}` with a deprecation warning, and will be removed in version 1.

Match rules continue to control which pipelines may use a profile. The GitHub App installation remains the final gate — tokens cannot grant access to repositories the App is not installed on. There is no pre-validation against the App's installed repository list; the GitHub API is the source of truth and rejects invalid repositories at token creation time.

> **Note:** Both literals draw on the same underlying access — any repository the GitHub App installation can reach — but differ in what the vended token permits. `{{all-repositories}}` issues a token with full-width access across all reachable repositories. `{{caller-scoped-repository}}` narrows each token to a single repository per request. The distinction is in token breadth, not in underlying App permissions.

## Examples

### Profile YAML

**`{{all-repositories}}`** replaces `*`. The vended token grants access to all repositories the GitHub App installation can reach:

```yaml
- name: "ci-tools-read"
  match:
    - claim: "pipeline_slug"
      valuePattern: ".*"
  repositories:
    - "{{all-repositories}}"
  permissions:
    - "contents:read"
```

**`{{caller-scoped-repository}}`** requires the caller to supply a repository name at request time. The vended token is narrowed to that single repository:

```yaml
- name: "agent-workflows-write"
  match:
    - claim: "pipeline_slug"
      valuePattern: "agent-workflows|agent-workflows-ci"
  repositories:
    - "{{caller-scoped-repository}}"
  permissions:
    - "contents:write"
```

Both literals must be the only entry in `repositories` — they cannot be combined with each other or with static repository names.

### Plugin invocation

Multiple plugin instances in a single Buildkite step are supported. Scoped and unscoped profiles can coexist:

```yaml
# Token scoped to a specific repo — for profiles using {{caller-scoped-repository}}
- chinmina/chinmina-token#v1.x.x:
    environment:
      - GITHUB_WRITE_TOKEN=org:agent-workflows-write
      - GITHUB_READ_TOKEN=org:agent-workflows-read
    repository-scope: hotel

# Token without scoping — standard profile usage
- chinmina/chinmina-token#v1.x.x:
    environment:
      - GITHUB_TOKEN=repo:default
```

The `repository-scope` value is the repository name only — no owner prefix. It is passed as a query parameter to the Chinmina Bridge organization token endpoint.

## Requirements

### 1. Profile schema

1.1. The profile parser shall accept `{{caller-scoped-repository}}` as a valid entry in an organization profile's `repositories` list.

1.2. The profile parser shall accept `{{all-repositories}}` as a valid entry in an organization profile's `repositories` list.

1.3. When `{{caller-scoped-repository}}` appears in a profile's `repositories` list, the profile parser shall reject the profile if any other entries are present in the list.

1.4. When `{{all-repositories}}` appears in a profile's `repositories` list, the profile parser shall reject the profile if any other entries are present in the list.

1.5. The profile parser shall accept `*` as a valid entry and treat it as an alias for `{{all-repositories}}`.

1.6. When a profile containing `*` is loaded, the profile parser shall emit a deprecation warning identifying the profile name and recommending migration to `{{all-repositories}}`.

1.7. The `{{caller-scoped-repository}}` and `{{all-repositories}}` literals shall only be valid in organization profiles.

1.8. The profile compiler shall resolve the scoping mode (static list, caller-scoped, or all-repositories) at compile time and store it in `OrganizationProfileAttr` using the `RepositoryScope` type.

1.9. The `RepositoryScope` type shall be extended with a third state representing caller-supplied access. This state shall be distinct from the wildcard state (`Wildcard: true`) and the specific-names state (`Names: [...]`) — it must not be representable as either.

1.10. When a profile's `RepositoryScope` is in the caller-scoped state, no repository name shall be stored in the compiled profile. The name shall be supplied only at request time from the `repository-scope` input.

> **Note:** Extension points are `OrganizationProfileAttr` (`internal/profile/profiles.go`) and `RepositoryScope` (`internal/profile/repositoryscope.go`). `RepositoryScope` currently has two states: `Wildcard bool` and `Names []string`. See *Implementation Decisions — Profile schema representation* for the intended approach.

### 2. Organization token endpoint — caller-scoped repository

2.1. When a request to the organization token endpoint includes a `repository-scope` query parameter and the matched profile contains `{{caller-scoped-repository}}`, the bridge shall issue a token scoped to the single repository named in `repository-scope`.

2.2. If a request to the organization token endpoint includes a `repository-scope` query parameter but the matched profile does not contain `{{caller-scoped-repository}}`, then the bridge shall reject the request with an error indicating the profile does not accept repository scoping.

2.3. If a request to the organization token endpoint omits the `repository-scope` query parameter but the matched profile contains `{{caller-scoped-repository}}`, then the bridge shall reject the request with an error indicating that a repository scope is required.

### 3. Organization git-credentials endpoint — caller-scoped repository

3.1. When a profile uses `{{caller-scoped-repository}}` or `{{all-repositories}}`, the git-credentials endpoint shall treat any token issuance failure as a 403 error response. It shall not return empty-success credentials for these profile types under any failure condition.

> **Note:** This is the claim-coverage principle: both new literals claim coverage of every repository, so failure means the request cannot be satisfied — there is no credential helper fallback. Static-list org profiles (those whose `repositories` field contains explicit repository names) return empty-success for repositories outside their list, because the profile makes no coverage claim for those repos. See *Implementation Decisions — Git-credentials endpoint behaviour* for the full rationale.

3.2. When a `{{caller-scoped-repository}}` profile is in use at the organization git-credentials endpoint, the bridge shall derive the repository scope from the Git-supplied repository in the request body.

3.3. When a `{{caller-scoped-repository}}` profile is in use at the organization git-credentials endpoint, the bridge shall issue a token scoped to the single Git-supplied repository.

### 4. Organization git-credentials endpoint — all-repositories

4.1. When an `{{all-repositories}}` profile is in use at the organization git-credentials endpoint and the token request succeeds, the bridge shall return git-credentials output covering all repositories, identical to the existing `*` wildcard behaviour.

### 5. Organization token endpoint — all-repositories

5.1. When the matched profile contains `{{all-repositories}}`, the bridge shall issue a token with access to all repositories accessible to the GitHub App installation.

5.2. If a request to the organization token endpoint includes a `repository-scope` query parameter but the matched profile contains `{{all-repositories}}`, then the bridge shall reject the request with an error indicating the profile does not accept repository scoping.

### 6. Input validation

6.1. The bridge shall reject any `repository-scope` value that contains a `/` character.

6.2. The bridge shall reject any `repository-scope` value that is empty or consists only of whitespace.

6.3. The bridge shall pass the `repository-scope` value through to the GitHub API without case normalization.

### 7. Error handling

7.1. If the GitHub API rejects a token request for a `{{caller-scoped-repository}}` or `{{all-repositories}}` profile, then the bridge shall return a 403 response to the caller with a generic error message that does not reveal whether the repository exists.

7.2. If the GitHub API rejects a token request for a `{{caller-scoped-repository}}` or `{{all-repositories}}` profile, then the bridge shall record the full GitHub API error details in the audit log.

### 8. Caching

8.1. While a `{{caller-scoped-repository}}` profile is in use, the cache layer shall include the scoped repository name in the cache key.

8.2. While a `{{caller-scoped-repository}}` profile is in use, the cache layer shall treat tokens for different repositories under the same profile as distinct cache entries.

8.3. While an `{{all-repositories}}` profile is in use, the cache layer shall use the same cache key structure as the current `*` wildcard behaviour.

> **Note:** "The current `*` wildcard behaviour" means a two-component key `{digest}:{profile-ref}`. This requirement can be read as: for `{{all-repositories}}` profiles, the cache key format is `{digest}:{profile-ref}`, unchanged from the existing wildcard implementation.

### 9. Observability

9.1. When a token is issued for a `{{caller-scoped-repository}}` profile, the audit log shall include the scoped repository name.

> **Note:** The existing audit infrastructure (`internal/vendor/auditvendor.go`) records repositories via `token.Repositories.NamesForDisplay()`. For `{{caller-scoped-repository}}` profiles, the issued token carries a specific-names scope, so this field will contain the single scoped repository name. For `{{all-repositories}}` profiles it will contain `["*"]`, unchanged from current `*` wildcard behaviour. No special handling is required for either case — the existing mechanism is correct.

9.2. When a token request is rejected due to a scoping mismatch, the audit log shall record which of the following conditions caused the rejection:

    a. A `repository-scope` was provided to a profile that does not use `{{caller-scoped-repository}}` (see Req 2.2).

    b. A `repository-scope` was omitted for a profile that requires `{{caller-scoped-repository}}` (see Req 2.3).

    c. A `repository-scope` was provided to a profile that uses `{{all-repositories}}` (see Req 5.2).

### 10. Chinmina-token Buildkite plugin

10.1. The chinmina-token Buildkite plugin shall accept a `repository-scope` configuration parameter.

10.2. When `repository-scope` is configured, the chinmina-token plugin shall pass the value as a query parameter to the Chinmina Bridge organization token endpoint.

10.3. The CLI script in the chinmina-token plugin shall accept a repository scope argument and pass it as a query parameter to the Chinmina Bridge organization token endpoint.

### 11. Chinmina-git-credentials Buildkite plugin

11.1. The chinmina-git-credentials Buildkite plugin shall require no new parameters for `{{caller-scoped-repository}}` support.

### 12. JSON schema

12.1. When the dynamic repository scoping feature is released, a JSON schema for the organization profile YAML structure shall be published in the chinmina-bridge repository.

> **Note:** The original issue lists additional documentation deliverables — updating the profile reference, deprecation docs for `*`, plugin usage examples, and CLI script docs. These are out of scope for this repository; they are deliverables for the documentation repository and the chinmina-token plugin repository.

### 13. Deprecation

13.1. While `*` remains supported, the bridge shall log a deprecation warning on every profile load that contains `*`.

13.2. The `*` wildcard entry shall be removed in version 1.

## Implementation Decisions

### Profile schema representation

The two new literals are string constants recognised during profile compilation. They are not YAML tags or custom types — they are specific string values in the `repositories` array that the compiler interprets. This means `KnownFields(true)` in the YAML decoder continues to work unchanged; no new YAML fields are introduced.

The `OrganizationProfileAttr` type currently carries `Repositories` as `[]string` and derives `RepositoryScope()` from content at call time. The scoping mode (static list, caller-scoped, all-repositories) should be resolved at compile time and stored as a typed value. This is a natural extension of the existing `RepositoryScope` type, which already distinguishes between wildcard and specific-name scopes, but needs a third state: "caller will provide at request time."

### Strict bidirectional validation

Scoping validation is enforced in both directions: the request must match what the profile expects, and the profile must match what the request provides. This prevents a misconfigured caller from accidentally receiving a broader or narrower token than intended. The bridge rejects mismatches with clear error messages rather than silently ignoring the discrepancy.

### Error response design

When the GitHub API rejects a scoped repository (e.g. the App isn't installed on that repo), the bridge returns a 403 with a generic message. It does not reveal whether the repository exists or why it was rejected — that information goes to the audit log only. This prevents information leakage to potential attackers while giving operators full diagnostic detail.

### No pre-validation against GitHub App installation

The bridge does not pre-validate that a scoped repository exists in the GitHub App's installed repository list. Pre-validation would require an extra API call and introduce a TOCTOU race condition. The GitHub API is the source of truth and provides a clear rejection at token creation time.

### Cache key structure

For `{{caller-scoped-repository}}` profiles, the cache key includes the repository name: `{digest}:{profile-ref}:{repository-name}`. Each repository gets its own cached token, which is correct — a token scoped to `repo-a` cannot be reused for `repo-b`. This design means the existing `checkTokenRepository` mismatch logic is irrelevant for scoped profiles by construction: a request for one repository will never retrieve another repository's cache entry.

For `{{all-repositories}}` profiles, the existing key format (`{digest}:{profile-ref}`) is sufficient since the token covers all repositories.

This design means more GitHub API calls under load compared to a single wildcard token (one API call per unique repository instead of one shared token). This is an acceptable trade-off for the security benefit of narrow scoping, and should be documented.

### No case normalization

The `repository-scope` value is passed through to the GitHub API without case normalization. GitHub's API is case-insensitive for repository names, so this works correctly without the bridge adding complexity.

### Query parameter transport

The `repository-scope` parameter is transported as a query parameter on POST requests to the organization token endpoint. This keeps it visible in access logs and avoids changing the request body format.

### Git-credentials endpoint behaviour

The git-credentials endpoint already receives the target repository from Git via the request body. For `{{caller-scoped-repository}}` profiles, this repository becomes the scoping input — no new parameters are needed from the plugin.

The error model follows a consistent principle across profile types: profiles that claim coverage of a repository treat issuance failure as a real error (403), while profiles that don't claim coverage return an empty success to let Git try another credential helper. Both `{{caller-scoped-repository}}` and `{{all-repositories}}` explicitly claim coverage of all repositories — the difference is only in token breadth, not coverage intent. This matches pipeline profile behaviour, where the profile's claim over the pipeline's repository means failure is always an error. Only static-list org profiles return empty success for repos outside the list, because the profile is explicitly not claiming coverage of those repos.

### Deprecation strategy

The `*` wildcard is supported as an alias during the transition period. At profile compile time, `*` is treated identically to `{{all-repositories}}` but a deprecation warning is emitted. No transitional handling is needed when an operator updates a profile from `*` to `{{all-repositories}}` — the two are semantically identical, the refresh picks up the new YAML, computes a new digest, and cached tokens naturally expire. The alias is removed in version 1, at which point `*` will cause a profile validation failure.

## Testing Decisions

### Profile compilation tests

The profile compilation layer has thorough existing tests. New tests should cover: acceptance of both new literals, rejection of mixed entries (literal combined with static repos or with each other), `*` alias behaviour including deprecation warning emission, rejection of the literals in pipeline profiles, and correct resolution of scoping mode at compile time. The existing `validateRepositories` function is the natural extension point.

### Org vendor tests

New tests should cover: scoped token issuance when `repository-scope` is provided, rejection when scope is provided but profile doesn't expect it, rejection when scope is missing but profile requires it, correct repository narrowing in the issued token, and 403 response when GitHub rejects the scoped repository. The existing test helpers provide the patterns to follow.

### Cached vendor tests

New tests should cover: distinct cache entries for different repositories under the same scoped profile, cache key format including repository name, correct hit/miss behaviour across repositories, and confirmation that `checkTokenRepository` is not reached for scoped profiles (by construction of the cache key).

### Handler tests

New tests should cover: extraction of `repository-scope` query parameter, rejection of requests with invalid `repository-scope` values (containing `/`, empty, whitespace-only), and correct passthrough to the vendor layer. The git-credentials handler should be tested for implicit scoping from the Git-supplied repository.

### Chinmina-token plugin + CLI script tests

The plugin has an existing test suite using `docker-compose`. New tests should cover: the `repository-scope` plugin parameter being passed through as a query parameter, and the CLI script accepting and forwarding the scope argument.

## Out of Scope

- **Runtime JSON schema validation within Chinmina itself.** The JSON schema is published for documentation and editor support. Profile validation continues to be handled by the Go compiler at load time.
- **Multi-repository scoping in a single request.** `{{caller-scoped-repository}}` narrows to exactly one repository. Multi-repo scoping with caller control would be a separate feature.
- **Pipeline profile scoping.** Pipeline profiles are inherently scoped to a single repository via the Buildkite pipeline configuration. The new literals apply only to organization profiles.
- **Automatic migration tooling for `*` to `{{all-repositories}}`.** The deprecation warning provides the signal; operators update their YAML manually.
- **Changes to the chinmina-release or chinmina-git-credentials Buildkite plugins.** The release plugin fetches release assets and doesn't need repository scoping. The git-credentials plugin needs no code changes.
- **Pre-validation against the GitHub App's installed repository list.** The GitHub API handles this at token creation time.

## Further Notes

The naming of the two literals was a deliberate design choice. `{{caller-scoped-repository}}` was preferred over shorter alternatives like `{{repository-scope}}` or `{{requested-repository}}` because it makes both the actor (caller) and the effect (scoping) explicit in a security-relevant configuration file. `{{all-repositories}}` was preferred over `{{any-repository}}` because "any" is ambiguous in English — it can mean "whichever one" or "every one" — while "all" is unambiguous.

The `RepositoryScope` type already exists in the codebase and provides the domain model for wildcard vs. specific repository access. The dynamic scoping feature extends this model with a third state rather than replacing it.

This feature interacts with the caching layer, which is currently under investigation for a separate bug (cache misses under load on organization routes). The cache key changes in this feature (adding repository name for scoped profiles) should be coordinated with any caching fixes to avoid conflicting changes.
