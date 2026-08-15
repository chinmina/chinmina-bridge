# Multiple GitHub App Association

## Problem Statement

Chinmina Bridge vends every token through a single GitHub App installation,
fixed at deployment time by `GITHUB_APP_ID` and `GITHUB_APP_INSTALLATION_ID`.
Every profile — organization or pipeline — draws on that one installation's
permission grant and repository selection.

This forces an operator who needs a genuinely separate credential to choose
between two bad options: widen the single app's permissions until it can serve
every use case (so every pipeline's token is minted by an app that *could*
write packages, administer repositories, or whatever the broadest consumer
needed), or run a second Chinmina deployment. The first collapses the blast
radius that profiles exist to control; the second duplicates configuration,
telemetry and operational burden.

The permission grant of a GitHub App is also not the only thing that differs
between use cases. Apps differ in their repository selection, their rate limit
budget, and who owns and audits them. A team that owns a packages-publishing
app reasonably wants that app to remain theirs, rather than having its
permissions folded into a shared credential.

## Solution

An operator may declare additional GitHub Apps in deployment configuration,
each under a logical name. A profile in the organization profile YAML may then
name one of those apps, and tokens vended for that profile are minted through
that app's installation. Profiles that name no app continue to use the existing
app, which remains the default.

All configured apps must be installed on the same GitHub organization as the
default app. This is verified once at startup; an app that fails verification
is disabled, and profiles naming it become unavailable rather than silently
falling back to a different credential.

Credentials stay in deployment configuration. The profile YAML — which is
typically writable by a broader group than the deployment environment —
can only *select* from apps the operator has already installed. Introducing a
new credential remains a deploy-time privilege.

### Configuration shape

Deployment environment:

```sh
# unchanged: the default app
export GITHUB_APP_ID="111"
export GITHUB_APP_INSTALLATION_ID="222"
export GITHUB_APP_PRIVATE_KEY_ARN="arn:aws:kms:..."

# new: additional named apps
export GITHUB_APPS='[
  {"name":"packages","appId":333,"installationId":444,
   "privateKeyArn":"arn:aws:kms:..."}
]'
```

Organization profile YAML:

```yaml
organization:
  profiles:
    - name: publish-packages
      app: packages
      match:
        - claim: pipeline_slug
          value: release
      repositories: [{{all-repositories}}]
      permissions: [packages:write]

pipeline:
  defaults:
    permissions: [contents:read]   # always the default app
  profiles:
    - name: build-images
      app: packages
      permissions: [packages:write]
```

## Requirements

### App registry configuration

1. The service shall treat the app described by `GITHUB_APP_ID`,
   `GITHUB_APP_INSTALLATION_ID` and the existing private key variables as the
   default app.
2. Where `GITHUB_APPS` is configured, the service shall construct one
   authenticated GitHub App client for each entry it contains.
3. Where `GITHUB_APPS` is not configured, the service shall vend every token
   through the default app.
4. Each registry entry shall declare a name, an application ID, an
   installation ID, and exactly one of a private key or a private key ARN.
5. If `GITHUB_APPS` is not well-formed JSON, then the service shall fail to
   start.
6. If a registry entry declares neither a private key nor a private key ARN,
   then the service shall fail to start.
7. If a registry entry declares both a private key and a private key ARN, then
   the service shall fail to start.
8. If two registry entries declare the same name, then the service shall fail
   to start.
9. If a registry entry is named `default`, then the service shall fail to
   start.
10. If a registry entry's name is empty or contains `/`, `:`, whitespace or
    control characters, then the service shall fail to start.
11. If a registry entry omits its application ID or its installation ID, then
    the service shall fail to start.

### Organization verification

12. When the service starts with a configured registry, the service shall
    determine the default app's installation account login by querying its
    installation.
13. When the service starts with a configured registry, the service shall
    determine each registry app's installation account login by querying its
    installation.
14. The service shall compare installation account logins case-insensitively.
15. If a registry app's installation account login differs from the default
    app's, then the service shall mark that app disabled.
16. If a registry app's client cannot be constructed or its installation cannot
    be queried, then the service shall mark that app disabled.
17. If the default app's installation cannot be queried, then the service shall
    mark every registry app disabled.
18. While an app is disabled, the service shall refuse to vend tokens through
    it.
19. The service shall not re-verify a disabled app until the service is
    restarted.
20. Where `GITHUB_APPS` is not configured, the service shall query no
    installation at startup.

### Profile schema and compilation

21. An organization profile shall accept an optional `app` property naming the
    app its tokens are minted through.
22. A named pipeline profile shall accept an optional `app` property naming the
    app its tokens are minted through.
23. Where a profile declares no `app` property, the service shall mint that
    profile's tokens through the default app.
24. The default pipeline profile shall mint its tokens through the default app.
25. If a profile's `app` property is `default`, then the service shall treat
    that profile as invalid.
26. If a profile's `app` property is present and empty, then the service shall
    treat that profile as invalid.
27. If a profile's `app` property names an app absent from the registry, then
    the service shall treat that profile as invalid.
28. If a profile's `app` property names a disabled app, then the service shall
    treat that profile as invalid.
29. When profile compilation marks a profile invalid because of its `app`
    property, the service shall log a warning naming the profile and the
    reason.
30. If a request names a profile that is invalid, then the service shall
    respond with 404 and a profile-unavailable message.
31. When the profile configuration is refreshed, the service shall re-evaluate
    each profile's `app` property against the registry.

### Token vending

32. When a request resolves a profile, the service shall resolve that profile's
    app to a single minting client at the handler boundary.
33. The service shall carry the resolved app through the vendor chain in the
    resolved request value.
34. When a token is vended, the service shall mint it through the installation
    of the resolved profile's app.
35. The service shall retrieve the organization profile configuration file
    through the default app.
36. The service shall not check a requested repository's owner against the
    resolved app's organization.

### Caching

37. The service shall include the resolved app's application ID and
    installation ID in the token cache key.
38. If two requests resolve the same profile from the same configuration
    generation but through different apps, then the service shall not serve
    either request's cached token to the other.
39. The service shall record the app a cached token was minted through in the
    cached entry.

### Observability

40. When a token request completes, the service shall record the resolved app's
    name on the audit entry.
41. When a token is vended, the service shall include the minting app's name in
    the token response.
42. The service shall attribute token cache outcome and token issuance metrics
    with the app name.
43. When the service starts, the service shall log each configured app's name,
    application ID, installation ID, verified organization and enabled state.
44. The service shall exclude private key material from all log output.

### Documentation

45. The `.envrc` reference block shall document `GITHUB_APPS` with a commented
    example alongside the existing `GITHUB_APP_*` variables.
46. The profile schema documentation shall document the `app` property,
    including that it may not name `default` and is unavailable on the default
    pipeline profile.
47. The documentation shall state the same-organization constraint, how it is
    verified, and what a disabled app means operationally.
48. The documentation shall state that a profile configuration using `app`
    requires a binary that supports it, and that rolling the binary back while
    such a configuration is published rejects the entire configuration.

## Implementation Decisions

### Registry placement and shape

The registry lives in `internal/github`, alongside `Client`, the signer and the
token sources. Everything about authenticating as a GitHub App stays in one
package and no new import edge is created.

The registry is built once during startup and is immutable thereafter. It
exposes lookup by name, returning a value that carries both the minting
function and the app's resolved identity (application ID, installation ID,
verified organization). Construction, KMS/PEM key handling, installation
verification and the disabled-state decision all stay behind that boundary —
callers only ask "give me the minter for this name".

Two distinct failure classes, deliberately separated:

- **Malformed configuration** (Reqs 5–11) fails startup, consistent with how
  `config.Load` already treats invalid configuration. The operator has written
  something that cannot be interpreted.
- **An unhealthy app** (Reqs 15–17) disables that app and lets the service
  start. The configuration is interpretable; one credential is not usable. A
  single broken app must not take down token vending for every other profile.

There is no background re-verification. A disabled app stays disabled until
restart, which keeps the registry genuinely immutable after boot and avoids a
second code path that mutates authorization-relevant state at runtime.

### The default app defines the organization

The default app's installation account login is the reference the others are
compared against. There is no separately configured organization literal —
adding a required variable to every existing deployment to express something
already discoverable is not worth it.

If the default app's own installation cannot be queried, there is nothing to
compare against, so every registry app is disabled and the default app
continues to serve (Req 17). This preserves today's behaviour for the default
app exactly: it has never been verified, and this change does not start gating
it on a successful GitHub call at boot.

Target type is not constrained. Only the account login is compared, so an
installation on a user account continues to work as it does today, provided all
apps share it.

### Where the app name is stored, and where it is resolved

Profile attributes stay pure data. `OrganizationProfileAttr` and
`PipelineProfileAttr` gain the app *name* — a string — not a live client.
Compilation validates that name against the registry's known-and-enabled names
and invalidates the profile if it does not resolve.

The name is turned into a minting client at the handler boundary, in the
profile resolver, and travels on the resolved request value. This follows the
doctrine already documented on `vendor.Resolved`: everything a request needs is
established once, at the boundary, so no downstream stage re-consults mutable
state and no request can combine one generation's authorization with another's
credential. It also means the cache key can be computed from the resolved value
without a second lookup.

Compilation therefore needs the set of usable app names threaded through from
the registry: `FetchOrganizationProfile` → `load` → `compile`, and through
`PeriodicRefresh` for the background refresh path. The registry is immutable,
so this is a value passed at wiring time, not a live dependency.

### Vendor chain

`Vending` currently closes over a single `TokenVendor` bound at wiring time. It
instead reads the minting function from the resolved request. The composition
order in `main.go` — Audit → Authorized → Cached → Vending — is unchanged, as is
the separation of the pipeline and organization chains.

### Cache key

The key becomes configuration digest, application ID, installation ID, profile
URN. Numeric IDs cannot contain the separator, so the key stays unambiguous.

The YAML digest alone is insufficient: remapping a logical name to different
credentials in deployment configuration does not change the YAML, so a
distributed Valkey cache could serve tokens minted by the previous app after a
redeploy. Including the resolved identity rather than the name means only
entries for the genuinely remapped app are orphaned.

Deploying this change orphans every existing cache entry once, because the key
format changes for the default app too. This is a one-time cold cache, not a
correctness problem, and is accepted.

### Response and audit

`ProfileToken` gains an `app` field. This is an additive change to a public
response contract and it lands in the cached payload; entries written by an
older version deserialize with an empty app, which is harmless because the key
format changed at the same time and those entries are unreachable.

`audit.Entry` gains the app name. Metrics gain an app-name attribute on the
existing instruments rather than new instruments — series count multiplies by
the configured app count, which is bounded and small.

### Compatibility and deployment ordering

A deployment with no `GITHUB_APPS` and a profile configuration with no `app`
properties behaves as it does today, and makes no additional GitHub API calls
at startup (Reqs 3, 20).

`parse` sets `KnownFields(true)` so that an unrecognised property fails the
whole configuration rather than being silently ignored — a deliberate choice to
prevent a typo from granting unintended access. The consequence for this
feature is that a profile YAML containing `app:` is rejected *in its entirety*
by a binary that predates this change, not merely for the profile carrying the
property. A server that has already loaded a good generation keeps serving it,
but a cold start drops to `NewDefaultProfiles()` — the default pipeline profile
with `contents:read` only.

Deployment must therefore roll the binary first and publish the YAML second,
and a binary rollback requires reverting the YAML too. Req 48 exists to make
this explicit to operators rather than leaving it to be discovered.

## Testing Decisions

Every module changed by this work gets tests. Prior art:
`internal/profile/compilation_test.go` for table-driven compilation cases,
`internal/profile/ref_test.go` for table structure with `expected` struct
fields, `internal/github/token_test.go` for black-box package testing against a
mocked GitHub, `internal/vendor/cached_test.go` for cache behaviour, and
`api_integration_test.go` with `APITestHarness` for full-chain tests.

**Registry construction and organization verification** (`internal/github`) —
table-driven over configuration inputs: a valid multi-app registry; duplicate
names; an entry named `default`; a name containing forbidden characters; both
key sources; neither key source; missing IDs; malformed JSON. Each asserts
startup failure or success as a whole, per Reqs 5–11. Separately, verification
outcomes against a mocked installation endpoint: matching login enables,
differing login disables, case difference still matches, installation query
failure disables, default-app query failure disables everything (Reqs 12–17).
A test asserts no installation call is made when no registry is configured
(Req 20).

**Profile compilation with `app`** (`internal/profile`) — extends the existing
compilation tables: `app` accepted on an organization profile; accepted on a
named pipeline profile; `default` rejected; empty string rejected; unknown name
rejected; disabled app's name rejected; omitted yields the default app. Each
invalid case asserts the profile lands in `invalidProfiles` and that other
profiles in the same configuration remain valid — the isolation property is the
point of Reqs 27–29. A refresh test asserts re-evaluation (Req 31).

**Cache key includes app identity** (`internal/vendor`) — the key guard for the
hole this design introduces. Two resolved requests identical in profile and
digest but differing in resolved app must not share an entry (Req 38), and a
single request round-trips through its own key. Prefer asserting observable
cache behaviour over asserting the key string, so the format stays free to
change.

**Vending through the resolved app** (`internal/vendor`) — a resolved request
carrying a non-default app mints through that app's function, not the default's;
a resolved request carrying no app mints through the default.

**End-to-end** (`api_integration_test.go`, `TestIntegration` prefix) — a request
against a profile bound to a second app produces a token minted via that app's
installation, with the app name present in the response and the audit entry
(Reqs 34, 40, 41). A request against a profile naming a disabled app returns
404 (Reqs 28, 30).

Tests document behaviour, not struct shape: no test should assert merely that a
field exists or is copied where the compiler already guarantees it.

## Out of Scope

- **Caller-selected apps.** A request-path selector (`/token/{app}/{profile}`
  or `?app=`) was considered and rejected: it inverts the trust model by
  letting the caller choose the privilege source, allowing a caller matched to
  a low-privilege profile to pair it with a high-privilege installation.
  Association is a property of the profile.
- **Apps declared in the profile YAML.** Declaring app IDs and key references
  in YAML would make the profile file a single source of truth and would make
  the cache key correct for free, but it turns profile-repo write access into
  credential-selection power, and closing that needs a deployment-side
  allow-list — which reinstates the split it was meant to remove.
- **Cross-organization apps.** All apps must share the default app's
  installation account. Multi-org support is a distinct problem: it would
  require the repository owner to participate in app selection and in
  authorization, neither of which this design introduces.
- **Multiple installations of one app.** The registry keys on a credential set,
  not on an app identity; two entries could legitimately reference the same
  application ID with different installations, but nothing in this work treats
  that as a first-class case.
- **Permission cross-checking.** `GetInstallation` returns the permissions an
  installation actually holds, and a profile requesting more could be detected
  at compile time. Not done: GitHub is already the enforcement boundary, and
  validating profiles against a cached snapshot of GitHub state introduces
  drift between what a profile says and whether it works.
- **Repository owner verification.** Deliberately unchanged (Req 36). The
  installation is the boundary — an app cannot mint for a repository outside
  its own installation, so a cross-organization repository already fails at
  GitHub.
- **Background re-verification or hot registry reload.** Disabled is terminal
  until restart (Req 19).
- **Per-app rate limit handling.** Metrics gain an app dimension (Req 42) so
  per-app pressure is visible, but no rate-limit-aware routing or backoff is
  introduced.

## Further Notes

The site documentation (profile schema, same-organization constraint,
operational meaning of a disabled app) is published from a separate repository.
Reqs 46–48 are stated here as deliverables of this feature, but land there;
Req 45 (`.envrc`) is in this repository.

Multi-line PEM keys inside a JSON environment variable require `\n` escaping.
This is workable but unpleasant, and it will push realistic multi-app
deployments toward `privateKeyArn`. Worth watching: if operators struggle with
it, name-suffixed environment variables
(`GITHUB_APP_PACKAGES_ID`, `GITHUB_APP_PACKAGES_PRIVATE_KEY`, …) remain
available as an additive alternative encoding without changing anything else in
this design.

The registry deliberately holds no notion of which app *should* serve a given
repository — that mapping lives entirely in profiles, where the match rules
that authorize a caller already live. Keeping app selection adjacent to
permission granting means a reviewer reading one profile sees the complete
answer to "what can this caller get, and from which credential".
