# Multiple GitHub App Association

## Problem Statement

Chinmina Bridge vends every token through a single GitHub App installation, fixed
at deployment time by `GITHUB_APP_ID` and `GITHUB_APP_INSTALLATION_ID`. Every
profile draws on that one installation's permission grant and repository
selection.

An operator needing a genuinely separate credential must either widen the single
app until it serves every use case — so every pipeline's token is minted by an
app that *could* write packages or administer repositories — or run a second
deployment. The first collapses the blast radius that profiles exist to control;
the second duplicates configuration, telemetry and operational burden.

Permissions are not the only difference. Apps differ in repository selection,
rate limit budget, and who owns and audits them. A team that owns a
packages-publishing app reasonably wants it to remain theirs.

## Solution

An operator may declare additional GitHub Apps in deployment configuration, each
under a logical name. A profile may then name one, and tokens vended for that
profile are minted through that app's installation. Profiles naming no app use
the existing app, which remains the default.

All configured apps must be installed on the same GitHub organization as the
default app. This is verified once at startup; an app that fails verification is
disabled, and profiles naming it become unavailable rather than silently falling
back to a different credential.

Credentials stay in deployment configuration. The profile YAML — typically
writable by a broader group than the deployment environment — can only *select*
from apps the operator has already installed. Introducing a credential remains a
deploy-time privilege.

### Trust and the profile repository

Registering an app raises the privilege ceiling of the profile repository to the
union of every registered app's grant, for as long as that app remains
registered.

Profile-repo write access is already full authority over the default app's grant:
a profile may omit `match` entirely and claim every repository the installation
reaches. This feature raises that ceiling. The deploy-time split protects against
*credential introduction*, not *privilege selection*, so `GITHUB_APPS` is a
decision about how far the profile repository is trusted. Whoever reviews it must
understand each registered app's grant and repository selection.

### Service boundary

The service owns its own configuration, decisions and state. It does not own the
contents of the profile YAML, nor the configuration of a GitHub App. Profile
review happens in the profile repository; app permissions and repository
selection live in GitHub and change there without notice.

The service therefore records what it did and decided, when it did it. It does
not snapshot external state it neither owns nor rechecks.

### Configuration shape

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

`GITHUB_APPS` is the only new configuration variable.

```yaml
organization:
  profiles:
    - name: publish-packages
      app: packages
      match:
        - claim: pipeline_slug
          value: release
      repositories: ["{{all-repositories}}"]
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
4. Each registry entry shall declare a name, an application ID, an installation
   ID, and exactly one of a private key or a private key ARN.
5. If `GITHUB_APPS` is not well-formed JSON, or contains an unrecognised field,
   then the service shall fail to start.
6. If a registry entry declares neither a private key nor a private key ARN, then
   the service shall fail to start.
7. If a registry entry declares both a private key and a private key ARN, then
   the service shall fail to start.
8. If two registry entries declare the same name, then the service shall fail to
   start.
9. If a registry entry is named `default`, then the service shall fail to start.
10. If a registry entry's name does not match
    `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`, or exceeds 64 characters, then the
    service shall fail to start.
11. If a registry entry's application ID or installation ID is not a positive
    integer, then the service shall fail to start.

### Organization verification

12. When the service starts with a configured registry, the service shall
    determine the default app's installation account ID by querying its
    installation.
13. When the service starts with a configured registry, the service shall
    determine each registry app's installation account ID by querying its
    installation, and shall issue those queries concurrently.
14. If a registry app's installation account ID differs from the default app's,
    then the service shall mark that app disabled.
15. If a registry entry's private key cannot be parsed, or its GitHub client
    cannot be constructed, then the service shall fail to start.
16. If a registry app's installation cannot be queried, then the service shall
    mark that app disabled and shall continue starting.
17. If the default app's installation cannot be queried, then the service shall
    exit with a non-zero status.
18. The service shall not re-verify a disabled app until the service is
    restarted.
19. Where `GITHUB_APPS` is not configured, the service shall query no
    installation at startup.

### Profile schema and compilation

20. An organization profile shall accept an optional `app` property naming the
    app its tokens are minted through.
21. A named pipeline profile shall accept an optional `app` property naming the
    app its tokens are minted through.
22. Where a profile declares no `app` property, the service shall mint that
    profile's tokens through the default app.
23. Where a profile's `app` property is `default`, the service shall mint that
    profile's tokens through the default app.
24. The default pipeline profile shall mint its tokens through the default app.
25. If a profile's `app` property is present and empty, then the service shall
    treat that profile as invalid.
26. If a profile's `app` property names an app absent from the registry, then the
    service shall treat that profile as invalid.
27. If a profile's `app` property names a disabled app, then the service shall
    treat that profile as invalid.
28. When the set of invalid profiles differs between profile generations, the
    service shall log each invalid profile and the reason it is invalid.
29. If a request names a profile that is invalid, then the service shall respond
    with 404 and a profile-unavailable message.
30. While the service is running, a profile naming an enabled registry app shall
    remain valid across profile refreshes.

### Token vending

31. When a request resolves a profile, the service shall resolve that profile's
    app to a single app identity at the handler boundary.
32. The service shall carry the resolved app's identity in the resolved request
    value.
33. When a token is vended, the service shall mint it through the installation of
    the resolved profile's app.
34. The service shall retrieve the organization profile configuration file
    through the default app.
35. The service shall not check a requested repository's owner against the
    resolved app's organization.
36. If a request resolves a profile whose app cannot be resolved in the registry,
    then the service shall respond with 500 and shall not vend a token, whether
    or not a cached token exists for that request.

### Caching

37. The service shall include the resolved app's application ID and installation
    ID in the token cache key.
38. If two requests resolve the same profile from the same configuration
    generation but through different app identities, then the service shall not
    serve either request's cached token to the other.
39. The service shall record the app a cached token was minted through in the
    cached entry.

### Startup

40. Where an organization profile location is configured, the service shall not
    accept connections until a profile generation has been loaded from that
    location.
41. While waiting for the first profile generation, the service shall log each
    failed load attempt.
42. When the service exits during startup, the service shall execute its
    registered shutdown hooks.

### Observability

43. When a request resolves a profile, the service shall record the resolved
    app's name on the audit entry.
44. If a profile is unavailable, then the service shall record on the audit entry
    the reason that profile is invalid.
45. When a token is vended, the service shall include the minting app's name in
    the token response.
46. The service shall attribute the token cache outcome metric with the app name.
47. When the service updates the profile generation, the trace span shall record
    the counts of valid and invalid profiles by profile type.
48. When the service starts, the service shall log each configured app's name,
    application ID, installation ID, verified organization and enabled state.
49. When the service logs a registry entry, the log record shall contain only the
    entry's name, application ID, installation ID and key source, and shall
    contain no private key material and no private key ARN.
50. When the service reports a registry configuration error, the error message
    shall identify the faulty entry by name or index, and shall contain no
    substring of the entry's private key or private key ARN.

### Documentation

51. The `.envrc` reference block shall document `GITHUB_APPS` with a commented
    example alongside the existing `GITHUB_APP_*` variables.
52. The profile schema documentation shall document the `app` property, including
    that `default` may be named explicitly and that the property is unavailable
    on the default pipeline profile.
53. The documentation shall state the same-organization constraint, how it is
    verified, and what a disabled app means operationally.
54. The documentation shall state that a profile configuration using `app`
    requires a binary that supports it; that rolling the binary back while such a
    configuration is published rejects the entire configuration; and that
    rollback restores pre-gate cold-start behaviour and is not a remedy for an
    upstream outage.
55. The documentation shall state that narrowing a GitHub App's permissions does
    not revoke tokens already issued, and that uninstalling the app does.
56. The documentation shall state that the token response body, the audit entry
    and the token cache outcome metric each carry the minting app's name.
57. The documentation shall state how a deployment scales with app count: metric
    series and KMS signing calls scale linearly; the outgoing connection pool
    does not.

## Rationale

**The default app defines the organization.** Its installation account is the
reference the others are compared against, so no new variable is required of
existing deployments. The account ID is compared rather than the login, because
logins are renameable and, once released, claimable by another account. Target
type is unconstrained, so an installation on a user account continues to work
provided all apps share it.

**Startup failure versus a disabled app.** Configuration with no single
unambiguous meaning fails startup: malformed JSON, neither or both key sources, a
duplicate name, a non-positive identifier, an unparseable key. These outcomes are
deterministic and identical on every instance. An app whose installation cannot
be queried is disabled and the service starts — the configuration is
interpretable, one credential could not be checked, and one unreachable app must
not take down vending for every other profile.

The default app is the exception (Req 17). If the service cannot query its own
installation it cannot authenticate to GitHub as itself, so minting is broken
regardless and a process that continued would serve failures while appearing
healthy. Per Req 19, deployments not using the feature are unaffected.

**Disabled is terminal until restart** (Req 18). Re-verification would make an
instance's enabled set a function of when its timer fired rather than of its
configuration, so instances with identical configuration could disagree
indefinitely. Installation suspension is not checked for the same reason: an
instance started before a suspension would answer 403 while one started after
answered 404, and unsuspending would restore nothing until every instance
restarted. A suspended app surfaces as a 403 at mint time carrying GitHub's own
message, on an audit entry naming the app.

**Verification concurrency.** Queries are issued concurrently (Req 13), so the
phase completes in roughly the time of the slowest one. A query that does not
complete is a query failure, and Reqs 16 and 17 determine the outcome. No
separate time budget governs the phase: its expiry would be evidence about the
service rather than about any app, which is the wrong basis on which to disable
one.

**Serving requires a loaded profile generation.** Until one has loaded, the
service has no configuration to serve, so Req 40 prevents it accepting
connections and a request is never answered from a generation the operator did
not publish. Not listening is the readiness signal, leaving the healthcheck
contract unchanged. The gate is a latch on the first load only: a service that
has a generation and later loses access to its source keeps serving it.

This couples startup to the availability of the profile source. That cost is
accepted because the alternative failure is silent: an instance serving before it
has loaded answers organization profiles with 404 and pipeline profiles with a
built-in permission set, while reporting healthy and counting as ready during a
rolling deployment.

**Cache key.** The key is the configuration digest, application ID, installation
ID and profile URN. The digest alone is insufficient: the YAML names an app, but
the mapping from that name to a credential lives in deployment configuration, so
repointing a name leaves the YAML — and the digest, and the key — unchanged while
the cache keeps serving tokens from the previous app. Exposure is bounded by the
45-minute entry lifetime against a 60-minute token lifetime, and requires a
distributed cache, a name reused rather than added, and an operator-initiated
remap. It is included because the indirection invites exactly that operation: the
benefit of a logical name is that what sits behind it can be swapped without
touching the YAML.

The key carries identity rather than the name, so only a remapped app's entries
are orphaned. A name is a label on an identity: two names for one application and
installation share entries, differing only in attribution. Granted permissions
are not part of the key — they are observable only through a GitHub call, and
narrowing a grant does not revoke issued tokens, so token lifetime rather than
the cache is the binding constraint.

Deploying this change orphans every existing entry once, because the key format
changes for the default app too. This is a one-time cold cache and is accepted.

**Response, audit and telemetry.** The cached payload is the response, so Req 39
keeps a cache hit and a cache miss returning the same shape. The audit entry
records the app at resolution rather than at vend, so every outcome downstream of
resolution carries it, including failures; a profile invalid because its app is
disabled fails before an app is resolved, so Req 44 records the reason instead.
Profile generation changes are already traced, and Req 47 adds the valid and
invalid counts to those span attributes rather than introducing metrics that
duplicate them — the counts are the only part of profile state not already
observable, and are what makes a partly-invalid generation visible.

**Compatibility and deployment ordering.** A deployment with no `GITHUB_APPS` and
no `app` properties behaves as it does today and makes no additional GitHub calls
at startup (Reqs 3, 19). Profile parsing rejects unrecognised properties so a
typo cannot grant unintended access, so a YAML containing `app:` is rejected in
its entirety by a binary predating this change — as is `app:` written under
`pipeline.defaults`, which is not a profile.

Roll the binary first and publish the YAML second. `GITHUB_APPS` is
deploy-blocking: a malformed entry or unparseable key halts a rollout rather than
degrading it. Rollback requires reverting the YAML first, and restores pre-gate
cold-start behaviour, so an instance that cannot reach the profile source will
again serve without a loaded generation. Rollback is not a remedy for an upstream
outage.

## Out of Scope

- **Caller-selected apps.** Association is a property of the profile. A
  request-path selector would let a caller matched to a low-privilege profile
  pair it with a high-privilege installation.
- **Apps declared in the profile YAML.** This would turn profile-repo write
  access into credential-introduction power. Constraining that requires a
  deployment-side allow-list, which reinstates the split it would remove.
- **Deployment-side constraints on which profiles may use an app.** Constraining
  by profile name does not hold, because the name is chosen by the party being
  constrained. Constraining which repository scopes an app may be paired with
  bounds breadth but not depth — a static repository list carries the same
  permission to the repository that matters — leaves the default app
  unconstrained, and would appear to describe an app's reach while constraining
  only what the YAML may say.
- **Cross-organization apps.** All apps share the default app's installation
  account. The constraint is organisational rather than protective, since GitHub
  already prevents an installation token reaching a repository outside its own
  installation; what it buys is one organization, one audit story, and one
  meaning for "the organization" in the profile YAML. Multi-organization support
  is blocked on consent: authorization rests on Buildkite claims, and nothing
  would establish that a second organization agreed to the first's pipelines
  minting against it.
- **Multiple installations of one app.** The registry keys on a credential set,
  so two entries may reference one application ID with different installations,
  but this is not treated as a first-class case.
- **Permission cross-checking.** Neither a profile's requested permissions nor an
  operator-declared set is validated against the installation's grant. GitHub is
  the enforcement boundary, and a local check is a copy of state this service
  does not own — one that would disable an app at an unrelated later restart in
  response to a change made elsewhere.
- **Repository owner verification.** The installation is the boundary, so a
  cross-organization repository fails at GitHub. Caller-scoped profiles do not
  change this: the caller supplies a bare repository name and the owner is
  implied by the installation.
- **Background re-verification and hot registry reload.**
- **Per-app rate limit handling.** A throttled mint surfaces as a token issuance
  error carrying GitHub's message, on an audit entry naming the resolved app.
  Installation token rate limits scale with installation size, so a second app
  adds budget rather than dividing it.
- **Flushing cached tokens.** A cached entry may be re-served for the remainder
  of its 45-minute lifetime, which sits inside the 60-minute token lifetime, so
  the cache re-delivers a credential that is already live and never extends it
  beyond expiry. Revoking early means uninstalling the app.

## Notes

Site documentation — profile schema, the same-organization constraint, the
operational meaning of a disabled app, and the response, audit and telemetry
contracts — is published from a separate repository. Reqs 52–57 land there; Req
51 is in this repository.

Multi-line PEM keys inside a JSON environment variable require `\n` escaping.
This is workable but unpleasant, and multi-app deployments will prefer
`privateKeyArn` — also recommended because one variable holds every private key,
so a single disclosure compromises every registered app, and recovery is an
uninstall and reinstall per app rather than a key rotation, since rotation does
not revoke outstanding tokens.

The registry holds no notion of which app should serve a given repository. That
mapping lives in profiles, alongside the match rules that authorize a caller, so
a reviewer reading one profile sees which credential a caller draws on and with
what permissions. It does not show them the reach: the installation's repository
selection lives in GitHub, and a profile using `{{all-repositories}}` or
`{{caller-scoped-repository}}` claims whatever that installation covers.

Implementation direction is in `docs/design-github-app-association.md`.

