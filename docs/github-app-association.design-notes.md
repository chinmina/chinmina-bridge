# Multiple GitHub App Association — implementation design

Implementation direction for `docs/prd-github-app-association.md`. Requirement
numbers refer to that document.

## Registry

The registry lives in `internal/github`, alongside `Client`, the signer and the
token sources, so app authentication stays in one package and no new import edge
is created. It is built once at startup and immutable thereafter: value receivers
over an unexported map set in the constructor and never written afterwards.

**A disabled app is not resolvable.** Lookup by name returns not-found; enabled
state is exposed only for logging. This lets Reqs 27 and 36 share one enforcement
point — compilation asks for the set of usable names, the request path asks to
resolve a name, and both call the same function. A lookup returning a minter
alongside an `enabled` flag would mean a disabled app's lookup succeeds and every
caller must remember to check.

Two entry types. A configuration entry holds key material and implements
`slog.LogValuer` exposing only name, application ID, installation ID and key
source, which is how Req 49 holds by construction rather than by vigilance. A
resolved entry holds verification results, never key material, and is what Req 48
logs. One type would see its `LogValuer` grow until it constrained nothing.

Req 50 requires that configuration errors never echo key material. The project
convention of wrapping with `%w` conflicts with this on the key-parsing path,
where the wrapped error comes from a third-party library whose message content is
outside our control and may change on any dependency bump. Key-parsing failures
must be wrapped with a sentinel that discards the underlying message — a
deliberate, documented exception.

## Client construction and signing keys

**The signing key must not capture a short-lived context.** `kmsSigningKey`
captures a context at construction and reuses it for every signature, and signing
is lazy and recurring — a fresh App JWT roughly every ten minutes for the life of
the process. A context scoped to startup or verification that reaches key
construction produces a clean boot, a clean verification, then `context canceled`
on every mint once the first JWT expires, permanently, and only for apps using
`privateKeyArn`.

Registry construction therefore takes the long-lived server context.
`createKMSSigningKey` should not capture a context at all: it takes a shared
`aws.Config` — one credential resolution for all apps rather than N concurrent
ones at boot — and the signing call carries its own.

This bears on Req 15's scope. KMS key handling contacts nothing at construction;
the first network call is the signing operation. So every network-shaped failure
— bad ARN, IAM denial, KMS outage, GitHub unreachable — arrives on the
verification path and is disabled under Req 16, and what remains at construction
is offline and deterministic.

The outgoing connection pool is shared, so with more apps than
`SERVER_OUTGOING_MAX_CONNS_PER_HOST` the concurrent queries of Req 13 proceed in
waves. At realistic app counts this is one wave.

## Startup sequence

Separate configuration validation from route construction. Everything offline —
base path normalisation, JWT middleware, the Buildkite client, the cache — is
validated before any GitHub call, so a configuration error is reported
immediately rather than behind a network phase. Routes are built after the
registry exists, so it is never mutated after the handlers capture it.

Construct the registry **after** `http.DefaultTransport` is replaced with the
instrumented, pool-tuned transport, because the GitHub client captures the
transport by value. Building it earlier leaves registry traffic untraced and
untuned, with no error and no log.

The default app is served by two clients: the registry's app-transport client for
minting and installation queries, and the existing token-transport client for
retrieving the profile configuration (Req 34).

`PeriodicRefresh` performs its first load immediately, before its first interval,
so Req 40's gate needs a first-load signal from it. Prefer a synchronous first
load followed by a refresh loop with a delayed start over a readiness channel: it
makes the gate a plain function testable with synthetic time, and avoids every
instance fetching the profile twice at boot.

Shutdown hooks currently run only via the HTTP server's shutdown path, so any
exit before serving — Req 17's, and a gate failure — discards buffered telemetry
describing the failure and leaks a distributed cache connection per restart. Req
42 requires them on those paths, which means guarding execution so the normal
path does not run them twice.

No timeout governs verification or the first load. A hung upstream blocks
startup, the service does not accept connections, and the platform's startup
grace period terminates the container. Req 41's per-attempt log is the
diagnostic, and it does not depend on winning a race against a platform timeout
we do not own.

## Resolution and the vendor chain

Profile attributes stay pure data: `OrganizationProfileAttr` and
`PipelineProfileAttr` gain the app *name*, a string, not a live client.

**Normalise in compilation, not at the request boundary.** An omitted `app` and
an explicit `app: default` must be indistinguishable downstream, so `compile`
resolves both to the default app's name and a valid profile's app name is never
empty. Normalising at the resolver would give the two spellings different
compiled attributes, and so different audit attribution for identical behaviour.

The name resolves to an app identity — name, application ID, installation ID — at
the handler boundary, in the profile resolver, and travels on the resolved
request value. The identity is data, not a closure, so `vendor.Resolved` stays
loggable and no credential is captured in a value that flows into a cache
payload. `Vending` resolves identity to a minter through the registry: an O(1)
lookup against an immutable value.

**Resolution must happen in the resolver, not in `Vending`.** The chain is Audit →
Authorized → Cached → Vending, and `Cached` short-circuits on a hit before the
wrapped vendor runs — the hazard already documented on `Authorized`, which must
be composed outside `Cached` for the same reason. A registry check inside
`Vending` is absent on every cache hit, which is exactly the state where a
profile that was valid long enough to warm an entry has since had its app
disabled. Resolving in the resolver makes the lookup that populates the identity
*the* guard, running on every request. This is what Req 36's final clause
requires.

Its failure is a 500, not a 403: reaching it means a profile was resolved that
compilation should have invalidated — our defect, not GitHub's denial. The
existing guards for unresolved scope and an uncompiled matcher have the same
shape.

Only the resolver reads the app name off the typed attributes, so only it is
constrained on that method. Cache, authorizer, auditor and vendor read the
identity from the resolved value and stay generic.

Compilation needs the registry's usable names threaded through
`FetchOrganizationProfile` → `load` → `compile`, and through `PeriodicRefresh`
for the background path. Req 30 exists because missing the second path is easy
and silent: profiles would be valid for the first refresh interval and invalid
after, with an unchanged digest, so the generation swap logs at debug level while
profiles become unavailable.

## Invalid-profile logging

Compilation logs its batched invalid-profile warning on every compile, and
compilation runs on every refresh, so one permanently-invalid profile produces a
warning every interval for the life of the process.

Req 28 places the comparison in the profile store — the only component holding
both generations, already under a write lock, already branching on change. Diff
the profile-name-to-reason mapping rather than names alone, so a profile whose
reason changes is reported. Do not diff on the digest: the case worth catching is
one where the YAML is unchanged and validity flips. The store update runs even
when the digest is unchanged, which is what makes this catch the Req 30 failure.

Req 44 requires the audit entry to carry why a profile is invalid.
`ProfileUnavailableError` currently discards its cause; the caller-facing message
comes from a separate method, so including it changes nothing a caller sees. This
becomes load-bearing once Req 28 is edge-triggered, because the audit entry is
then the only timely record.

## Cache

The key is `digest:applicationID:installationID:profileURN`. Numeric identifiers
cannot contain the separator, so the key stays unambiguous.

No consistency check is performed between the app recorded in an entry and the
app implied by its key. Against an attacker it is worth nothing: with encryption
enabled the key is authenticated associated data, so an entry cannot be forged or
relocated without the keyset; with encryption disabled, anyone able to write an
entry can write a consistent one, and the dominant risk there is reading, since
every entry holds a live token. As a defect canary it would duplicate an
invariant the key already enforces, on a branch reachable only through a change
the required cache-key test detects first.

Old and new key formats are disjoint keyspaces, so during a rolling deployment
each warms independently and neither misreads the other. The cost is a bounded
increase in mint volume for one cache lifetime. Nothing reaps orphaned entries;
they expire. The in-memory capacity bound does not apply to the distributed
cache, so two live keyspaces do not interact with it.

## Testing

**Harness.** The GitHub mock exposes only the installation token endpoint, with
one status code and one counter shared across requests. Verification testing
needs the installation endpoint, per-installation responses and per-installation
counters, so one boot can exercise an app that matches, an app on a different
account and an app whose query fails. Req 19 asserts which calls were made, so it
needs the per-installation counter independently. The harness needs a way to
supply registry configuration, and registry entries must inherit the internal API
URL or none of this can be pointed at the mock.

**Registry construction and verification** (`internal/github`) — table-driven
over configuration inputs: a valid multi-app registry; duplicate names; an entry
named `default`; a name failing the allowlist; both key sources; neither; a
non-positive identifier; malformed JSON; unknown fields. Each asserts startup
failure or success as a whole (Reqs 5–11, 15). Then verification outcomes against
the mocked endpoint: matching account enables, differing account disables, query
failure disables, default-app query failure exits (Reqs 12–17). One test asserts
no installation call when no registry is configured (Req 19).

**The signing key outlives verification** (`internal/github`) — construct the
registry under a context that is then cancelled, mint a token, assert success.
Without this the defect is invisible: it does not reproduce with PEM keys, and
every existing test uses PEM.

**Profile compilation** (`internal/profile`) — extends the existing tables: `app`
accepted on an organization profile and on a named pipeline profile; `default`
accepted as an alias; empty string, unknown name and disabled app's name
rejected; omitted yields the default app. A behaviour test asserts two
configurations differing only in the presence of `app: default` compile to equal
attributes. Each invalid case asserts the profile is invalid and that others in
the same configuration remain valid — the isolation property is the point of Reqs
26–28. A refresh test drives a refresh and asserts a profile naming an enabled
app is still valid (Req 30).

**Cache key includes app identity** (`internal/vendor`) — two resolved requests
identical in profile and digest but differing in identity must not share an entry
(Req 38), and a single request round-trips through its own key. Assert observable
cache behaviour rather than the key string. This also discharges the absence of a
payload consistency check: it fails if a future change stops the key determining
identity.

**A warm entry does not bypass app resolution** — prime the cache, make the
registry unable to resolve that profile's app, repeat the request, assert 500 and
that the cached token was not served (Req 36). This is the test that fails if
resolution is placed inside the vendor chain.

**Vending through the resolved app** (`internal/vendor`) — a request carrying a
non-default identity mints through that app; one carrying the default identity
mints through the default.

**The startup gate** — extract the wait for a first generation as a function, so
it can be tested with synthetic time as the refresh daemon already is. The
integration harness constructs routes directly rather than booting the server, so
a gate tested only through the harness is not tested at all.

**Invalid-profile logging is edge-triggered** (`internal/profile`) — two
successive updates with the same invalid set log once; a change logs again.

**Concurrency** — an integration test issuing parallel requests across two apps,
under the race detector, so a future change introducing lazily populated registry
state is caught.

**End-to-end** (`api_integration_test.go`) — a request against a profile bound to
a second app produces a token minted via that app's installation, with the app
name in the response and the audit entry (Reqs 33, 43, 45). A request against a
profile naming a disabled app returns 404 (Reqs 27, 29) with the reason on the
audit entry (Req 44).

Tests document behaviour, not struct shape.

## Suggested order

1. Edge-triggered invalid-profile logging; `ProfileUnavailableError` carries its
   cause.
2. Shutdown hooks on startup exit paths.
3. Split configuration validation from route construction; fix transport
   ordering.
4. Registry construction, with the shared `aws.Config` and no captured context.
5. Resolution and guard in the profile resolver; alias normalisation in
   compilation.
6. The startup gate, with the refresh daemon's delayed-start option.
7. Cache key, response and audit fields, name allowlist.
8. Span attributes for profile counts.
9. Documentation, the error-sentinel test, the race test.

Items 1 and 2 are independent of the feature and unblock the rest.
