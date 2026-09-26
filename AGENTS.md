# AGENTS.md

## Local instructions and safety

- If `~/.agents/local/chinmina-bridge.md` exists, load it as additional guidance.
- Edit `AGENTS.md`, not its `CLAUDE.md` symlink. Give each nested `AGENTS.md` a sibling `CLAUDE.md` symlink so both entry points receive the same instructions.
- Put local runtime configuration in gitignored `.envrc.private`; keep real credentials out of committed files and command output. Load local configuration with `direnv allow .`.
- Return errors instead of introducing `panic`, unless the task or an approved plan explicitly permits it.

## Verification

Run commands from the repository root with the toolchain selected by `mise.toml`.
If the shell has another toolchain active, prefix the command with `mise exec --`.

Fast, targeted examples; substitute the package and test for the change:

```sh
go test ./internal/credentialhandler -run '^TestReadProperties$'
go test -tags=integration ./internal/bridge -run '^TestIntegrationHealthCheck$'
CGO_ENABLED=1 go test -race ./internal/server
go test -tags=fuzz ./internal/credentialhandler -run='^$' -fuzz=FuzzReadProperties -fuzztime=5s
```

- `just test` and `just integration` include `./...`; appending a package path does not narrow them. Use direct `go test` commands for package-scoped runs.
- For code changes, run `just agent` before declaring completion; it formats, lints, unit-tests, and builds, but excludes integration, race, and fuzz checks. Lint rules live in `.golangci.yaml`.
- Run `just integration` for changes crossing handlers, profiles, caches, or external-service adapters. Cache integration tests require Docker/testcontainers and may pull images.
- Run `just ci-unit` and, where integration behavior is affected, `just ci-integration` for concurrency-sensitive changes. For parser/validation changes, run the affected fuzz target; `just fuzz 5` runs the registered package list.
- Name integration tests `TestIntegration...` and use the `integration` build tag: the integration recipe selects tests by both.
- After dependency changes, run `just ensure-deps`. It runs `go mod tidy` and fails if `go.mod` or `go.sum` differs from the index; review intended dependency changes rather than undoing them to satisfy this check.
- Use `just --list` for other recipes. Use `just docker logs` or `just docker-up` for the local Compose stack rather than invoking Compose directly: the wrapper generates `integration/.docker-endpoint.env` for the host's Docker endpoint.

## Coverage review

- Review behavior and failure modes, not compiler-enforced structure or lines in isolation.
- Combined unit and integration coverage is currently above 90%. GitHub Actions coverage checks fail on a decrease, but accepting that decrease is a review judgement, not an automatic merge prohibition.
- A decrease must prompt: **Which expected or unexpected behaviors introduced or affected by this change are not yet tested?** Add tests for missing behavior; if behavior is adequately covered, explain why the decrease is acceptable.

## Project-specific conventions

- Write Go in the style of the Go standard library.
- Wrap propagated errors with `fmt.Errorf` and `%w` where the caller can add useful context: the operation that failed and safe identifying details. Each layer should explain its part of the failure, not merely repeat the underlying message. Preserve deliberate credential-redaction boundaries rather than wrapping sensitive parser errors.
- Return wrapped errors to the handling boundary instead of logging and returning the same failure; log where the error is handled.
- Use `log/slog` for structured logging. Implement `slog.LogValuer` for complex logged objects to control their fields and representation.
- Prefer APIs and idioms supported by the Go version in `go.mod` over older model defaults: `t.Context()`, `testing/synctest` for deterministic concurrent tests, `sync.WaitGroup.Go`, and `errors.AsType` where appropriate. Verify unfamiliar APIs with the selected toolchain's `go doc`.
- Use `encoding/json/v2` and `encoding/json/jsontext`, not legacy JSON APIs.
- Use `omitzero` to omit zero-valued numeric or boolean fields; JSON v2's `omitempty` omits empty JSON values, not Go zero values.
- Use `github.com/stretchr/testify/assert` for non-fatal checks and `require` for prerequisites instead of hand-written assertion boilerplate.
- Prefer `github.com/gkampitakis/go-snaps` snapshots for structured output contracts such as audit records. Follow `internal/audit/log_test.go:125`, normalize volatile fields, and review snapshot diffs against intended behavior rather than blindly accepting updates.
- When decoding requests or configuration, reject unknown JSON members with `json.RejectUnknownMembers(true)` and explicitly reject `null` wherever it must differ from absence. This prevents silently accepted invalid input.
- Keep lock-protected regions in small functions with deferred unlocks; return protected state before I/O or callbacks. See `internal/server/shutdown.go` for the pattern.
- Use table-driven tests when cases share setup and assertions, with descriptive `t.Run` names. Keep success and failure tables separate; use individual tests for materially different workflows.
- Put complete expected structs in table cases rather than separate expected fields, and prefer whole-struct equality over field-by-field assertions; HTTP status/header checks are an exception.
- Follow the adjacent tests' package style (`package x` versus `package x_test`).
- Go filenames are lowercase without separators except `_test.go`. Other filenames use lowercase hyphen-separated words where practical.
- If committing, use a conventional commit prefix and keep implementation and its tests together; explain why the change is needed.

## Deeper documentation

- Use Context7 for up-to-date language and library documentation before choosing unfamiliar APIs or relying on remembered behavior. Match the version in `go.mod`; use these verified library IDs:
  - Go language and standard library: `/golang/go`
  - Testify assertions: `/stretchr/testify`
  - Snapshot testing: `/gkampitakis/go-snaps`
  - CLI parsing (urfave/cli v3): `/urfave/cli`
  - JWT/JWK operations (jwx v3): `/lestrrat-go/jwx`
  - GitHub API client: `/google/go-github`
  - AWS SDK v2, including KMS and Secrets Manager: `/aws/aws-sdk-go-v2`
  - Authenticated encryption (Tink Go v2): `/tink-crypto/tink-go`
  - OpenTelemetry Go SDK: `/open-telemetry/opentelemetry-go`
  - OpenTelemetry HTTP instrumentation: `/open-telemetry/opentelemetry-go-contrib`
- Resolve the correct Context7 ID for other dependencies rather than guessing. If Context7 lacks the required version or is unavailable, use the selected toolchain's `go doc` or official documentation.
- Check `go.mod` replacements before applying upstream documentation: the Tink AWS KMS adapter uses a fork, whose selected source takes precedence.
- Package responsibilities and invariants live in each package's `doc.go`, discoverable with `go doc ./internal/bridge` (substitute the package).
- User and operator documentation: <https://docs.chinmina.dev>.
