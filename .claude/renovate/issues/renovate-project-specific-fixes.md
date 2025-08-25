# Project-Specific Renovate Fix Patterns

This file contains common fix patterns specific to this repository that complement the generic renovate-merge-workflow.md.

## OpenTelemetry Schema URL Conflicts

**Symptoms:**
- Test failures with error: `conflicting Schema URL: https://opentelemetry.io/schemas/1.X.0 and https://opentelemetry.io/schemas/1.Y.0`
- Occurs when updating OpenTelemetry packages to newer versions

**Root Cause:**
- `resource.Default()` uses an older schema URL (e.g., v1.26.0)
- New OpenTelemetry semconv packages use newer schema URLs (e.g., v1.34.0)
- `resource.Merge()` detects conflicting schema URLs and fails

**Fix Pattern:**
1. Identify the target schema version from the OpenTelemetry updates
2. Update semconv import in `internal/observe/telemetry.go`:
   ```go
   // From:
   semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
   
   // To:
   semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
   ```
3. Run `go mod tidy`
4. Test with `go test ./internal/observe/...`

**Files affected:**
- `internal/observe/telemetry.go`
- `go.mod` and `go.sum`

**Commands:**
```bash
gh pr checkout <PR_NUMBER>
# Edit internal/observe/telemetry.go to update semconv import
go mod tidy
go test ./internal/observe/...
git add .
git commit -m "fix: update semconv to vX.Y.0 to resolve schema URL conflict"
git push
```

## JWT v4→v5 Breaking Changes

**Symptoms:**
- Compilation errors in `internal/github/token.go` and `internal/github/kmssigner.go`
- Type mismatch errors for signing methods and interfaces

**Root Cause:**
- JWT v5 has breaking API changes in signing method interfaces
- Custom KMS signer implementation needs updates

**Fix Pattern:**
- Requires manual code updates (not just dependency resolution)
- See JWT v5 migration guide for specific API changes
- Update custom signing method implementations

**Status:** Requires code changes - not a simple dependency fix

## Resolving PR Conflicts During Renovate Updates

**Symptoms:**
- PR shows `mergeable: "CONFLICTING"` and `mergeStateStatus: "DIRTY"`
- Conflicts typically in `go.sum` or `go.mod` due to overlapping dependency updates

**Fix Pattern:**
1. Check conflict status: `gh pr view <PR_NUMBER> --json mergeable,mergeStateStatus`
2. Rebase with latest main:
   ```bash
   git checkout main && git pull origin main
   gh pr checkout <PR_NUMBER>
   git rebase origin/main
   ```
3. Resolve conflicts (typically go.sum):
   ```bash
   # For go.sum conflicts:
   git checkout --theirs go.sum  # Use main's version
   rm go.sum                     # Or remove entirely
   go get ./...                  # Re-download all deps
   go mod tidy                   # Regenerate go.sum
   ```
4. Complete rebase and push:
   ```bash
   git add .
   git rebase --continue
   git push --force-with-lease
   ```