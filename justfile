export GOEXPERIMENT := "jsonv2"

# cgo is disabled by default; recipes that need it (e.g. the race detector)
# opt back in explicitly with `CGO_ENABLED=1`.
export CGO_ENABLED := "0"

# Build flags shared across build targets
GO_BUILD_FLAGS := "-trimpath"
GO_LD_FLAGS := "-w"

# Packages containing fuzz targets
FUZZ_PACKAGES := "internal/credentialhandler internal/jwt internal/profile internal/vendor ."

# List available recipes
default:
    @just --list

# Format all Go source files
[group('dev')]
format:
    go fmt ./...

# Run the linter
[group('dev')]
lint:
    golangci-lint run

# Ensure `go mod tidy` has been run after any dependency changes
[group('ci')]
ensure-deps:
    @go mod tidy
    @git diff --exit-code go.mod go.sum

# Everything expected to pass before committing
agent: format lint test build

# Run unit tests; extra `go test` args are appended after ./..., e.g. `just test -run TestFoo`
[group('test')]
test *args:
    go test -cover -covermode=atomic ./... {{args}}

# Run integration tests; extra `go test` args are appended after ./...
[group('test')]
integration *args:
    go test -tags=integration -run='^TestIntegration' -cover -covermode=atomic ./... {{args}}

# Run fuzz tests locally (seconds per target, default 30s)
[group('test')]
fuzz secs=env('FUZZING_LOCAL_SECS', "30"):
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in {{FUZZ_PACKAGES}}; do
        echo "Fuzzing ${pkg}..."
        go test -tags=fuzz -fuzz=Fuzz -run='^$' -fuzztime={{secs}}s "./${pkg}"
    done

# CI: run unit tests with race detection, coverage output for codecov
[group('ci')]
ci-unit:
    CGO_ENABLED=1 go test -race -coverprofile=coverage.out -covermode=atomic ./...

# CI: run integration tests with race detection, coverage output for codecov
[group('ci')]
ci-integration:
    CGO_ENABLED=1 go test -tags=integration -run='^TestIntegration' -race -coverprofile=coverage.out -covermode=atomic ./...

# CI: run fuzz tests (seconds per target, default 10s)
[group('ci')]
ci-fuzz: (fuzz env('FUZZING_CI_SECS', "10"))

# Build the container, local, and oidc-local binaries (in parallel)
[group('build')]
[parallel]
build: build-container build-local build-oidc

# Build the Linux container binary
[group('build')]
build-container:
    # in future we will need "ko" or "goreleaser" to produce images across the
    # required architectures.
    mkdir -p dist
    GOOS=linux go build {{GO_BUILD_FLAGS}} -ldflags="{{GO_LD_FLAGS}}" -o dist/chinmina-bridge .

# Build the local dev binary; extra go build args are forwarded, e.g. `just build-local -v`
[group('build')]
build-local *args:
    mkdir -p dist
    go build {{args}} {{GO_BUILD_FLAGS}} -ldflags="{{GO_LD_FLAGS}}" -o dist/chinmina-bridge-local .

# Build the oidc-local test helper binary
[group('build')]
build-oidc:
    mkdir -p dist
    go build -ldflags="{{GO_LD_FLAGS}}" -o dist/oidc-local cmd/create/main.go

# Build and run the local binary
[group('build')]
run: build-local
    dist/chinmina-bridge-local

# Run integration tests against docker-compose
[group('dev')]
[working-directory('integration')]
docker: build
    docker compose up --abort-on-container-exit

# Stop the docker-compose stack
[group('dev')]
[working-directory('integration')]
docker-down:
    docker compose down

# Generate a JWKS key pair for local testing
[group('dev')]
keygen:
    #!/usr/bin/env bash
    set -euo pipefail
    go install github.com/go-jose/go-jose/v4/jose-util@latest
    cd .development/keys
    rm -f *.json
    jose-util generate-key --use sig --alg RS256 --kid testing
    chmod +w *.json
    jq '. | { keys: [ . ] }' < jwk-sig-testing-pub.json > tmp.json
    mv tmp.json jwk-sig-testing-pub.json
