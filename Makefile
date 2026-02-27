.DEFAULT_GOAL := build

# Disable cgo by default for all commands
CGO_ENABLED ?= 0
export CGO_ENABLED

# Build flags shared across build targets
GO_BUILD_FLAGS := -ldflags="-w" -trimpath

# Fuzz test durations
FUZZING_LOCAL_SECS ?= 30
FUZZING_CI_SECS ?= 10

.PHONY: mod
mod:
	go mod download

.PHONY: format
format:
	go fmt ./...

.PHONY: lint
lint: mod
	golangci-lint run

.PHONY: test
test: mod
	go test -cover ./... -covermode=atomic

.PHONY: integration
integration: mod
	go test -tags=integration -run="^TestIntegration" -cover ./... -covermode=atomic

.PHONY: fuzz
fuzz: mod
	@echo "Fuzzing internal/credentialhandler..."
	@go test -tags=fuzz -fuzz=Fuzz -run=^$$ -fuzztime=$(FUZZING_LOCAL_SECS)s ./internal/credentialhandler
	@echo "Fuzzing internal/jwt..."
	@go test -tags=fuzz -fuzz=Fuzz -run=^$$ -fuzztime=$(FUZZING_LOCAL_SECS)s ./internal/jwt

# CI targets - output coverage.out for codecov
.PHONY: ci-unit
ci-unit: mod
	go test -race -coverprofile=coverage.out -covermode=atomic ./...

.PHONY: ci-integration
ci-integration: mod
	go test -tags=integration -run="^TestIntegration" -race -coverprofile=coverage.out -covermode=atomic ./...

.PHONY: ci-fuzz
ci-fuzz: mod
	@echo "Fuzzing internal/credentialhandler..."
	@go test -tags=fuzz -fuzz=Fuzz -run=^$$ -fuzztime=$(FUZZING_CI_SECS)s ./internal/credentialhandler
	@echo "Fuzzing internal/jwt..."
	@go test -tags=fuzz -fuzz=Fuzz -run=^$$ -fuzztime=$(FUZZING_CI_SECS)s ./internal/jwt

dist:
	mkdir -p dist

.PHONY: build
build: dist mod
	# build for container use: in future we will need to either use "ko" or
	# "goreleaser" (or both) to create executables and images in the required
	# architectures.
	GOOS=linux go build $(GO_BUILD_FLAGS) -o dist/chinmina-bridge .
	# build for local use, whatever the local platform is
	go build $(GO_BUILD_FLAGS) -o dist/chinmina-bridge-local .
	go build -o dist/oidc-local cmd/create/main.go

.PHONY: run
run: build
	dist/chinmina-bridge-local

.PHONY: agent
agent: build format test lint

.PHONY: docker
docker: build
	cd integration && docker compose up --abort-on-container-exit

.PHONY: docker-down
docker-down:
	cd integration && docker compose down

# ensures that `go mod tidy` has been run after any dependency changes
.PHONY: ensure-deps
ensure-deps: mod
	@go mod tidy
	@git diff --exit-code

# use generation tool to create a JWKS key pair that can be used for local
# testing.
keygen:
	go install github.com/go-jose/go-jose/v4/jose-util@latest
	cd .development/keys \
		&& rm -f *.json \
		&& jose-util generate-key --use sig --alg RS256 --kid testing \
		&& chmod +w *.json \
		&& jq '. | { keys: [ . ] }' < jwk-sig-testing-pub.json > tmp.json \
		&& mv tmp.json jwk-sig-testing-pub.json
