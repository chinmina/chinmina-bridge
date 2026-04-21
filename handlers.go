package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"log/slog"
)

// HTTPStatuser provides HTTP status information for errors
type HTTPStatuser interface {
	Status() (int, string)
}

// PathValuer abstracts path-parameter extraction to keep the builder free of
// HTTP-type dependencies. *http.Request satisfies this implicitly via its
// PathValue method.
type PathValuer interface {
	PathValue(name string) string
}

// ProfileRefBuilder constructs a profile.ProfileRef from request context, a
// path-parameter source, and caller-supplied repository scope. Validation of
// scope against profile type (caller-scoped vs static-list vs all-repos) is
// applied inside the builder, centralising the authorisation-boundary logic
// and keeping the handler focused on transport concerns.
type ProfileRefBuilder func(ctx context.Context, pv PathValuer, scopedRepo string) (profile.ProfileRef, error)

// NewProfileRefBuilder returns a ProfileRefBuilder closed over the given
// profile store and expected profile type. The profile store enables
// type-aware scope validation in a subsequent phase; the expected profile
// type drives profile-string resolution rules (e.g. repo defaults to
// "default" when empty; org requires an explicit name).
//
// The returned builder honours caller-supplied scope for
// ProfileTypeOrg refs only; repo profiles ignore scope by contract.
func NewProfileRefBuilder(store *profile.ProfileStore, expectedType profile.ProfileType) ProfileRefBuilder {
	// store is captured for future scope validation against the profile's
	// RepositoryScope; the current implementation delegates scope handling
	// to the vendor chain and does not yet consult the store here.
	_ = store
	return func(ctx context.Context, pv PathValuer, _ string) (profile.ProfileRef, error) {
		claims := jwt.RequireBuildkiteClaimsFromContext(ctx)
		profileStr := pv.PathValue("profile")
		// Scope is resolved by the handler boundary and remains dual-sourced
		// through the vendor chain for this phase; the ref is constructed
		// without ScopedRepository until the builder takes over scope
		// validation.
		return profile.NewProfileRef(claims, expectedType, profileStr, "")
	}
}

// deriveScopeFromRepoURL extracts the repository-name component from a
// git-credentials request URL (e.g. "https://github.com/acme/widget" →
// "widget"). Returns "" if the URL is unparseable or does not resolve to a
// GitHub org/repo pair; callers then fall back to unscoped behaviour.
func deriveScopeFromRepoURL(repoURL string) string {
	u, err := url.Parse(repoURL)
	if err != nil {
		return ""
	}
	_, repo := github.RepoForURL(*u)
	return repo
}

// extractRepositoryScope extracts and validates the repository-scope query parameter.
// Returns empty string if the parameter is absent.
// Returns an error if the parameter is present but invalid (empty, whitespace-only, or contains '/').
func extractRepositoryScope(r *http.Request) (string, error) {
	if !r.URL.Query().Has("repository-scope") {
		return "", nil
	}

	scope := r.URL.Query().Get("repository-scope")
	if strings.TrimSpace(scope) == "" {
		return "", fmt.Errorf("repository-scope must not be empty")
	}
	if strings.Contains(scope, "/") {
		return "", fmt.Errorf("repository-scope must not contain '/'")
	}
	return scope, nil
}

func handlePostToken(tokenVendor vendor.ProfileTokenVendor, builder ProfileRefBuilder, expectedType profile.ProfileType) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer drainRequestBody(r)

		// Resolve repository scope first so the builder receives a normalised
		// value. Pipeline routes (ProfileTypeRepo) are never scoped: skip the
		// query-parameter read entirely to preserve their current behaviour.
		var repositoryScope string
		if expectedType == profile.ProfileTypeOrg {
			var err error
			repositoryScope, err = extractRepositoryScope(r)
			if err != nil {
				requestError(r.Context(), w, http.StatusBadRequest, fmt.Errorf("invalid repository-scope: %w", err))
				return
			}
		}

		ref, err := builder(r.Context(), r, repositoryScope)
		if err != nil {
			requestError(r.Context(), w, http.StatusBadRequest, fmt.Errorf("invalid profile parameter: %w", err))
			return
		}

		result := tokenVendor(r.Context(), ref, "", repositoryScope)
		if err, failed := result.Failed(); failed {
			writeJSONError(r.Context(), w, fmt.Errorf("token creation failed: %w", err))
			return
		}

		// Check if a token was vended (success vs unmatched)
		tokenResponse, tokenVended := result.Token()
		if !tokenVended {
			// No token vended (unmatched case): return 204 No Content
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// write the response to the client as JSON, supplying the token and URL
		// of the repository it's vended for.
		marshalledResponse, err := json.Marshal(tokenResponse)
		if err != nil {
			requestError(r.Context(), w, http.StatusInternalServerError, fmt.Errorf("failed to marshal token response: %w", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(marshalledResponse)
		if err != nil {
			// record failure to log: trying to respond to the client at this
			// point will likely fail
			auditError(r.Context(), fmt.Errorf("failed to write response: %w", err))
			return
		}
	})
}

func handlePostGitCredentials(tokenVendor vendor.ProfileTokenVendor, builder ProfileRefBuilder, expectedType profile.ProfileType) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer drainRequestBody(r)

		// Read and reconstruct the Git-supplied URL first: the org path uses
		// it to derive repository scope, so the builder receives a normalised
		// value. Keeping the order consistent across endpoints reads cleanly.
		requestedRepo, err := credentialhandler.ReadProperties(r.Body)
		if err != nil {
			writeTextError(r.Context(), w, fmt.Errorf("read repository properties from client failed: %w", err))
			return
		}

		requestedRepoURL, err := credentialhandler.ConstructRepositoryURL(requestedRepo)
		if err != nil {
			requestError(r.Context(), w, http.StatusBadRequest, fmt.Errorf("invalid request parameters: %w", err))
			return
		}

		// Derive repository scope from the Git-supplied URL only for org
		// routes. Pipeline routes remain unscoped: they pass the full URL
		// directly to the vendor, which continues to match against the
		// pipeline's configured repository.
		var scopedRepo string
		if expectedType == profile.ProfileTypeOrg {
			scopedRepo = deriveScopeFromRepoURL(requestedRepoURL)
		}

		ref, err := builder(r.Context(), r, scopedRepo)
		if err != nil {
			requestError(r.Context(), w, http.StatusBadRequest, fmt.Errorf("invalid profile parameter: %w", err))
			return
		}

		result := tokenVendor(r.Context(), ref, requestedRepoURL, "")
		if err, failed := result.Failed(); failed {
			writeTextError(r.Context(), w, fmt.Errorf("token creation failed: %w", err))
			return
		}

		w.Header().Set("Content-Type", "text/plain")

		// Check if a token was vended (success vs unmatched)
		tokenResponse, tokenVended := result.Token()
		if !tokenVended {
			// Given repository doesn't match the pipeline: empty return this means
			// that we understand the request but cannot fulfil it: this is a
			// successful case for a credential helper, so we successfully return
			// but don't offer credentials.
			w.Header().Add("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
			return
		}

		// write the response to the client in git credentials property format
		tokenURL, err := tokenResponse.URL()
		if err != nil {
			requestError(r.Context(), w, http.StatusInternalServerError, fmt.Errorf("invalid repo URL: %w", err))
			return
		}

		props := credentialhandler.NewMap(6)
		props.Set("protocol", tokenURL.Scheme)
		props.Set("host", tokenURL.Host)
		props.Set("path", strings.TrimPrefix(tokenURL.Path, "/"))
		props.Set("username", "x-access-token")
		props.Set("password", tokenResponse.Token)
		props.Set("password_expiry_utc", tokenResponse.ExpiryUnix())

		err = credentialhandler.WriteProperties(props, w)
		if err != nil {
			requestError(r.Context(), w, http.StatusInternalServerError, fmt.Errorf("failed to write response: %w", err))
			return
		}
	})
}

func handleHealthCheck() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer drainRequestBody(r)

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
}

func maxRequestSize(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.MaxBytesHandler(next, limit)
	}
}

// stripPrefix wraps a handler to strip a path prefix at segment boundaries.
// Unlike http.StripPrefix, "/api" matches "/api", "/api/", and "/api/foo" but
// not "/apifoo". Requests that don't match return 404.
func stripPrefix(prefix string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := cutPathSegment(r.URL.Path, prefix)
		if !ok {
			http.NotFound(w, r)
			return
		}

		r2 := r.Clone(r.Context())
		r2.URL.Path = rest
		if r.URL.RawPath != "" {
			// On failure cutPathSegment returns "", which clears RawPath
			// and causes net/http to fall back to Path.
			r2.URL.RawPath, _ = cutPathSegment(r.URL.RawPath, prefix)
		}
		handler.ServeHTTP(w, r2)
	})
}

// cutPathSegment strips prefix from path at a segment boundary. The remainder
// must be empty or start with '/'. An empty remainder is normalised to "/".
func cutPathSegment(path, prefix string) (string, bool) {
	rest, found := strings.CutPrefix(path, prefix)
	if !found || (rest != "" && rest[0] != '/') {
		return "", false
	}
	if rest == "" {
		rest = "/"
	}
	return rest, true
}

// ErrorResponse represents a JSON error response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// writeJSONError writes a JSON error response with the given status code and message.
func writeJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	auditError(ctx, err)
	statusCode, message := errorStatus(err)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{Error: message}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		// At this point the status code has been written, so we can only log
		slog.Info("failed to write JSON error response", "error", err)
	}
}

// writeTextError writes a text/plain error response with custom header
func writeTextError(ctx context.Context, w http.ResponseWriter, err error) {
	auditError(ctx, err)
	statusCode, message := errorStatus(err)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Chinmina-Denied", message)
	w.WriteHeader(statusCode)
}

// errorStatus extracts HTTP status code and message from an error.
// Returns (StatusInternalServerError, StatusText) for errors that don't implement HTTPStatuser.
func errorStatus(err error) (int, string) {
	var statuser HTTPStatuser
	if errors.As(err, &statuser) {
		return statuser.Status()
	}

	var limitExceeded *http.MaxBytesError
	if errors.As(err, &limitExceeded) {
		return http.StatusRequestEntityTooLarge, http.StatusText(http.StatusRequestEntityTooLarge)
	}

	return http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)
}

func requestError(ctx context.Context, w http.ResponseWriter, statusCode int, err error) {
	auditError(ctx, err)
	http.Error(w, http.StatusText(statusCode), statusCode)
}

// drainRequestBody drains the request body by reading and discarding the contents.
// This is useful to ensure the request body is fully consumed, which is important
// for connection reuse in HTTP/1 clients.
func drainRequestBody(r *http.Request) {
	if r.Body != nil {
		// 5kb max: after this we'll assume the client is broken or malicious
		// and close the connection
		_, _ = io.CopyN(io.Discard, r.Body, 5*1024*1024)
	}
}

// auditError records an error message in the audit log where possible: it will
// skip writing the error if there has already been an error recorded.
func auditError(ctx context.Context, err error) {
	if err == nil {
		return // nothing to log
	}

	_, auditLog := audit.Context(ctx)
	if auditLog.Error == "" {
		// record the error to the audit log
		auditLog.Error = err.Error()
		return
	}

	// we don't override existing audit errors, so write it to the general log
	slog.Info("request failure", "error", err)
}
