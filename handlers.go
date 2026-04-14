package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"log/slog"
)

// HTTPStatuser provides HTTP status information for errors
type HTTPStatuser interface {
	Status() (int, string)
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

// buildProfileRef constructs a ProfileRef from the request context and path.
// Returns an error if the profile parameter is invalid. Panics if Buildkite
// claims are missing (via jwt.RequireBuildkiteClaimsFromContext), which should
// only occur when used outside the JWT middleware chain.
func buildProfileRef(r *http.Request, expectedType profile.ProfileType) (profile.ProfileRef, error) {
	// claims must be present from the middleware
	claims := jwt.RequireBuildkiteClaimsFromContext(r.Context())

	// Extract profile parameter from path (empty string for legacy routes)
	profileStr := r.PathValue("profile")

	// Construct ProfileRef from claims and profile parameter
	return profile.NewProfileRef(claims, expectedType, profileStr)
}

func handlePostToken(tokenVendor vendor.ProfileTokenVendor, expectedType profile.ProfileType) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer drainRequestBody(r)

		ref, err := buildProfileRef(r, expectedType)
		if err != nil {
			requestError(r.Context(), w, http.StatusBadRequest, fmt.Errorf("invalid profile parameter: %w", err))
			return
		}

		result := tokenVendor(r.Context(), ref, "", "")
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

func handlePostGitCredentials(tokenVendor vendor.ProfileTokenVendor, expectedType profile.ProfileType) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer drainRequestBody(r)

		ref, err := buildProfileRef(r, expectedType)
		if err != nil {
			requestError(r.Context(), w, http.StatusBadRequest, fmt.Errorf("invalid profile parameter: %w", err))
			return
		}

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
