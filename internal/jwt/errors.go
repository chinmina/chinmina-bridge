package jwt

import (
	"encoding/json"
	"errors"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
)

// jwtErrorResponse is the RFC 6750-style body returned to callers on JWT
// validation failure. Field names match jwtmiddleware's own response shape
// so existing consumers of the "error"/"error_description" keys are
// unaffected.
type jwtErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeJWTError writes the caller-facing response for a JWT validation
// failure. Unlike jwtmiddleware.DefaultErrorHandler, it does not vary the
// response by validation cause (bad signature, issuer, audience, claims,
// expiry, ...): Buildkite's OIDC issuer is shared across every customer, so
// a cause-specific response would let a holder of any validly-signed token
// use the response text as an oracle to narrow down another pipeline's
// configuration (audience, organization slug) without needing to break any
// cryptography. Full failure detail is still recorded in the audit log by
// auditErrorHandler.
//
// The only case handled differently is a request with no credentials at
// all: RFC 6750 section 3.1 requires the WWW-Authenticate header to be a
// bare challenge, with no error/error_description auth-params (the JSON
// body still carries "error":"invalid_token", matching the other branch's
// shape). Since the caller already knows they sent nothing, this discloses
// no validation state.
func writeJWTError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	if errors.Is(err, jwtmiddleware.ErrJWTMissing) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(jwtErrorResponse{
			Error: "invalid_token",
		})
		return
	}

	w.Header().Set("WWW-Authenticate", `Bearer realm="api", error="invalid_token", error_description="The access token is invalid"`)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(jwtErrorResponse{
		Error:            "invalid_token",
		ErrorDescription: "The access token is invalid",
	})
}
