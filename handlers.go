package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/rs/zerolog/log"
)

func handlePostToken(tokenVendor vendor.ProfileTokenVendor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer drainRequestBody(r)

		// claims must be present from the middleware
		claims := jwt.RequireBuildkiteClaimsFromContext(r.Context())

		tokenResponse, err := tokenVendor(r.Context(), claims, "", "")
		if err != nil {
			log.Info().Msgf("token creation failed %v\n", err)
			requestError(w, http.StatusInternalServerError)
			return
		}

		// write the reponse to the client as JSON, supplying the token and URL
		// of the repository it's vended for.
		marshalledResponse, err := json.Marshal(tokenResponse)
		if err != nil {
			requestError(w, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(marshalledResponse)
		if err != nil {
			// record failure to log: trying to respond to the client at this
			// point will likely fail
			log.Info().Msgf("failed to write response: %v\n", err)
			return
		}
	})
}

func handlePostGitCredentials(tokenVendor vendor.ProfileTokenVendor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer drainRequestBody(r)

		profile := r.PathValue("profile")

		// claims must be present from the middleware
		claims := jwt.RequireBuildkiteClaimsFromContext(r.Context())

		requestedRepo, err := credentialhandler.ReadProperties(r.Body)
		if err != nil {
			log.Info().Msgf("read repository properties from client failed %v\n", err)
			requestError(w, http.StatusInternalServerError)
			return
		}

		requestedRepoURL, err := credentialhandler.ConstructRepositoryURL(requestedRepo)
		if err != nil {
			log.Info().Msgf("invalid request parameters %v\n", err)
			requestError(w, http.StatusBadRequest)
			return
		}

		tokenResponse, err := tokenVendor(r.Context(), claims, requestedRepoURL, profile)
		if err != nil {
			log.Info().Msgf("token creation failed %v\n", err)
			requestError(w, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")

		// Given repository doesn't match the pipeline: empty return this means
		// that we understand the request but cannot fulfil it: this is a
		// successful case for a credential helper, so we successfully return
		// but don't offer credentials.
		if tokenResponse == nil {
			w.Header().Add("Content-Length", "0")
			w.WriteHeader(http.StatusOK)

			return
		}

		// write the reponse to the client in git credentials property format
		tokenURL, err := tokenResponse.URL()
		if err != nil {
			log.Info().Msgf("invalid repo URL: %v\n", err)
			requestError(w, http.StatusInternalServerError)
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
			log.Info().Msgf("failed to write response: %v\n", err)
			requestError(w, http.StatusInternalServerError)
			return
		}
	})
}

func handleHealthCheck() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer drainRequestBody(r)

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

func maxRequestSize(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.MaxBytesHandler(next, limit)
	}
}

func requestError(w http.ResponseWriter, statusCode int) {
	http.Error(w, http.StatusText(statusCode), statusCode)
}

// drainRequestBody drains the request body by reading and discarding the contents.
// This is useful to ensure the request body is fully consumed, which is important
// for connection reuse in HTTP/1 clients.
func drainRequestBody(r *http.Request) {
	if r.Body != nil {
		// 5kb max: after this we'll assume the client is broken or malicious
		// and close the connection
		io.CopyN(io.Discard, r.Body, 5*1024*1024)
	}
}
