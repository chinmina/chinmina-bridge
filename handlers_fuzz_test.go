//go:build fuzz

package main

import (
	"net/http"
	"net/url"
	"testing"
)

func FuzzExtractRepositoryScope(f *testing.F) {
	// --- seeds: absent parameter ---
	f.Add("")

	// --- seeds: valid names ---
	f.Add("repository-scope=my-repo")
	f.Add("repository-scope=MyRepo")
	f.Add("repository-scope=repo-with-hyphens")
	f.Add("repository-scope=repo123")
	f.Add("repository-scope=UPPERCASE")

	// --- seeds: invalid values ---
	f.Add("repository-scope=owner/repo")
	f.Add("repository-scope=")
	f.Add("repository-scope=%20%20")
	f.Add("repository-scope=a/b/c")
	f.Add("repository-scope=/")

	// --- seeds: encoding edge cases ---
	f.Add("repository-scope=%00")           // null byte
	f.Add("repository-scope=%0A")           // newline
	f.Add("repository-scope=%2F")           // encoded slash
	f.Add("repository-scope=hello%20world") // space
	f.Add("repository-scope=%09")           // tab

	// --- seeds: multiple params ---
	f.Add("repository-scope=repo&other=val")
	f.Add("repository-scope=first&repository-scope=second")

	// --- seeds: unusual query strings ---
	f.Add("repository-scope")       // key without value
	f.Add("=repo")                  // value without key
	f.Add("repository-scope=repo&") // trailing ampersand
	f.Add("&repository-scope=repo") // leading ampersand

	f.Fuzz(func(t *testing.T, rawQuery string) {
		// Build a request with the fuzzed query string
		u := &url.URL{
			Scheme:   "http",
			Host:     "localhost",
			Path:     "/organization/token/test",
			RawQuery: rawQuery,
		}

		req, err := http.NewRequest("POST", u.String(), nil)
		if err != nil {
			// Invalid URL from fuzzer - skip
			return
		}

		// Property 1: No panics
		scope, extractErr := extractRepositoryScope(req)

		// Property 2: If extraction succeeds with a non-empty scope, it must not contain '/'
		if extractErr == nil && scope != "" {
			for _, ch := range scope {
				if ch == '/' {
					t.Errorf("extracted scope contains '/' but should have been rejected: %q", scope)
				}
			}
		}

		// Property 3: If extraction succeeds with a non-empty scope, it must not be all whitespace
		if extractErr == nil && scope != "" {
			allWhitespace := true
			for _, ch := range scope {
				if ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r' {
					allWhitespace = false
					break
				}
			}
			if allWhitespace {
				t.Errorf("extracted scope is all whitespace but should have been rejected: %q", scope)
			}
		}

		// Property 4: If the parameter is absent, scope must be empty and err nil
		if !req.URL.Query().Has("repository-scope") {
			if scope != "" {
				t.Errorf("scope should be empty when parameter is absent, got %q", scope)
			}
			if extractErr != nil {
				t.Errorf("err should be nil when parameter is absent, got %v", extractErr)
			}
		}
	})
}
