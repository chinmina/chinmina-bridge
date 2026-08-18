package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"
)

// Sentinel errors for matching
var (
	// ErrNoMatch indicates that profile match conditions were not satisfied
	ErrNoMatch = errors.New("profile match conditions not met")
)

// ClaimValidationError indicates a claim value failed validation
type ClaimValidationError struct {
	Claim string
	Value string
	Err   error
}

func (e ClaimValidationError) Error() string {
	return fmt.Sprintf("claim %q validation failed for value %q: %v", e.Claim, e.Value, e.Err)
}

func (e ClaimValidationError) Unwrap() error {
	return e.Err
}

func (e ClaimValidationError) Status() (int, string) {
	return http.StatusForbidden, http.StatusText(http.StatusForbidden)
}

type profileConfig struct {
	Organization struct {
		Profiles []organizationProfile `yaml:"profiles"`
	} `yaml:"organization"`
	Pipeline struct {
		Defaults struct {
			Permissions []string `yaml:"permissions"`
		} `yaml:"defaults"`
		Profiles []pipelineProfile `yaml:"profiles"`
	} `yaml:"pipeline"`
}

type organizationProfile struct {
	Name         string      `yaml:"name"`
	Match        []matchRule `yaml:"match"`
	Repositories []string    `yaml:"repositories"`
	Permissions  []string    `yaml:"permissions"`

	// App names the GitHub App this profile's tokens are minted through. A
	// pointer distinguishes an omitted property from an explicitly empty one:
	// omitted means the default app, while `app: ""` names nothing and is a
	// mistake worth reporting rather than silently reading as the default.
	App *string `yaml:"app"`
}

type pipelineProfile struct {
	Name        string      `yaml:"name"`
	Match       []matchRule `yaml:"match"`
	Permissions []string    `yaml:"permissions"`

	// App names the GitHub App this profile's tokens are minted through. See
	// organizationProfile.App for why this is a pointer.
	App *string `yaml:"app"`
}

type matchRule struct {
	Claim        string `yaml:"claim"`
	Value        string `yaml:"value"`
	ValuePattern string `yaml:"valuePattern"`
}

// ProfileUnavailableError indicates a profile failed validation
type ProfileUnavailableError struct {
	Name  string
	Cause error
}

// Error names the reason the profile failed validation, so the audit entry
// this string lands on records why the request was refused. The caller-facing
// message comes from Status and stays deliberately generic.
func (e ProfileUnavailableError) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("profile %q unavailable: validation failed", e.Name)
	}

	return fmt.Sprintf("profile %q unavailable: %v", e.Name, e.Cause)
}

func (e ProfileUnavailableError) Unwrap() error {
	return e.Cause
}

func (e ProfileUnavailableError) Status() (int, string) {
	return http.StatusNotFound, "profile unavailable: validation failed"
}

// AppUnresolvedError indicates a profile was resolved but the GitHub App it
// names could not be resolved in the registry.
//
// This is a 500 rather than a 403 or 404: reaching it means compilation should
// already have invalidated the profile, so it describes a defect in this
// service rather than a denial by GitHub or a name the caller got wrong. It is
// also the guard that stops a warm cache entry being served after its app is
// disabled, so it must never be softened into a success.
type AppUnresolvedError struct {
	ProfileName string
	AppName     string
}

func (e AppUnresolvedError) Error() string {
	return fmt.Sprintf("profile %q names app %q, which could not be resolved", e.ProfileName, e.AppName)
}

func (e AppUnresolvedError) Status() (int, string) {
	return http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)
}

// ProfileNotFoundError indicates a profile was not found in the store
type ProfileNotFoundError struct {
	Name string
}

func (e ProfileNotFoundError) Error() string {
	return fmt.Sprintf("profile %q not found", e.Name)
}

func (e ProfileNotFoundError) Status() (int, string) {
	return http.StatusNotFound, "profile not found"
}

// ProfileMatchFailedError indicates a profile's match conditions were not met
type ProfileMatchFailedError struct {
	Name string
}

func (e ProfileMatchFailedError) Error() string {
	return fmt.Sprintf("profile %q match conditions not met", e.Name)
}

func (e ProfileMatchFailedError) Status() (int, string) {
	return http.StatusForbidden, http.StatusText(http.StatusForbidden)
}

// RepositoryScopeUnexpectedError indicates a repository-scope was provided
// to a profile that does not accept caller scoping.
type RepositoryScopeUnexpectedError struct {
	ProfileName string
}

func (e RepositoryScopeUnexpectedError) Error() string {
	return fmt.Sprintf("profile %q does not accept repository scoping", e.ProfileName)
}

func (e RepositoryScopeUnexpectedError) Status() (int, string) {
	return http.StatusBadRequest, "profile does not accept repository scoping"
}

// RepositoryScopeRequiredError indicates a repository-scope was not provided
// but the profile requires one.
type RepositoryScopeRequiredError struct {
	ProfileName string
}

func (e RepositoryScopeRequiredError) Error() string {
	return fmt.Sprintf("profile %q requires a repository scope", e.ProfileName)
}

func (e RepositoryScopeRequiredError) Status() (int, string) {
	return http.StatusBadRequest, "repository scope is required for this profile"
}

// parse deserializes YAML into profileConfig and calculates digest.
// Fails on YAML parsing issues including unknown properties.
func parse(yamlContent string) (profileConfig, string, error) {
	config := profileConfig{}

	dec := yaml.NewDecoder(strings.NewReader(yamlContent))

	// Loading the profiles MUST fail in the presence of unknown fields otherwise
	// a misconfiguration (like a typo) could lead to unauthorized access through
	// privilege escalation.
	dec.KnownFields(true)

	err := dec.Decode(&config)
	if err != nil {
		return profileConfig{}, "", fmt.Errorf("profile file parsing failed: %w", err)
	}

	// Calculate SHA256 digest of the source YAML for change detection
	hash := sha256.Sum256([]byte(yamlContent))
	digest := hex.EncodeToString(hash[:])

	return config, digest, nil
}
