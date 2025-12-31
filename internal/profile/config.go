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
}

type pipelineProfile struct {
	Name        string      `yaml:"name"`
	Match       []matchRule `yaml:"match"`
	Permissions []string    `yaml:"permissions"`
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

func (e ProfileUnavailableError) Error() string {
	return fmt.Sprintf("profile %q unavailable: validation failed", e.Name)
}

func (e ProfileUnavailableError) Unwrap() error {
	return e.Cause
}

func (e ProfileUnavailableError) Status() (int, string) {
	return http.StatusNotFound, "profile unavailable: validation failed"
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

// ProfileStoreNotLoadedError indicates the profile store has not been loaded
type ProfileStoreNotLoadedError struct{}

func (e ProfileStoreNotLoadedError) Error() string {
	return "organization profile not loaded"
}

func (e ProfileStoreNotLoadedError) Status() (int, string) {
	return http.StatusServiceUnavailable, "organization profile not loaded"
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
		return profileConfig{}, "", fmt.Errorf("organization profile file parsing failed: %w", err)
	}

	// Calculate SHA256 digest of the source YAML for change detection
	hash := sha256.Sum256([]byte(yamlContent))
	digest := hex.EncodeToString(hash[:])

	return config, digest, nil
}
