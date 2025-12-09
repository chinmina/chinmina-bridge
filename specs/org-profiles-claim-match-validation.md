# Validation and Error Handling

[← Back to Index](./org-profiles-claim-match-index.md)

## Config Load Validation

### Profile-Level Validation

- Profile names must be unique within the organization
- Profile names must be non-empty
- Repositories list must be non-empty
- Repository strings must not contain host or organization (format: `owner/repo`)
- Permissions list must be non-empty
- Permissions are not validated (token creation will fail if invalid)

### Match Rule Validation

```go
func validateMatchRule(rule MatchRuleConfig) error {
    // Exactly one of value or valuePattern
    if rule.Value != "" && rule.ValuePattern != "" {
        return errors.New("exactly one of 'value' or 'valuePattern' must be specified")
    }
    if rule.Value == "" && rule.ValuePattern == "" {
        return errors.New("one of 'value' or 'valuePattern' is required")
    }

    // Validate claim is allowed
    if !isAllowedClaim(rule.Claim) {
        return fmt.Errorf("claim %q is not allowed for matching", rule.Claim)
    }

    return nil
}

func isAllowedClaim(claim string) bool {
    allowedClaims := map[string]bool{
        "pipeline_slug": true,
        "pipeline_id":   true,
        "build_number":  true,
        "build_branch":  true,
        "build_tag":     true,
        "build_commit":  true,
        "cluster_id":    true,
        "cluster_name":  true,
        "queue_id":      true,
        "queue_key":     true,
    }

    if allowedClaims[claim] {
        return true
    }

    // Allow agent_tag: prefix
    if strings.HasPrefix(claim, "agent_tag:") {
        return true
    }

    return false
}
```

### Prevent Typo-Based Fail-Open

```go
func ValidateProfile(ctx context.Context, profileYAML string) (ProfileConfig, error) {
    var profileConfig ProfileConfig

    dec := yaml.NewDecoder(strings.NewReader(profileYAML))
    dec.KnownFields(true)  // Reject unknown fields

    err := dec.Decode(&profileConfig)
    if err != nil {
        return ProfileConfig{}, fmt.Errorf("invalid profile configuration: %w", err)
    }

    return profileConfig, nil
}
```

**Example rejection**:
```yaml
profiles:
  - name: "test"
    mtach:  # Typo: should be "match"
      - claim: pipeline_slug
        value: "silk"
```
Error: `field mtach not found in type ProfileConfig`

## Runtime Validation

### Validate Claim Values

**Validate claim values before Matcher evaluation**:

```go
func ValidateClaims(claims BuildkiteClaims) error {
    // Check all string claims for control chars/whitespace
    claimsToValidate := []struct {
        name  string
        value string
    }{
        {"pipeline_slug", claims.PipelineSlug},
        {"pipeline_id", claims.PipelineID},
        {"build_branch", claims.BuildBranch},
        {"build_tag", claims.BuildTag},
        {"build_commit", claims.BuildCommit},
        // ... matchable claims only
    }

    for _, c := range claimsToValidate {
        if c.value == "" {
            continue  // Optional claims
        }
        if err := ValidateClaimValue(c.value); err != nil {
            return fmt.Errorf("invalid claim %s: %w", c.name, err)
        }
    }

    // Validate agent tags
    for key, value := range claims.AgentTags {
        if err := ValidateClaimValue(key); err != nil {
            return fmt.Errorf("invalid agent tag key %s: %w", key, err)
        }
        if err := ValidateClaimValue(value); err != nil {
            return fmt.Errorf("invalid agent tag value for %s: %w", key, err)
        }
    }

    return nil
}

func ValidateClaimValue(value string) error {
    for _, r := range value {
        if unicode.IsControl(r) || unicode.IsSpace(r) {
            return errors.New("contains control character or whitespace")
        }
    }
    return nil
}
```

**Timing**: Validate once before any Matcher evaluation. Keep `Lookup()` simple.

## Graceful Degradation

```go
func LoadProfiles(config ProfileConfig) (*ProfileStore, []error) {
    validProfiles := []Profile{}
    failedProfiles := map[string]error{}  // Track failures for diagnostics
    warnings := []error{}

    for _, profileConfig := range config.Organization.Profiles {
        profile, err := validateAndCompileProfile(profileConfig)
        if err != nil {
            warning := fmt.Errorf("profile %q validation failed, skipping: %w",
                profileConfig.Name, err)
            warnings = append(warnings, warning)
            failedProfiles[profileConfig.Name] = err

            log.Warn().
                Err(err).
                Str("profile", profileConfig.Name).
                Msg("profile validation failed, profile unavailable")
            continue
        }
        validProfiles = append(validProfiles, profile)
    }

    return &ProfileStore{
        config:         ProfileConfig{Organization: OrganizationConfig{Profiles: validProfiles}},
        failedProfiles: failedProfiles,
    }, warnings
}
```

## Error Handling

### HTTP Error Responses

| Scenario | HTTP Status | Response Body | Log Level |
|----------|-------------|---------------|-----------|
| Profile match failed | 403 | `{"error": "access denied: profile match conditions not met"}` | Error (with audit) |
| Profile validation failed at load | 404 | `{"error": "profile unavailable: validation failed"}` | Warn (at load) |
| Profile not found | 404 | `{"error": "profile not found"}` | Debug |
| Invalid claim value | 400 | `{"error": "invalid JWT claims"}` | Warn |

### Profile Resolution

```go
func (p *ProfileStore) GetProfile(name string) (Profile, error) {
    p.mu.Lock()
    defer p.mu.Unlock()

    // Check for validation failure
    if err, failed := p.failedProfiles[name]; failed {
        return Profile{}, &ProfileUnavailableError{
            Name:  name,
            Cause: err,
        }
    }

    // Lookup profile
    profile, ok := p.config.LookupProfile(name)
    if !ok {
        return Profile{}, &ProfileNotFoundError{
            Name: name,
        }
    }

    return profile, nil
}

// Custom error types for HTTP status mapping
type ProfileUnavailableError struct {
    Name  string
    Cause error
}

func (e *ProfileUnavailableError) Error() string {
    return "profile unavailable: validation failed"
}

type ProfileNotFoundError struct {
    Name string
}

func (e *ProfileNotFoundError) Error() string {
    return "profile not found"
}
```
