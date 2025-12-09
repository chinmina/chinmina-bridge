# Implementation Details

[← Back to Index](./org-profiles-claim-match-index.md)

## ClaimValueLookup Interface

Instead of passing claims as a map, use a zero-allocation interface:

```go
type ClaimValueLookup interface {
    Lookup(claim string) (value string, found bool)
}
```

**Benefits**:
- Zero allocations for claim lookup
- Clean interface - easy to mock for testing
- Agent tags handled transparently via prefix matching

**Behavior notes**:
- **Optional claims**: Return `(value, false)` when not present (not empty string). Matchers will fail if they expect an absent optional claim.
- **Case sensitivity**: All matching is case-sensitive (follows standard regex behavior)
- **Claim validation**: Done by JWT framework, out of scope for claim-matching implementation

## BuildkiteClaims Implementation

**Note**: The `BuildkiteClaims` struct needs to be extended to include all supported claims allowed for matching. Current implementation only includes a subset of these claims.

### Required Fields to Add

```go
type BuildkiteClaims struct {
    // Existing fields:
    OrganizationSlug string `json:"organization_slug"`
    PipelineSlug     string `json:"pipeline_slug"`
    PipelineID       string `json:"pipeline_id"`
    BuildNumber      int    `json:"build_number"`
    BuildBranch      string `json:"build_branch"`
    BuildTag         string `json:"build_tag"`
    BuildCommit      string `json:"build_commit"`
    StepKey          string `json:"step_key"`
    JobID            string `json:"job_id"`
    AgentID          string `json:"agent_id"`

    // NEW: Additional fields for claim-matching
    ClusterID    string            `json:"cluster_id"`
    ClusterName  string            `json:"cluster_name"`
    QueueID      string            `json:"queue_id"`
    QueueKey     string            `json:"queue_key"`
    AgentTags    map[string]string `json:"-"`  // Populated via custom unmarshaling

    // Note: build_id, job_id, agent_id, step_key are NOT exposed for matching
    // (present in JWT but not available as match claims)

    // Internal validation field
    expectedOrganizationSlug string
}
```

### Agent Tags Deserialization

Agent tags are JWT fields with the `agent_tag:` prefix (e.g., `"agent_tag:queue": "runners"`). These need custom unmarshaling logic:

```go
// Implement UnmarshalJSON to handle agent_tag: prefixed fields
func (c *BuildkiteClaims) UnmarshalJSON(data []byte) error {
    // Parse into map to access all fields
    var raw map[string]any
    if err := json.Unmarshal(data, &raw); err != nil {
        return err
    }

    // Process each field
    c.AgentTags = make(map[string]string)
    for key, value := range raw {
        if err := c.setField(key, value); err != nil {
            // Unknown fields silently ignored
            continue
        }
    }

    return nil
}

// SetField maps a JWT field name to the appropriate struct field
func (c *BuildkiteClaims) setField(key string, value any) error {
    switch key {
    case "organization_slug":
        c.OrganizationSlug = value.(string)
    case "pipeline_slug":
        c.PipelineSlug = value.(string)
    // ... standard fields
    default:
        // Handle agent_tag: prefix
        if tagName, found := strings.CutPrefix(key, "agent_tag:"); found {
            if strVal, ok := value.(string); ok {
                c.AgentTags[tagName] = strVal
            }
        }
        // Unknown fields silently ignored
    }
    return nil
}
```

### ClaimValueLookup Implementation

```go
func (c BuildkiteClaims) Lookup(claim string) (string, bool) {
    switch claim {
    case "pipeline_slug":
        return c.PipelineSlug, true
    case "pipeline_id":
        return c.PipelineID, true
    case "build_number":
        return strconv.Itoa(c.BuildNumber), true
    case "build_branch":
        return c.BuildBranch, true
    case "build_tag":
        // Optional claim: return false when not present (not empty string)
        if c.BuildTag != "" {
            return c.BuildTag, true
        }
        return "", false
    case "build_commit":
        return c.BuildCommit, true
    case "cluster_id":
        if c.ClusterID != "" {
            return c.ClusterID, true
        }
        return "", false
    case "cluster_name":
        if c.ClusterName != "" {
            return c.ClusterName, true
        }
        return "", false
    case "queue_id":
        if c.QueueID != "" {
            return c.QueueID, true
        }
        return "", false
    case "queue_key":
        if c.QueueKey != "" {
            return c.QueueKey, true
        }
        return "", false
    default:
        // Handle agent_tag: prefix dynamically
        if agentTag, found := strings.CutPrefix(claim, "agent_tag:"); found {
            if val, ok := c.AgentTags[agentTag]; ok {
                return val, true
            }
        }
        return "", false
    }
}
```

## Matcher Implementation

### Core Types

```go
// ClaimMatch records which claim matched and its value (for audit logs)
type ClaimMatch struct {
    Claim string
    Value string
}

// Matcher evaluates whether claims satisfy match conditions
type Matcher func(claims ClaimValueLookup) (matches []ClaimMatch, ok bool)
```

### ExactMatcher

```go
func ExactMatcher(matchClaim string, matchValue string) Matcher {
    return func(claims ClaimValueLookup) ([]ClaimMatch, bool) {
        value, ok := claims.Lookup(matchClaim)
        if !ok || value != matchValue {
            return nil, false
        }

        return []ClaimMatch{{
            Claim: matchClaim,
            Value: value,
        }}, true
    }
}
```

**Performance**: O(1) string comparison

### RegexMatcher

```go
func RegexMatcher(matchClaim string, matchPattern string) (Matcher, error) {
    // 1. Validate user pattern compiles
    validatedRegex, err := regexp.Compile(matchPattern)
    if err != nil {
        return nil, fmt.Errorf("invalid regex pattern: %w", err)
    }

    // 2. Optimization: if pattern is purely literal, use ExactMatcher
    prefix, complete := validatedRegex.LiteralPrefix()
    if complete {
        return ExactMatcher(matchClaim, prefix), nil
    }

    // 3. Wrap with non-capturing group and string anchors
    anchored := `\A(?:` + matchPattern + `)\z`

    // 4. Compile final pattern
    compiledRegex, err := regexp.Compile(anchored)
    if err != nil {
        return nil, fmt.Errorf("anchored pattern failed to compile: %w", err)
    }

    return func(claims ClaimValueLookup) ([]ClaimMatch, bool) {
        value, ok := claims.Lookup(matchClaim)
        if !ok || !compiledRegex.MatchString(value) {
            return nil, false
        }

        return []ClaimMatch{{
            Claim: matchClaim,
            Value: value,
        }}, true
    }, nil
}
```

**Performance**:
- Literal optimization → O(n) string comparison
- Regex → O(n) RE2 (linear time guaranteed)

### CompositeMatcher

```go
func CompositeMatcher(matchers ...Matcher) Matcher {
    // Handle empty case: no match rules = always match
    if len(matchers) == 0 {
        return func(claims ClaimValueLookup) ([]ClaimMatch, bool) {
            return []ClaimMatch{}, true
        }
    }

    // Single matcher optimization
    if len(matchers) == 1 {
        return matchers[0]
    }

    // Multiple matchers: AND logic with short-circuit
    return func(claims ClaimValueLookup) ([]ClaimMatch, bool) {
        matches := make([]ClaimMatch, 0, len(matchers))

        for _, m := range matchers {
            mMatches, ok := m(claims)
            if !ok {
                // Short-circuit on first failure
                return nil, false
            }
            matches = append(matches, mMatches...)
        }

        return matches, true
    }
}
```

**Semantics**: All matchers must succeed (AND logic)

**Evaluation order**: Match rules are not guaranteed to be evaluated in any particular order or in a stable order. Initial implementation evaluates rules in declaration order, but this behavior should not be relied upon.
