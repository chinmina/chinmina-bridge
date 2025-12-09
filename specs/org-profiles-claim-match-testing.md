# Testing Strategy

[← Back to Index](./org-profiles-claim-match-index.md)

## Unit Tests - Matchers

### ExactMatcher

- Match when claim present and equals value
- No match when claim absent
- No match when claim present but different value

### RegexMatcher

- Compile valid patterns
- Reject invalid patterns
- Literal prefix optimization detection
- Alternation matching
- Wildcard matching
- Automatic anchoring prevents substring matches

### CompositeMatcher

- Empty matcher list → always match
- Single matcher → delegate directly
- Multiple matchers → AND logic
- Short-circuit on first failure

## Unit Tests - ClaimValueLookup

### BuildkiteClaims.Lookup()

- Standard claims return correct values
- Optional claims return false when not set
- Agent tags with prefix matching
- Unknown claims return false

## Unit Tests - Validation

### Config Load Validation

- Invalid regex patterns rejected
- Both `value` and `valuePattern` rejected
- Neither `value` nor `valuePattern` rejected
- Disallowed claims rejected
- `agent_tag:` prefix allowed
- Unknown YAML fields rejected (typo protection)

### Runtime Validation

- Control characters in claim values rejected
- Whitespace in claim values rejected
- Valid claim values accepted
- Invalid claim rejects entire request

## Integration Tests

### End-to-End Matching

- Profile matches on exact `value`
- Profile matches on `valuePattern` with alternation
- Profile matches on `valuePattern` with wildcard
- Multiple match rules (AND logic)
- No match returns 403

### Graceful Degradation

- Service starts with failed profiles
- Failed profile returns 404 with "validation failed"
- Valid profiles work correctly
- Failed profile tracked for diagnostics

### Audit Logging

- Successful match logs claim values
- Failed match logs attempted patterns
- Empty match rules logs empty matches array

## Property-Based Tests

```go
func TestExactMatcherProperties(t *testing.T) {
    rapid.Check(t, func(t *rapid.T) {
        claim := rapid.String().Draw(t, "claim")
        value := rapid.String().Draw(t, "value")

        matcher := ExactMatcher(claim, value)

        // Property: Matcher returns true iff claim exists and equals value
        claims := &mockClaims{data: map[string]string{claim: value}}
        matches, ok := matcher(claims)

        assert.True(t, ok)
        assert.Len(t, matches, 1)
        assert.Equal(t, claim, matches[0].Claim)
        assert.Equal(t, value, matches[0].Value)
    })
}

func TestCompositeMatcherAssociativity(t *testing.T) {
    rapid.Check(t, func(t *rapid.T) {
        m1 := ExactMatcher("a", "1")
        m2 := ExactMatcher("b", "2")
        m3 := ExactMatcher("c", "3")

        claims := &mockClaims{data: map[string]string{"a": "1", "b": "2", "c": "3"}}

        // Property: (m1 AND m2) AND m3 == m1 AND (m2 AND m3)
        left := CompositeMatcher(CompositeMatcher(m1, m2), m3)
        right := CompositeMatcher(m1, CompositeMatcher(m2, m3))

        leftMatches, leftOk := left(claims)
        rightMatches, rightOk := right(claims)

        assert.Equal(t, leftOk, rightOk)
        assert.ElementsMatch(t, leftMatches, rightMatches)
    })
}

func TestRegexMatcherLiteralOptimization(t *testing.T) {
    rapid.Check(t, func(t *rapid.T) {
        literal := rapid.StringMatching(`^[a-z0-9-]+$`).Draw(t, "literal")

        // Create regex matcher with literal pattern
        matcher, err := RegexMatcher("claim", literal)
        require.NoError(t, err)

        // Property: Should behave identically to ExactMatcher
        exactMatcher := ExactMatcher("claim", literal)

        claims := &mockClaims{data: map[string]string{"claim": literal}}

        regexMatches, regexOk := matcher(claims)
        exactMatches, exactOk := exactMatcher(claims)

        assert.Equal(t, exactOk, regexOk)
        assert.Equal(t, exactMatches, regexMatches)
    })
}

type mockClaims struct {
    data map[string]string
}

func (m *mockClaims) Lookup(claim string) (string, bool) {
    val, ok := m.data[claim]
    return val, ok
}
```
