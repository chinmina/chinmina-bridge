//go:build fuzz

package credentialhandler_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
)

func FuzzReadProperties(f *testing.F) {
	// Seed corpus derived from existing tests and edge cases
	f.Add("protocol=https\nhost=github.com\n\n")
	f.Add("")
	f.Add("\n")
	f.Add("key=\n")
	f.Add("=value\n")
	f.Add("key=val=ue\n")
	f.Add("no-delimiter\n")
	f.Add("key\x00=value\n")
	f.Add("key=val\x00ue\n")
	f.Add("one=1\ntwo=2\n\n")
	f.Add("empty=\n")
	f.Add("multiple===\n")
	f.Add("\n\n\n")
	f.Add("=\n")
	f.Add("a=b\nc=d\ne=f\n\n")

	f.Fuzz(func(t *testing.T, input string) {
		// Property 1: No panics on any input
		r := strings.NewReader(input)
		result, err := credentialhandler.ReadProperties(r)

		// Property 2: If err == nil, result is non-nil and iterable
		if err == nil {
			if result == nil {
				t.Fatal("ReadProperties returned nil result with nil error")
			}

			// Verify we can iterate without panics
			iter := result.Iter()
			for iter.HasNext() {
				k, v := iter.Next()
				// Keys should never be empty (validated during parsing)
				if k == "" {
					t.Errorf("ReadProperties returned empty key")
				}
				// Value can be anything including empty string
				_ = v
			}
		}

		// Property 3: Round-trip test - if WriteProperties succeeds on parsed result,
		// re-parsing produces same length
		if err == nil && result != nil {
			var buf bytes.Buffer
			writeErr := credentialhandler.WriteProperties(result, &buf)

			if writeErr == nil {
				// Re-parse the output
				reparsed, reparseErr := credentialhandler.ReadProperties(&buf)
				if reparseErr != nil {
					t.Errorf("Round-trip failed: re-parsing failed with %v", reparseErr)
				}

				// Count items in both
				originalCount := 0
				iter1 := result.Iter()
				for iter1.HasNext() {
					iter1.Next()
					originalCount++
				}

				reparsedCount := 0
				iter2 := reparsed.Iter()
				for iter2.HasNext() {
					iter2.Next()
					reparsedCount++
				}

				if originalCount != reparsedCount {
					t.Errorf("Round-trip failed: original had %d items, reparsed had %d items",
						originalCount, reparsedCount)
				}
			}
		}
	})
}
