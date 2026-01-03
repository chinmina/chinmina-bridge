package credentialhandler_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadProperties(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected [][]string
	}{
		{
			name:     "nil handling",
			input:    "~~nil~~",
			expected: [][]string{},
		},
		{
			name:     "empty",
			input:    "",
			expected: [][]string{},
		},
		{
			name: "stop at empty line",
			input: `
one=1

three=3
`,
			expected: [][]string{
				{"one", "1"},
			},
		},
		{
			name: "handle empty values",
			input: `
one=1
two=
three=3
`,
			expected: [][]string{
				{"one", "1"},
				{"two", ""},
				{"three", "3"},
			},
		},
		{
			name: "skip empty keys",
			input: `
one=1
=2
three=3
`,
			expected: [][]string{
				{"one", "1"},
				{"three", "3"},
			},
		},
		{
			name: "skip missing delimiter",
			input: `
one
two=2
three
`,
			expected: [][]string{
				{"two", "2"},
			},
		},
		{
			name: "normal",
			input: `
one=1
two=2
three=3
`,
			expected: [][]string{
				{"one", "1"},
				{"two", "2"},
				{"three", "3"},
			},
		},
	}

	inputReader := func(input string) io.Reader {
		if input == "~~nil~~" { // something of a hack but easier than making it a pointer.
			return nil
		}

		input = strings.TrimPrefix(input, "\n")
		return strings.NewReader(input)
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := inputReader(c.input)
			actual, err := credentialhandler.ReadProperties(r)
			require.NoError(t, err)

			expected := credentialhandler.NewMapFromArray(c.expected)
			assert.Equal(t, expected, actual)
		})
	}
}

func TestWriteProperties(t *testing.T) {
	cases := []struct {
		name     string
		input    [][]string
		expected []string
		failed   bool
	}{
		{
			name:     "empty",
			input:    [][]string{},
			expected: []string{"", ""},
		},
		{
			name: "handle empty values",
			input: [][]string{
				{"one", "1"},
				{"two", ""},
				{"three", "3"},
			},
			expected: []string{"one=1", "two=", "three=3", "", ""},
		},
		{
			name: "fail empty keys",
			input: [][]string{
				{"one", "1"},
				{"", "2"},
				{"three", "3"},
			},
			expected: []string{""},
			failed:   true,
		},
		{
			name: "fail invalid key with '\\n'",
			input: [][]string{
				{"one\n", "1"},
			},
			expected: []string{""},
			failed:   true,
		},
		{
			name: "fail invalid key with '\\0'",
			input: [][]string{
				{"o\000ne", "1"},
			},
			expected: []string{""},
			failed:   true,
		},
		{
			name: "fail invalid key with '='",
			input: [][]string{
				{"on=e", "1"},
			},
			expected: []string{""},
			failed:   true,
		},
		{
			name: "fail invalid value with \\n",
			input: [][]string{
				{"one", "1\n"},
			},
			expected: []string{""},
			failed:   true,
		},
		{
			name: "fail invalid value with \\0",
			input: [][]string{
				{"one", "\0001"},
			},
			expected: []string{""},
			failed:   true,
		},
		{
			name: "value with '='",
			input: [][]string{
				{"one", "=1="},
			},
			expected: []string{"one==1=", "", ""},
		},
		{
			name: "normal",
			input: [][]string{
				{"one", "1"},
				{"two", "2"},
				{"three", "3"},
			},
			expected: []string{"one=1", "two=2", "three=3", "", ""},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := &bytes.Buffer{}

			input := credentialhandler.NewMapFromArray(c.input)
			err := credentialhandler.WriteProperties(input, w)
			require.Equal(t, err != nil, c.failed, "%v", err)

			assert.Equal(t, c.expected, strings.Split(w.String(), "\n"), w.String())
		})
	}
}

// failingWriter always returns an error on Write
type failingWriter struct{}

func (f *failingWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write failed: disk full")
}

func TestWriteProperties_PropagatesWriteError(t *testing.T) {
	// arrange
	m := credentialhandler.NewMap(3)
	m.Set("protocol", "https")
	m.Set("host", "github.com")
	m.Set("path", "org/repo")

	w := &failingWriter{}

	// act
	err := credentialhandler.WriteProperties(m, w)

	// assert
	require.Error(t, err, "WriteProperties should return error when writer fails")
	assert.Contains(t, err.Error(), "write failed", "error should describe the write failure")
}

func TestConstructURL(t *testing.T) {
	cases := []struct {
		name     string
		input    [][]string
		expected string
		failed   bool
		failure  string
	}{
		{
			name:     "fails on empty",
			input:    [][]string{},
			expected: "",
			failed:   true,
			failure:  "protocol/scheme must be present",
		},
		{
			name: "fails without scheme",
			input: [][]string{
				{"host", "github.com"},
				{"path", "org/repo.git"},
			},
			expected: "",
			failed:   true,
			failure:  "protocol/scheme must be present",
		},
		{
			name: "fails without host",
			input: [][]string{
				{"protocol", "https"},
				{"path", "org/repo.git"},
			},
			expected: "",
			failed:   true,
			failure:  "host must be present",
		},
		{
			name: "fails without path",
			input: [][]string{
				{"protocol", "https"},
				{"host", "github.com"},
			},
			expected: "",
			failed:   true,
			failure:  "path must be present",
		},
		{
			// validating the correct host is handled elsewhere, outside the
			// responsibility of this function
			name: "succeeds with non-Github",
			input: [][]string{
				{"protocol", "https"},
				{"host", "gitlubber.com"},
				{"path", "org/repo.git"},
			},
			expected: "https://gitlubber.com/org/repo.git",
		},
		{
			// the URL may not be correct, but that's OK: the pipeline won't
			// match and the application can't create a token for it.
			name: "succeeds with incorrectly formed path",
			input: [][]string{
				{"protocol", "https"},
				{"host", "github.com"},
				{"path", "org/much-too-long/repo.git"},
			},
			expected: "https://github.com/org/much-too-long/repo.git",
		},
		{
			name: "succeeds when correctly formed",
			input: [][]string{
				{"protocol", "https"},
				{"host", "github.com"},
				{"path", "org/repo.git"},
			},
			expected: "https://github.com/org/repo.git",
		},
		{
			name: "succeeds when correctly formed with unknown keys",
			input: [][]string{
				{"protocol", "https"},
				{"host", "github.com"},
				{"path", "org/repo.git"},
				{"x-host", "gitgrub.com"},
				{"hostlike", "unhostly.com"},
				{"pathymcpathface", "how many paths must we walk down"},
			},
			expected: "https://github.com/org/repo.git",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			input := credentialhandler.NewMapFromArray(c.input)
			url, err := credentialhandler.ConstructRepositoryURL(input)
			require.Equal(t, err != nil, c.failed, "%v", err)

			if c.failed {
				assert.ErrorContains(t, err, c.failure)
			}

			assert.Equal(t, c.expected, url)
		})
	}
}
