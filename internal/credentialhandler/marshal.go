package credentialhandler

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// ReadProperties implements parsing a stream formatted as defined by the Git
// credential storage documentation. Multi-valued properties are not
// implemented -- not required for this system.
//
// Note that the Reader may be fully consumed by this method.
//
// See also: https://git-scm.com/docs/git-credential#IOFMT
func ReadProperties(r io.Reader) (*ArrayMap, error) {
	pairs := NewMap(20)

	// FIXME: limit the number of pairs we read in to prevent DoS attacks

	if r == nil {
		return pairs, nil
	}

	s := bufio.NewScanner(r)

	for s.Scan() {
		line := s.Text()

		if line == "" {
			// empty line terminates input
			break
		}

		// must have a delimiter, key must be valued, skip invalid
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			continue
		}

		pairs.Set(k, v)
	}

	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("failed to read properties: %w", err)
	}

	return pairs, nil
}

func WriteProperties(props *ArrayMap, w io.Writer) error {
	b := bytes.Buffer{}
	i := props.Iter()
	for i.HasNext() {
		k, v := i.Next()

		if k == "" || strings.ContainsAny(k, "\n=\000") {
			return errors.New("key empty or contains invalid character")
		}
		if strings.ContainsAny(v, "\n\000") {
			return errors.New("value empty or contains invalid character")
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')

	// write after serialization, to avoid partial output
	if _, err := b.WriteTo(w); err != nil {
		return fmt.Errorf("failed to write properties: %w", err)
	}

	return nil
}

func ConstructRepositoryURL(props *ArrayMap) (string, error) {
	u := &url.URL{}

	protocol, ok := props.Lookup("protocol")
	if !ok {
		return "", errors.New("protocol/scheme must be present")
	}

	host, ok := props.Lookup("host")
	if !ok {
		return "", errors.New("host must be present")
	}

	path, ok := props.Lookup("path")
	if !ok {
		return "", errors.New("path must be present")
	}

	u.Scheme = protocol
	u.Host = host
	u.Path = path

	return u.String(), nil
}
