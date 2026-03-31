package config

import (
	"fmt"
	"strings"
)

// NormalizeBasePath validates and normalizes a base path for use as a URL path
// prefix. It ensures a leading slash, strips trailing slashes, and rejects
// paths containing double slashes. Empty or whitespace-only input returns an
// empty string (meaning no prefix). A bare "/" is treated as empty.
func NormalizeBasePath(basePath string) (string, error) {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		return "", nil
	}

	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}

	basePath = strings.TrimRight(basePath, "/")
	if basePath == "" {
		return "", nil
	}

	if strings.Contains(basePath, "//") {
		return "", fmt.Errorf("base path %q contains double slashes", basePath)
	}

	return basePath, nil
}
