// Package config loads environment-based service settings and validates their
// combinations. Config and its field tags define operator-facing variables,
// defaults, and required values; validation also enforces dependencies between
// cache, encryption, IAM authentication, and observability settings.
//
// Load supports mounted secret files through an explicit allowlist of _FILE
// alternatives. Inline and file sources are mutually exclusive; file lookup
// errors are collected and returned after environment processing. The GitHub
// app registry payload is loaded here as raw text, with its schema and
// credential-safe validation owned by the github package.
//
// NormalizeBasePath is shared by service routing and the standalone health
// probe so both interpret the configured path prefix consistently.
package config
