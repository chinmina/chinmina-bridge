# Configuration changes

- Use `go-envconfig` field tags for operator settings, declaring required values and defaults in the tags rather than duplicating environment parsing.
- Mark configuration fields used only for internal injection or tests with `// internal only` so they are distinguishable from operator settings.
- Keep the repository-root `.envrc` aligned when adding or changing environment variables.
