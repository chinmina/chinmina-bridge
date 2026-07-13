#!/bin/bash
#
# Verify that the assembled release notes reference every PR in the release
# exactly once — that none was dropped, duplicated, or invented. Run this after
# synthesis and before publishing; a mismatch means the notes are wrong.
#
# Usage: check-coverage.sh <work-dir> [notes-file]
#   notes-file defaults to the single release-notes-*.md in the work directory.

set -euo pipefail

# Print a timestamped message to STDERR.
err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

# Entry point. Receives the script's arguments as "$@".
main() {
  local work="${1:-}"
  local notes="${2:-}"

  if [[ -z "${work}" ]]; then
    err "usage: check-coverage.sh <work-dir> [notes-file]"
    return 1
  fi

  local expected="${work}/pr-numbers.txt"
  if [[ ! -f "${expected}" ]]; then
    err "PR list not found: ${expected} (run collect-prs.sh first)"
    return 1
  fi

  if [[ -z "${notes}" ]]; then
    notes="$(printf '%s\n' "${work}"/release-notes-*.md | head -n 1)"
  fi
  if [[ ! -f "${notes}" ]]; then
    err "notes file not found: ${notes}"
    return 1
  fi

  local found="${work}/notes-prs.txt"
  grep -oE '#[0-9]+' "${notes}" \
    | grep -oE '[0-9]+' \
    | sort -un \
    > "${found}"

  if diff -q "${expected}" "${found}" > /dev/null; then
    err "OK: all $(wc -l < "${expected}" | tr -d ' ') PRs present exactly once"
    return 0
  fi

  err "MISMATCH: release PR list (<) vs PRs cited in notes (>):"
  diff "${expected}" "${found}" >&2 || true
  return 1
}

main "$@"
