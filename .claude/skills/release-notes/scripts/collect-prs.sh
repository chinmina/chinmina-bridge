#!/bin/bash
#
# Collect and pre-digest the pull requests that make up a release, so that
# augmented release notes can be written without ever loading large PR bodies
# into an agent's context.
#
# Given a release tag, this asks GitHub which PRs are in the release, fetches
# each one as JSON, and reduces every PR to a small markdown file with YAML
# frontmatter (title, url, author, bot flag) plus a bounded body. Bot
# (Renovate/Dependabot) bodies are dropped entirely: the title already says
# everything and the body can run to tens of thousands of characters, which is
# pure token cost with no value for release notes.
#
# The script also renders the boilerplate header, splits the PRs into batch
# files for parallel summarisers, and writes a meta.json for the synthesis step.
# All output lands under a deterministic working directory so later steps can
# find it. Machine-readable results are printed to STDOUT as KEY=value lines.
#
# Usage: collect-prs.sh <tag> [previous-tag]
#
# Environment overrides:
#   REPO              GitHub repository        (default: chinmina/chinmina-bridge)
#   RELNOTES_WORK_DIR base for working files   (default: .development/tmp/release)
#   BATCH_SIZE        PRs per summariser batch (default: 5)
#   FETCH_JOBS        concurrent gh calls      (default: 6)
#   BODY_LIMIT        body chars kept per PR   (default: 8000)
#
# Output lives under a repo-local directory by default rather than $TMPDIR,
# because agents reading/writing under $TMPDIR trigger repeated permission
# prompts. RELNOTES_WORK_DIR overrides the base.

set -euo pipefail

# Split declaration from command substitution so a failing `cd` is not masked
# by `readonly`'s own exit status (ShellCheck SC2155).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
SKILL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly SKILL_DIR

readonly REPO="${REPO:-chinmina/chinmina-bridge}"
readonly BATCH_SIZE="${BATCH_SIZE:-5}"
readonly FETCH_JOBS="${FETCH_JOBS:-6}"
readonly BODY_LIMIT="${BODY_LIMIT:-8000}"

# Print a timestamped message to STDERR (progress/errors, kept off STDOUT so the
# KEY=value results stay machine-parseable).
err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

# Fetch one PR as JSON into PR_DIR. Exported so xargs can call it in parallel.
fetch_pr() {
  local number="$1"
  gh pr view "${number}" --repo "${REPO}" \
    --json number,title,author,body,labels,url \
    > "${PR_DIR}/${number}.json"
}
export -f fetch_pr
export REPO

# Entry point. Receives the script's arguments as "$@".
main() {
  local tag="${1:-}"
  local prev_tag="${2:-}"

  if [[ -z "${tag}" ]]; then
    err "usage: collect-prs.sh <tag> [previous-tag]"
    return 1
  fi

  # Resolve the working base to an absolute path so the paths printed for the
  # orchestrator and its subagents are unambiguous regardless of their cwd.
  local work_base="${RELNOTES_WORK_DIR:-.development/tmp/release}"
  mkdir -p "${work_base}"
  work_base="$(cd "${work_base}" && pwd)"
  local work="${work_base}/relnotes-${tag}"
  # PR_DIR is consumed by the exported fetch_pr, so it must be global+exported.
  PR_DIR="${work}/pr"
  local summary_dir="${work}/summary"
  local batch_dir="${work}/batches"
  export PR_DIR
  mkdir -p "${PR_DIR}" "${summary_dir}" "${batch_dir}"

  # Ask GitHub which PRs make up the release. Omitting previous_tag_name lets
  # GitHub pick the preceding tag automatically; pass one to override.
  local notes_json="${work}/generate-notes.json"
  if [[ -n "${prev_tag}" ]]; then
    gh api "repos/${REPO}/releases/generate-notes" \
      -f tag_name="${tag}" \
      -f previous_tag_name="${prev_tag}" \
      > "${notes_json}"
  else
    gh api "repos/${REPO}/releases/generate-notes" \
      -f tag_name="${tag}" \
      > "${notes_json}"
  fi

  # The generated body lists one PR per line and ends with a compare URL.
  local pr_numbers="${work}/pr-numbers.txt"
  jq -r '.body' "${notes_json}" \
    | grep -oE 'pull/[0-9]+' \
    | grep -oE '[0-9]+' \
    | sort -un \
    > "${pr_numbers}"

  local pr_count
  pr_count="$(wc -l < "${pr_numbers}" | tr -d ' ')"
  if [[ "${pr_count}" -eq 0 ]]; then
    err "no PRs found for ${tag}; nothing to do"
    return 1
  fi

  local compare_url
  compare_url="$(jq -r '.body' "${notes_json}" \
    | grep -oE 'https://github.com/[^ ]+/compare/[^ )]+' \
    | tail -n 1)"
  if [[ -z "${compare_url}" ]]; then
    compare_url="https://github.com/${REPO}/compare/${prev_tag}...${tag}"
  fi

  # Fetch every PR in parallel, capped at FETCH_JOBS concurrent calls. macOS
  # ships bash 3.2, so xargs -P is used instead of `wait -n` job control.
  xargs -P "${FETCH_JOBS}" -I '{}' \
    bash -c 'fetch_pr "$@"' _ '{}' < "${pr_numbers}"

  # Reduce each PR JSON to a compact markdown record. This is where the huge
  # Renovate bodies get dropped, before any model reads them.
  local pr_json number
  for pr_json in "${PR_DIR}"/*.json; do
    number="$(jq -r '.number' "${pr_json}")"
    jq -r --argjson limit "${BODY_LIMIT}" -f "${SCRIPT_DIR}/pr-digest.jq" \
      "${pr_json}" > "${PR_DIR}/${number}.md"
  done

  # Split the PR markdown files into batches for parallel summarisers.
  printf '%s\n' "${PR_DIR}"/*.md > "${work}/pr-files.txt"
  split -l "${BATCH_SIZE}" -a 2 "${work}/pr-files.txt" "${batch_dir}/batch-"

  # Render the boilerplate header with the release tag substituted in.
  sed "s|__TAG__|${tag}|g" "${SKILL_DIR}/assets/header-template.md" \
    > "${work}/header.md"

  # Record release metadata for the synthesis step.
  jq -n \
    --arg repo "${REPO}" \
    --arg tag "${tag}" \
    --arg prev "${prev_tag}" \
    --arg compare "${compare_url}" \
    --argjson count "${pr_count}" \
    '{repo: $repo, tag: $tag, prev_tag: $prev,
      compare_url: $compare, pr_count: $count}' \
    > "${work}/meta.json"

  local batch_count
  batch_count="$(printf '%s\n' "${batch_dir}"/batch-* | wc -l | tr -d ' ')"

  printf 'WORK=%s\n' "${work}"
  printf 'PR_COUNT=%s\n' "${pr_count}"
  printf 'BATCH_COUNT=%s\n' "${batch_count}"
  printf 'BATCH_DIR=%s\n' "${batch_dir}"
  printf 'SUMMARY_DIR=%s\n' "${summary_dir}"
  printf 'NOTES_FILE=%s\n' "${work}/release-notes-${tag}.md"
  err "collected ${pr_count} PRs for ${tag} into ${work} (${batch_count} batches)"
}

main "$@"
