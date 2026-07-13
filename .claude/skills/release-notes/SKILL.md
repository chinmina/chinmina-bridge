---
name: release-notes
description: >-
  Write augmented GitHub release notes for chinmina-bridge — a hand-crafted
  Highlights section synthesised from the actual PR contents, plus a categorised
  What's Changed list — going well beyond GitHub's flat auto-generated notes.
  Use this whenever the user wants to draft, write, augment, improve, or
  "flesh out" release notes, a changelog, or a GitHub release for a tag (e.g.
  "write the release notes for v0.12.0", "augment the v0.11.0 release",
  "turn the auto-generated notes into proper highlights", "the release notes
  are just a flat list, make them good"). Also use for back-filling notes on
  older releases. Reach for this even if the user only says "release notes" or
  names a tag without spelling out the format.
---

# Release notes (augmented)

GitHub's auto-generated release notes are a flat bullet list of PR titles. This
skill produces the **augmented** format: the same boilerplate header, then a
written `## Highlights` section that synthesises what actually changed (grouped
into themes, drawing detail from the PRs themselves), then a `## What's Changed`
list reorganised into `###` categories, then the changelog link.

## How the work is divided — read this first

The expensive part of this task is reading PR descriptions. There can be dozens,
and Renovate/Dependabot PRs alone can be tens of thousands of characters each.
Pulling all of that into this (the orchestrating) context would be slow and
costly, so the work is deliberately pushed elsewhere:

- **Deterministic collection → a bash script.** Fetching PRs, dropping giant bot
  bodies, batching, rendering the header. No model tokens spent on any of it.
- **Bulk PR reading → parallel Haiku subagents.** Cheap and fast; the task is
  mechanical (read a PR, write two sentences + a category).
- **Synthesis → one Sonnet subagent.** The judgement-heavy prose, kept out of
  this context and off the most expensive model.

**As the orchestrator you must not read PR bodies or write the notes prose
yourself.** Your job is to run the script, launch the subagents, verify, and
present. If you find yourself reading `pr/*.md` or drafting Highlights, stop —
that work belongs to a subagent. Doing it here defeats the point of the skill.

Paths below are relative to this skill's own directory; use its absolute path
when building subagent prompts. Set `REPO=<owner>/<repo>` in the environment for
any repo other than the `chinmina/chinmina-bridge` default.

## Step 1 — Collect (bash)

Run, capturing STDOUT:

```bash
bash <skill>/scripts/collect-prs.sh <tag> [previous-tag]
```

Omit `previous-tag` to let GitHub pick the preceding release automatically; pass
it to force a range. The script prints `KEY=value` lines — capture `WORK`,
`BATCH_DIR`, `SUMMARY_DIR`, `NOTES_FILE`, and `PR_COUNT`. Everything downstream
lives under `WORK`. You do **not** need to read any PR files.

## Step 2 — Summarise (parallel Haiku)

List the batch files: `ls <BATCH_DIR>/batch-*`. Spawn **one Haiku subagent per
batch file, all in a single message** so they run concurrently. Use the `Agent`
tool with `subagent_type: general-purpose` and `model: haiku`.

Give each agent this prompt (substitute the real absolute paths — Haiku will not
infer them):

> You summarise GitHub pull requests for release notes — a narrow, mechanical
> task. Read the instructions at `<skill>/references/summarize-prs.md` and
> follow them exactly. Your WORK directory is `<WORK>`. Your BATCH_FILE is
> `<BATCH_DIR>/batch-XX`. Read every PR file listed in that batch file and write
> one summary file per PR as the instructions describe. Reply only with the list
> of PR numbers you wrote.

The detailed rules live in the reference file, so the agent reads them itself —
keep your spawn prompt to the pointer above. When all agents finish, confirm the
count: `ls <SUMMARY_DIR>/*.md | wc -l` should equal `PR_COUNT`.

## Step 3 — Synthesise (one Sonnet agent)

Spawn a single subagent with `subagent_type: general-purpose` and
`model: sonnet`:

> You write augmented release notes from pre-digested PR summaries. Read the
> instructions at `<skill>/references/synthesize-notes.md` and follow them
> exactly. Your WORK directory is `<WORK>`. Write the finished notes to
> `<NOTES_FILE>`. Reply only with the path you wrote and a two-line summary of
> the release's themes.

## Step 4 — Verify

```bash
bash <skill>/scripts/check-coverage.sh <WORK>
```

This fails if any PR is missing, duplicated, or invented. On failure, relay the
diff to the synthesis agent to fix (continue it with `SendMessage`, or respawn
with the mismatch noted) — do not hand-edit the notes yourself.

## Step 5 — Review and publish

Read `NOTES_FILE` now (this is the finished, compact result — reading it here is
fine) and show the user the Highlights plus the file path. Publishing edits a
public release, so **do not publish without explicit confirmation.** On the
user's go-ahead:

```bash
gh release edit <tag> --repo <REPO> --notes-file <NOTES_FILE>
```

## Notes

- Working files land under `.development/tmp/release/relnotes-<tag>/` (a
  gitignored, repo-local directory), not `$TMPDIR` — agents hitting `$TMPDIR`
  trigger repeated permission prompts. Override the base with
  `RELNOTES_WORK_DIR`. The script prints the resolved absolute `WORK` path.
- macOS ships bash 3.2; the scripts avoid bash-4 features (`wait -n`,
  `mapfile`) and use `xargs -P` for capped parallelism.
- Tuning via environment: `BATCH_SIZE` (PRs per Haiku agent, default 5),
  `FETCH_JOBS` (concurrent `gh` calls, default 6), `BODY_LIMIT` (body chars kept
  per human PR, default 8000).
- The header boilerplate is in `assets/header-template.md`. Only the Docker tag
  changes per release; edit that file if the distribution/verification wording
  changes.
