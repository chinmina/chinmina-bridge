# Synthesise augmented release notes (subagent instructions)

You turn a set of pre-digested PR summaries into finished release notes. This is
the one step that needs judgement: you decide what matters, group it into
themes, and write the prose. Everything you need has already been prepared for
you — you do not need to call the GitHub API or read raw PRs.

You were told a **WORK** directory when you were started, and the output path to
write (`<WORK>/release-notes-<tag>.md`).

## Inputs (all under WORK)

- `meta.json` — `{ repo, tag, prev_tag, compare_url, pr_count }`.
- `header.md` — the rendered boilerplate header. Use it **verbatim** as the top
  of the document; do not edit it.
- `summary/*.md` — one file per PR, each with frontmatter (`pr`, `title`, `url`,
  `category`) and a one/two-sentence summary. This is your source material.

Read `meta.json`, `header.md`, and every file in `summary/`. Do not read
anything outside WORK.

## What to produce

Assemble the document in this order:

1. The contents of `header.md`, unchanged.
2. `## Highlights`
3. `## What's Changed`, with `###` category subsections.
4. The changelog link (exact line): `**Full Changelog**: <compare_url>`

Write the whole thing to `<WORK>/release-notes-<tag>.md`. **Always write the
file fresh, overwriting any existing version** — a file may be left over from an
earlier run against different instructions, so never inspect it and decide "no
change needed". You were asked to produce these notes; produce them.

### `## Highlights` — the part that adds value

GitHub already produces the flat list. Highlights exist to give a reader the
*shape* of the release in under a minute and hook the interested ones into
looking deeper — at the PRs, the docs, the code. It is an invitation to study,
not the study itself. The depth already lives in the linked PRs; your job is to
make someone want to follow them, not to reproduce them.

Write at altitude:

- **Lead with the headline change** in a sentence or two: what a user or
  operator can now do, or what problem is gone. If the release has a single
  story, tell that story and stop.
- **Group the rest into a few themes** — usually two to four for a substantial
  release, each a short paragraph of two or three sentences behind a **bold
  lead-in**. Give the one fact that makes a theme matter (a measured effect, a
  new config flag, the mechanism) and trust the reader to follow the PR for the
  rest. Resist piling on the second and third supporting detail.
- **Prefer prose; use lists sparingly.** A short bulleted list earns its place
  only when you are genuinely enumerating parallel items — say, two or three new
  configuration options. Highlights is not the place to out-bullet the What's
  Changed section; if a list starts growing, turn it back into a sentence.
  Concise means fewer words, not more bullets.
- **Cut what only a maintainer cares about.** Internal refactors, package
  reshuffles, renamed types, and test/tooling churn are not highlights unless
  one of them genuinely *is* the release. They stay in What's Changed.
- **Be honest about scale.** A one-fix patch gets one short paragraph, not a
  manufactured six. Inflating a quiet release reads as noise and teaches the
  reader to skim past the next one.

If one important change needs more than its summary gives, you may read that
single `<WORK>/pr/<n>.md` file — but you are writing a lead-in, not a manual, so
you rarely should. Never bulk-read the PR directory.

### `## What's Changed` — categorised list

Group the PR bullets under `###` headings by each summary's `category`. Render
every bullet in GitHub's exact style so author and PR links render:

```
* <title> by @<author> in #<pr>
```

- The `author` is the login; you have it in each `pr/<n>.md` frontmatter if a
  summary omits it. Bot logins render as e.g. `@renovate[bot]`.
- Order categories by importance for **this** release: headline/feature work
  first, `Dependency Updates` last. Drop empty categories.
- The Haiku categories are a starting point, not gospel. Merge or rename them
  when the release's shape calls for it — e.g. if distributed caching dominates,
  a `### Distributed Caching & Encryption` heading reads better than a generic
  `### Features`. Use judgement; keep it readable.
- Every PR from `summary/` must appear exactly once. Do not invent PRs.

## When done

Reply only with the path you wrote and a two-line summary of the release's
themes (so the orchestrator can relay it). Do not paste the whole document back.
