# Summarise pull requests (subagent instructions)

You are one of several parallel workers turning pull requests into short,
uniform summaries for release notes. Your job is narrow and mechanical: read the
PRs you were given and write one small summary file for each. Do not judge which
PRs matter or write any prose beyond the summaries — a later step does that.

You were told two things when you were started:

- a **WORK** directory, and
- a **BATCH_FILE** path — a text file listing the PR files you are responsible
  for, one absolute path per line.

## What to do

1. Read `BATCH_FILE`. Each line is the path to one PR markdown file.
2. Read each of those PR files. Every file has YAML frontmatter (`pr`, `title`,
   `url`, `author`, `bot`, `labels`) followed by the PR description.
3. For **each** PR, write an output file to `<WORK>/summary/<pr>.md` (where
   `<pr>` is the PR number) with **exactly** this structure:

```
---
pr: <number>
title: <copy the title verbatim from the input frontmatter>
url: <copy the url verbatim from the input frontmatter>
category: <ONE category from the list below>
---
<one or two plain sentences: what the change does and, if stated, why>
```

## Rules

- Copy `pr`, `title`, and `url` **unchanged** from the input frontmatter. Do not
  reword the title.
- If the frontmatter says `bot: true`, the summary body is exactly:
  `Dependency update: <title>`. Do not read the body — it was deliberately
  omitted because it is a useless changelog dump.
- For human PRs, keep the summary to **at most two sentences**. State facts only.
  No marketing words ("powerful", "seamless", "robust"). Never begin with
  "This PR".
- If a body is empty or unhelpful, summarise from the title alone.
- Choose exactly one `category` from this fixed list — this is a first-pass
  bucket, the later step may rename or merge categories:
  `Features`, `Performance`, `Security`, `Observability`, `Bug Fixes`,
  `Runtime & Build`, `Build, Test & Tooling`, `Dependency Updates`,
  `Documentation`.

  Guidance for choosing:
  - `bot: true` (any dependency bump) → `Dependency Updates`.
  - title starts `ci:`, `build:`, `test:`, or non-dependency `chore:` →
    `Build, Test & Tooling`.
  - title starts `fix:` → `Bug Fixes` (unless it is clearly a security or
    performance fix).
  - title starts `perf:` → `Performance`.
  - title starts `feat:` → `Features` (unless it is clearly Observability or
    Security work).

## When done

Write the files. Do not print the summaries back. Reply only with the list of PR
numbers you wrote (e.g. `184, 186, 207`).
