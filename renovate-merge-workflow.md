# Renovate PR Merge Workflow

## Prerequisites
- `gh` CLI installed and authenticated
- `git` CLI available
- Repository access with merge permissions

## Process Steps

1. **List Renovate PRs**
   - Find open PRs with title pattern `chore(deps): *`
   - Exclude PRs targeting `main` or `master` branches
   - Command: `gh pr list --state open --json title,baseRefName,number | jq '.[] | select(.title | startswith("chore(deps):")) | select(.baseRefName != "main" and .baseRefName != "master")'`

2. **Select Next PR**
   - Choose the next PR from the filtered list
   - Note PR number for subsequent operations

3. **Validate CI Checks**
   - Check that all required checks have passed
   - Command: `gh pr checks <PR_NUMBER>`
   - If checks failed, document which ones and skip merge

3a. **Handle Build Failures (Language-Specific)**
   - **Go projects**: If builds fail due to dependency issues, check out PR branch and run `go mod tidy`
   - **Node.js projects**: Run `pnpm install` (preferred) or `npm install`/`yarn install` if lock files are outdated
   - **Python projects**: Check for dependency conflicts in requirements files
   - Commit and push fixes if needed before proceeding

4. **Check for Major Version Changes**
   - Review PR description for major version bumps
   - Look for version changes like `1.x.x -> 2.x.x`
   - Check links in PR description for breaking changes

5. **Decision Point**
   - **No major versions + all checks pass**: Approve and merge
     - `gh pr review <PR_NUMBER> --approve`
     - `gh pr merge <PR_NUMBER> --auto --squash` (or preferred merge strategy)
   - **Major versions present**: Investigate breaking changes
     - Review linked changelogs/release notes
     - Research compatibility issues
     - Manual review required before merge

6. **Post-Merge**
   - Verify merge completed successfully
   - Move to next PR in queue

## Commands Reference

```bash
# List qualifying PRs
gh pr list --state open --json title,baseRefName,number | jq '.[] | select(.title | startswith("chore(deps):")) | select(.baseRefName != "main" and .baseRefName != "master")'

# Check PR status
gh pr view <PR_NUMBER>

# Check CI status
gh pr checks <PR_NUMBER>

# View build logs for failures
gh run list --limit 5
gh run view <RUN_ID> --log

# Approve PR
gh pr review <PR_NUMBER> --approve

# Merge PR
gh pr merge <PR_NUMBER> --auto --squash

# Fix Go dependency issues (if build fails)
gh pr checkout <PR_NUMBER>
go mod tidy
git add go.mod go.sum
git commit -m "fix: run go mod tidy"
git push
```

## Notes
- Always verify checks pass before merging
- Major version changes require manual investigation
- Use appropriate merge strategy for repository (squash, merge, rebase)