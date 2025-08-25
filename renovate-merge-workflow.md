# Enhanced Renovate PR Merge Workflow

This document outlines our proven workflow for systematically merging Renovate pull requests with conflict resolution strategies.

## Key Workflow Principles

1. **Always check merge status after every operation**
2. **Never force push unless absolutely necessary** - always integrate remote changes first
3. **Wait for CI checks to complete after changes before proceeding**
4. **Start fresh from remote when resolving conflicts**
5. **Verify status at each step before moving to the next**

## Merge Status Detection

Always check PR status using:
```bash
gh pr view <PR_NUMBER> --json mergeable,mergeStateStatus,state
gh pr checks <PR_NUMBER>
```

**Status Indicators:**
- `"mergeable": "CONFLICTING"` + `"mergeStateStatus": "DIRTY"` = has merge conflicts
- `"mergeable": "MERGEABLE"` + `"mergeStateStatus": "CLEAN"` = ready to merge
- `"mergeable": "MERGEABLE"` + `"mergeStateStatus": "UNSTABLE"` = mergeable but checks pending
- `"mergeable": "UNKNOWN"` + `"mergeStateStatus": "UNKNOWN"` = checks pending

## Workflow Steps

### 1. List and Triage PRs
```bash
gh pr list --state open --author "app/renovate"
```

### 2. Check PR Status
For each PR, always check status first:
```bash
gh pr view <PR_NUMBER> --json mergeable,mergeStateStatus,state
gh pr checks <PR_NUMBER>
```

### 3. Simple Merge Path
If `mergeable: "MERGEABLE"`, `mergeStateStatus: "CLEAN"`, and all checks pass:
```bash
gh pr review <PR_NUMBER> --approve --body "Approved: Dependency update. All checks passing."
gh pr merge <PR_NUMBER> --squash
```

### 4. Conflict Resolution Path
If `mergeable: "CONFLICTING"` or `mergeStateStatus: "DIRTY"`:

#### Step 4a: Start Fresh from Remote
```bash
# Update main branch
git checkout main && git pull origin main

# Delete any local branch to start fresh
git branch -D <PR_BRANCH_NAME> 2>/dev/null || true

# Fresh checkout from remote
gh pr checkout <PR_NUMBER>
```

#### Step 4b: Merge Main to See Conflicts
```bash
git merge origin/main
```

#### Step 4c: Resolve Conflicts Manually
- For go.mod conflicts: Keep the PR version (HEAD) since it's the update we want
- For go.sum conflicts: Use `git checkout --ours go.sum` then `go mod tidy`
- For other conflicts: Resolve based on the nature of the update

```bash
# Example for go.mod conflicts - keep HEAD version
# Edit conflicts manually to keep PR version

# For go.sum conflicts
git checkout --ours go.sum
go mod tidy
go build ./...  # Verify build works
```

#### Step 4d: Commit and Push Resolution
```bash
git add .
git commit -m "fix: resolve merge conflicts - keep <description> update"
git push
```

#### Step 4e: Wait and Verify Status
```bash
sleep 90  # Wait for GitHub to process
gh pr view <PR_NUMBER> --json mergeable,mergeStateStatus
gh pr checks <PR_NUMBER>
```

#### Step 4f: Retry if Still Conflicting
If still showing conflicts, may need to integrate remote changes:
```bash
git fetch origin
git pull --rebase origin <PR_BRANCH_NAME>
git push
# Wait and check status again
```

### 5. Final Merge
Only proceed when:
- `mergeable: "MERGEABLE"`
- `mergeStateStatus: "CLEAN"`
- All checks pass

```bash
gh pr review <PR_NUMBER> --approve --body "Approved: <Description> update successfully applied. All conflicts resolved and checks passing."
gh pr merge <PR_NUMBER> --squash
```

## Common Conflict Patterns

### OpenTelemetry Version Conflicts
- **Symptoms**: Conflicts in go.mod/go.sum with otel package versions
- **Resolution**: Keep the PR version (newer version) in conflicts
- **Files**: `go.mod`, `go.sum`

### Dependency Chain Updates
- **Symptoms**: Multiple related packages updating together causing conflicts
- **Resolution**: Keep all PR versions, run `go mod tidy` to resolve dependencies
- **Verification**: Run `go build ./...` to ensure compatibility

## Best Practices

1. **Process PRs individually** - don't batch to avoid complex conflicts
2. **Check status after every change** - don't assume operations succeeded
3. **Always wait for CI** - let GitHub process changes before checking status
4. **Start fresh for conflicts** - delete local branches to avoid state issues
5. **Preserve remote changes** - never force push unless critical
6. **Verify builds work** - run `go build ./...` after conflict resolution

## Emergency Procedures

If a PR gets into an unrecoverable state:
1. Close the PR and let Renovate recreate it
2. Or manually create a new branch with the desired changes
3. Always preserve the intent of the dependency update

## Success Metrics

- PR successfully merged with all checks passing
- No build failures introduced
- Dependency versions correctly updated
- No conflicts remaining in repository