# Comprehensive Renovate PR Merge Workflow

This document provides a battle-tested, systematic approach for merging Renovate pull requests. It has been refined through practical experience and captures proven strategies for handling conflicts, verifications, and edge cases.

## Core Principles (NEVER VIOLATE THESE)

1. **ALWAYS verify builds work locally before pushing** 
2. **NEVER force push unless absolutely necessary** - integrate remote changes first
3. **Process PRs individually** - avoid batching to prevent complex conflicts  
4. **Check status after every operation** - don't assume commands succeeded
5. **Wait for CI checks before proceeding** - let GitHub fully process changes
6. **Start fresh from remote for conflicts** - delete local branches to avoid state issues
7. **Preserve user settings and preferences** - respect existing configurations
8. **Preserve information** - when you encounter novel issues, document them as per Phase 4

## Critical Status Detection

The foundation of this workflow is reliable status detection. Use these commands before every decision:

```bash
gh pr view <PR_NUMBER> --json mergeable,mergeStateStatus,state
gh pr checks <PR_NUMBER>
```

**Status Matrix:**
- `"mergeable": "CONFLICTING"` + `"mergeStateStatus": "DIRTY"` → Has merge conflicts, needs resolution
- `"mergeable": "MERGEABLE"` + `"mergeStateStatus": "CLEAN"` → Ready to merge immediately  
- `"mergeable": "MERGEABLE"` + `"mergeStateStatus": "UNSTABLE"` → Mergeable but checks pending
- `"mergeable": "UNKNOWN"` + `"mergeStateStatus": "UNKNOWN"` → Status being computed, wait

## Step-by-Step Workflow

### Phase 1: Discovery and Triage

1. **List open Renovate PRs:**
   ```bash
   gh pr list --state open --author "app/renovate"
   ```

2. **For each PR, collect status:**
   ```bash
   gh pr view <PR_NUMBER> --json title,number,mergeable,mergeStateStatus,state
   gh pr checks <PR_NUMBER>
   ```

3. **Categorize PRs:**
   - **Ready**: `MERGEABLE` + `CLEAN` + all checks pass → proceed to Phase 3
   - **Conflicted**: `CONFLICTING` + `DIRTY` → proceed to Phase 2  
   - **Pending**: `UNKNOWN` or `UNSTABLE` → wait then re-check
   - **Failed**: `MERGEABLE` but checks failing → proceed to Phase 2

### Phase 2: Conflict Resolution and Repair

**CRITICAL: This phase requires starting completely fresh from remote state**

1. **Prepare clean environment:**
   ```bash
   # Handle any local changes first
   git stash  # if needed
   
   # Update main branch
   git checkout main && git pull origin main
   
   # Delete any existing local branch
   git branch -D <PR_BRANCH_NAME> 2>/dev/null || true
   ```

2. **Fresh checkout from remote:**
   ```bash
   gh pr checkout <PR_NUMBER>
   ```

3. **Attempt merge to reveal conflicts:**
   ```bash
   git merge origin/main
   ```

4. **Resolve conflicts based on type:**

   Check the issues available at `.claude/renovate/issues` to see if there is a relevant issue documented.
   If there is, attempt to follow the issue documentation to resolve it.

   **For other conflicts:**
   - Analyze the nature of the change
   - Generally prefer the PR version for dependency updates
   - Preserve existing functionality

5. **CRITICAL: Verify build before proceeding:**
   ```bash
   # For Go repositories
   go build ./...
   
   # For TypeScript/Node.js repositories
   npm run build    # or pnpm build / yarn build
   npm run typecheck  # if available
   ```
   
   **If this fails, you MUST fix it before pushing. Common issues:**
   - **Go**: Missing go.sum entries, incompatible versions
   - **TypeScript**: Missing dependencies, type conflicts, build configuration issues
   - **General**: Breaking changes in dependencies

6. **Fix dependency issues if needed:**
   ```bash
   # For Go repositories
   go get ./...      # Get missing dependencies
   go mod tidy       # Clean up go.mod/go.sum
   go build ./...    # Verify build
   
   # For TypeScript/Node.js repositories  
   npm install       # or pnpm install / yarn install
   npm run typecheck # Verify types if available
   npm run build     # Verify build
   ```

7. **Commit and push resolution:**
   ```bash
   git add .
   git commit -m "fix: resolve merge conflicts and dependencies - <description>"
   git push
   ```

8. **Wait and verify CI:**
   ```bash
   sleep 90  # Critical: let GitHub process the changes
   gh pr view <PR_NUMBER> --json mergeable,mergeStateStatus
   gh pr checks <PR_NUMBER>
   ```

9. **Handle remaining conflicts:**
   If still `CONFLICTING`, integrate remote changes:
   ```bash
   git fetch origin
   git pull --rebase origin <PR_BRANCH_NAME>
   # Resolve any additional conflicts
   git push
   # Wait and check status again
   ```

### Phase 3: Final Merge

Only proceed when ALL conditions are met:
- ✅ `"mergeable": "MERGEABLE"`
- ✅ `"mergeStateStatus": "CLEAN"`  
- ✅ All checks pass
- ✅ Build verified locally

```bash
gh pr review <PR_NUMBER> --approve --body "Approved: <Package> update to <version>. All conflicts resolved, build verified, and checks passing."
gh pr merge <PR_NUMBER> --squash
```

### Phase 4:

If the PR merged contains issues that do not match any known patterns, summarise the issue as well as the solution used and persist it to a document located in .claude/renovate/issues.


### General Patterns

#### Breaking API Changes
**Recognition:** Build fails after dependency resolution
**Strategy:** Check release notes, update calling code if needed
**Examples:** 
- JWT v4→v5 requires code changes
- React 17→18 requires render API changes
- Express 4→5 has middleware changes

## Verification Checkpoints

At each critical step, verify these conditions:

**After conflict resolution:**
- [ ] Build passes without errors
- [ ] No remaining conflict markers in files
- [ ] Dependency versions match PR intent

**After pushing:**
- [ ] CI builds pass
- [ ] No new test failures introduced  
- [ ] Merge status shows `CLEAN`

**Before final merge:**
- [ ] All status checks green
- [ ] No security alerts introduced
- [ ] Dependency update intent preserved

## Troubleshooting Guide

### "Build fails after merge"

**For Go repositories:**
1. Check for missing go.sum entries: `go get ./...`
2. Clean and retry: `go mod tidy && go build ./...`
3. Check for breaking changes in dependency release notes

**For TypeScript/Node.js repositories:**
1. Delete and reinstall dependencies: `rm -rf node_modules && npm install`
2. Check for type issues: `npm run typecheck`
3. Clear build cache: `npm run clean` (if available)
4. Check for breaking changes in dependency release notes

### "PR still shows conflicts after resolution"
1. Verify you pushed your changes: `git status`
2. Wait for GitHub to process: `sleep 90`
3. Check for new remote changes: `git fetch && git status`
4. Integrate remote changes: `git pull --rebase origin <branch>`

### "CI fails but local build works"

**For Go repositories:**
1. Check for test dependencies: `go get -t ./...`
2. Run tests locally: `go test ./...`
3. Check CI logs for environment differences

**For TypeScript/Node.js repositories:**
1. Check for test dependencies: `npm install --include=dev`
2. Run tests locally: `npm test`
3. Check Node.js version differences: `node --version`
4. Check CI logs for environment differences

### "Unrecoverable PR state"
1. Document the intended change
2. Close the PR (Renovate will recreate)
3. Or create manual PR with same intent

## Success Criteria

A successful merge must achieve:
- ✅ PR merged with squash commit
- ✅ All CI checks passing
- ✅ No build regressions introduced
- ✅ Dependency updated to intended version
- ✅ No remaining conflicts in repository
- ✅ Local build verification completed

## Repository-Specific Notes

This workflow should be adapted for each repository's specific:
- Build systems and requirements
- Testing frameworks and commands  
- Dependency management patterns
- CI/CD pipeline requirements

Always preserve existing repository conventions and user preferences while applying this workflow.