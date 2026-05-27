# chinmina-bridge maintenance

Chimina receives dependency updates from the OSS renovate tool. This doesn't happen entirely automatically - we have to authorise it to open the PRs on our behalf.

## Open Renovate PR

Navigate to the [Developer Portal for Renovate](https://developer.mend.io/github/chinmina) and select a Renovate run. Click the "Select all" checkbox down the bottom and click the "Create/Rebase" button to have it create the PRs.

## Using Claude to action renovate PRs

The Renovate configuration for this repository targets `main` for all branches, so these PRs won't be automatically merged. You can use Claude to target the PRs for merging. Use the instructions in `.claude/renovate/RENOVATE.md` to do this.

You will need to have `gh` CLI installed and authenticated to your GitHub account.