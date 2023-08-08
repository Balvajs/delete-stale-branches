## delete-stale-branches

Delete all branches that are stale - branches without any associated opened PRs and without any recent commits.

Useful for keeping the repository clean from leftover branches after manually closed PRs.

## Usage

```yaml
name: 'delete-stale-branches'
on:
  schedule:
    - cron: '0 0 * * 1'

jobs:
  delete-stale-branches:
    runs-on: ubuntu-latest
    permissions:
      contents: write # to be able to delete branches
      pull-requests: read # to be able to confirm that branches don't have associated PRs
    steps:
      - uses: balvajs/delete-stale-branches@v1
        with:
          days-to-delete: 120
          dry-run: false
```

## Inputs

| INPUT          | TYPE    | DEFAULT                      | DESCRIPTION                                                                                           |
| -------------- | ------- | ---------------------------- | ----------------------------------------------------------------------------------------------------- |
| days-to-delete | number  | `90`                         | Number of days without activity after which the branch will be deleted                                |
| dry-run        | boolean | `true`                       | If set to true, the action will only log the branches that would be deleted, but will not delete them |
| repository     | string  | `"${{ github.repository }}"` | Repository name and owner in format `"owner/repo"`                                                    |
| token          | string  | `"${{ github.token }}"`      | GitHub token with `pull-requests: read` and `contents: write` permissions                             |

\* required
