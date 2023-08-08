import { Chalk } from 'chalk'

import { getOctokit } from './get-octokit.ts'
import { getRepositoryBranches } from './get-branches.ts'
import { getInputs } from './get-inputs.ts'

// set level to 2, to be able to print colorful messages also in CI
const chalk = new Chalk({ level: 2 })

const pluralizeBranches = (count: number) =>
  count === 1 ? 'branch' : 'branches'

export const deleteStaleBranches = async () => {
  const { ghToken, daysToDelete, dryRun, repositoryName, repositoryOwner } =
    getInputs()

  const octokit = getOctokit({ ghToken })

  const branches = await getRepositoryBranches({
    octokit,
    repositoryOwner,
    repositoryName,
  })

  console.log(
    `Found ${branches.length} ${pluralizeBranches(
      branches.length,
    )} without associated PR.\n\n`,
  )

  let separatorPrinted = false
  for (const { name, daysDiff } of branches) {
    const willBeDeleted = daysDiff > daysToDelete

    if (!separatorPrinted && willBeDeleted) {
      console.log(
        `\n====== Following branches are inactive more than ${daysToDelete} days and will be deleted ======\n`,
      )
      separatorPrinted = true
    }

    console.log(
      `${name} - `,
      chalk[willBeDeleted ? 'red' : 'green'](`${daysDiff} days inactive`),
    )
  }

  const branchesToDelete = branches.filter(
    ({ daysDiff }) => daysDiff > daysToDelete,
  )

  if (dryRun) {
    console.log(
      `\n\nDry run. Would delete ${branchesToDelete.length} ${pluralizeBranches(
        branchesToDelete.length,
      )} that are inactive for more than ${daysToDelete} days.`,
    )

    return
  }

  if (!branchesToDelete.length) {
    console.log('\n\nNo stale branches found.')

    return
  }

  console.log(
    `\n\nDeleting ${branchesToDelete.length} ${pluralizeBranches(
      branchesToDelete.length,
    )} that ${
      branchesToDelete.length === 1 ? 'is' : 'are'
    } inactive for more than ${daysToDelete} days...`,
  )

  const deletionResults = await Promise.allSettled(
    branchesToDelete.map(async ({ name }) => {
      try {
        await octokit.request({
          method: 'DELETE',
          url: `/repos/${repositoryOwner}/${repositoryName}/git/refs/heads/${name}`,
        })
        console.log(`Deleted ${name}`)
      } catch (e) {
        console.error(`Failed to delete ${name}: ${e}`)
      }
    }),
  )

  const failedDeletions = deletionResults.filter(
    ({ status }) => status === 'rejected',
  )

  if (failedDeletions.length) {
    throw new Error(
      `${failedDeletions}/${branchesToDelete.length} branch deletions failed.`,
    )
  }

  console.log(
    `\nSuccessfully deleted ${branchesToDelete.length} ${pluralizeBranches(
      branchesToDelete.length,
    )}.`,
  )
}
