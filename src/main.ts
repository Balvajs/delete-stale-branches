import { getInput } from '@actions/core'
import chalk from 'chalk'

import { getOctokit } from './get-octokit.ts'
import { getRepositoryBranches } from './get-branches.ts'

async function run(): Promise<void> {
  process.env['INPUT_DAYS-TO-DELETE'] = '90'

  const ghToken = getInput('token', { required: true })
  const daysToDeleteInput = getInput('days-to-delete', { required: true })
  const dryRun = getInput('dry-run') !== 'false'

  const daysToDelete = parseInt(daysToDeleteInput, 10)

  if (Number.isNaN(daysToDelete) || daysToDelete < 0) {
    console.error('Invalid `days-to-delete` value. Must be a positive number.')
    process.exit(1)
  }

  const repository = getInput('repository', { required: true })

  if (!repository.match(/^[^/]*\/[^/]*$/)) {
    console.error(
      'Invalid `repository` value. Must be in format `owner/repository`.',
    )
    process.exit(1)
  }

  const repositoryOwner = repository.split('/')[0]
  const repositoryName = repository.split('/')[1]

  const octokit = getOctokit({ ghToken })

  const branches = await getRepositoryBranches({
    octokit,
    repositoryOwner,
    repositoryName,
  })

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
      `\n\nDry run. Would delete ${branchesToDelete.length} branches that are inactive for more than ${daysToDelete} days.`,
    )

    return
  }

  console.log(
    `\n\nDeleting ${branchesToDelete.length} branches that are inactive for more than ${daysToDelete} days...`,
  )

  await Promise.all(
    branchesToDelete.map(async ({ name }) => {
      try {
        await octokit.request({
          method: 'DELETE',
          url: `/repos/${repository}/git/refs/heads/${name}`,
        })
      } catch (e) {
        console.error(`Failed to delete ${name}: ${e}`)
      }

      console.log(`Deleted ${name}`)
    }),
  )

  console.log('Done.')
}

run()
