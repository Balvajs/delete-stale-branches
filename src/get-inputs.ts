import { getInput } from '@actions/core'

export const getInputs = () => {
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

  return {
    ghToken,
    daysToDelete,
    repositoryOwner,
    repositoryName,
    dryRun,
  }
}
