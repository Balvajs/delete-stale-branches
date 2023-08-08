import { getInput } from '@actions/core'

export const getInputs = () => {
  const ghToken = getInput('token', { required: true })

  const daysToDeleteInput = getInput('days-to-delete', { required: true })
  const daysToDelete = parseInt(daysToDeleteInput, 10)
  if (
    !daysToDeleteInput.match(/^\d+$/) ||
    Number.isNaN(daysToDelete) ||
    daysToDelete <= 0
  ) {
    throw new Error(
      'Invalid `days-to-delete` value. Must be a positive number or zero.',
    )
  }

  const dryRunInput = getInput('dry-run', { required: true })
  if (!dryRunInput.match('true') && !dryRunInput.match('false')) {
    throw new Error('Invalid `dry-run` value. Must be either `true` or `false`')
  }
  const dryRun = dryRunInput !== 'false'

  const repository = getInput('repository', { required: true })
  if (!repository.match(/^[^/]*\/[^/]*$/)) {
    throw new Error(
      'Invalid `repository` value. Must be in format `owner/repository`.',
    )
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
