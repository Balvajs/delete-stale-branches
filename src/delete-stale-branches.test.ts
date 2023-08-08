import { deleteStaleBranches } from './delete-stale-branches.ts'
import { getRepositoryBranches } from './get-branches.ts'
import { getInputs } from './get-inputs.ts'
import { getOctokit } from './get-octokit.ts'

jest.mock('./get-octokit.ts')
jest.mock('./get-branches.ts')
jest.mock('./get-inputs.ts')
jest.spyOn(global.console, 'log').mockImplementation()

const mockGetInputs = (override: Partial<ReturnType<typeof getInputs>> = {}) =>
  (
    getInputs as unknown as jest.MockedFunction<typeof getInputs>
  ).mockReturnValue({
    ghToken: 'random-token',
    daysToDelete: 90,
    dryRun: true,
    repositoryOwner: 'balvajs',
    repositoryName: 'delete-stale-branches',
    ...override,
  })

const mockGetRepositoryBranches = (
  branches: Pick<
    Awaited<ReturnType<typeof getRepositoryBranches>>[number],
    'daysDiff' | 'name'
  >[] = [],
) =>
  (
    getRepositoryBranches as unknown as jest.MockedFunction<
      typeof getRepositoryBranches
    >
  )
    // for the deleteStaleBranches only subset of branch properties is needed
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    .mockResolvedValue(branches as any)

const requestMock = jest.fn()
const getOctokitMock = getOctokit as unknown as jest.MockedFunction<
  typeof getOctokit
>
getOctokitMock
  // for the deleteStaleBranches only request property is needed
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  .mockReturnValue({ request: requestMock } as any)

describe('deleteStaleBranches', () => {
  beforeEach(() => {
    mockGetInputs()
    mockGetRepositoryBranches()
  })

  it('exits early if dry-run is true', async () => {
    mockGetInputs({ dryRun: true })

    await deleteStaleBranches()

    expect(requestMock).not.toBeCalled()
  })

  it('delete stale branches if dry-run is false', async () => {
    mockGetInputs({ dryRun: false })
    mockGetRepositoryBranches([
      { daysDiff: 10, name: 'active-branch' },
      { daysDiff: 90, name: 'branch-1-day-before-stale' },
      { daysDiff: 100, name: 'stale-branch' },
    ])

    await deleteStaleBranches()

    expect(requestMock).toBeCalledTimes(1)
  })
})
