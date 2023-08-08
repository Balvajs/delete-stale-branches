import dayjs from 'dayjs'
import { getRepositoryBranches } from './get-branches.ts'

type BranchOutput = Awaited<ReturnType<typeof getRepositoryBranches>>[number]
type BranchInput = Omit<BranchOutput, 'daysDiff'>

const tenDaysAgo = dayjs().subtract(10, 'd').toISOString()

const inputBranchWithoutOpenedPr: BranchInput = {
  name: 'stale-branch',
  associatedPullRequests: { nodes: [] },
  target: { __typename: 'Commit', committedDate: tenDaysAgo },
}

const inputBranchWithoutCommitTarget: BranchInput = {
  ...inputBranchWithoutOpenedPr,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  target: { __typename: 'UnknownType' } as any,
}

const inputBranchWithOpenedPr: BranchInput = {
  name: 'stale-with-opened-pr',
  associatedPullRequests: { nodes: [{ number: 1 }] },
  target: { __typename: 'Commit', committedDate: tenDaysAgo },
}

const outputBranchWithoutOpenedPr: BranchOutput = {
  ...inputBranchWithoutOpenedPr,
  daysDiff: 10,
}

type Octokit = Parameters<typeof getRepositoryBranches>[0]['octokit']

const createOctokitMock = (
  response: ReturnType<Octokit['graphql']['paginate']>,
): Octokit => ({
  graphql: {
    paginate: async () => response,
  },
})

describe('getRepositoryBranches', () => {
  it('fails if repository is not found', async () => {
    try {
      await getRepositoryBranches({
        octokit: createOctokitMock(Promise.resolve({ repository: null })),
        repositoryName: '',
        repositoryOwner: '',
      })
    } catch (e) {
      expect(e).toBeInstanceOf(Error)
    }
  })

  it('fails if refs are not found', async () => {
    try {
      await getRepositoryBranches({
        octokit: createOctokitMock(
          Promise.resolve({ repository: { refs: null } }),
        ),
        repositoryName: '',
        repositoryOwner: '',
      })
    } catch (e) {
      expect(e).toBeInstanceOf(Error)
    }
  })

  it('fails if refs.nodes doesn’t exist', async () => {
    try {
      await getRepositoryBranches({
        octokit: createOctokitMock(
          Promise.resolve({
            repository: {
              refs: {
                nodes: null,
                pageInfo: { endCursor: null, hasNextPage: false },
              },
            },
          }),
        ),
        repositoryName: '',
        repositoryOwner: '',
      })
    } catch (e) {
      expect(e).toBeInstanceOf(Error)
    }
  })

  it('returns empty array if the refs.nodes is empty', async () => {
    const branches = await getRepositoryBranches({
      octokit: createOctokitMock(
        Promise.resolve({
          repository: {
            refs: {
              nodes: [],
              pageInfo: { endCursor: null, hasNextPage: false },
            },
          },
        }),
      ),
      repositoryName: '',
      repositoryOwner: '',
    })

    expect(branches.length).toEqual(0)
  })

  it('filters out branches that have opened PR', async () => {
    const branches = await getRepositoryBranches({
      octokit: createOctokitMock(
        Promise.resolve({
          repository: {
            refs: {
              nodes: [inputBranchWithOpenedPr, inputBranchWithOpenedPr],
              pageInfo: { endCursor: null, hasNextPage: false },
            },
          },
        }),
      ),
      repositoryName: '',
      repositoryOwner: '',
    })

    expect(branches.length).toEqual(0)
  })

  it('filters out branches that don’t have commit', async () => {
    const branches = await getRepositoryBranches({
      octokit: createOctokitMock(
        Promise.resolve({
          repository: {
            refs: {
              nodes: [inputBranchWithoutCommitTarget],
              pageInfo: { endCursor: null, hasNextPage: false },
            },
          },
        }),
      ),
      repositoryName: '',
      repositoryOwner: '',
    })

    expect(branches.length).toEqual(0)
  })

  it('returns branches that don’t have opened PR', async () => {
    const branches = await getRepositoryBranches({
      octokit: createOctokitMock(
        Promise.resolve({
          repository: {
            refs: {
              nodes: [
                inputBranchWithOpenedPr,
                inputBranchWithoutOpenedPr,
                inputBranchWithOpenedPr,
                inputBranchWithoutOpenedPr,
              ],
              pageInfo: { endCursor: null, hasNextPage: false },
            },
          },
        }),
      ),
      repositoryName: '',
      repositoryOwner: '',
    })

    expect(branches).toEqual([
      outputBranchWithoutOpenedPr,
      outputBranchWithoutOpenedPr,
    ])
  })
})
