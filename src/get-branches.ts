import { debug } from '@actions/core'
import dayjs from 'dayjs'

import { BranchesQuery } from './__generated__/get-branches.graphql.ts'

const branchesQuery = /* GraphQL */ `
  query branches($cursor: String, $name: String!, $owner: String!) {
    repository(owner: $owner, name: $name) {
      refs(refPrefix: "refs/heads/", first: 100, after: $cursor) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          name
          associatedPullRequests(first: 1, states: [OPEN]) {
            nodes {
              number
            }
          }
          target {
            __typename
            ... on Commit {
              committedDate
            }
          }
        }
      }
    }
  }
`

function hasCommitTarget<
  T extends {
    target: {
      __typename: string
    } | null
  } | null,
>(value: T): value is NonNullable<T> & { target: { __typename: 'Commit' } } {
  return value?.target?.__typename === 'Commit'
}

export const getRepositoryBranches = async ({
  octokit,
  repositoryOwner,
  repositoryName,
}: {
  octokit: {
    graphql: {
      paginate: (
        query: string,
        initialParameters?: Record<string, unknown>,
      ) => Promise<BranchesQuery>
    }
  }
  repositoryOwner: string
  repositoryName: string
}) => {
  const { repository } = await octokit.graphql.paginate(branchesQuery, {
    owner: repositoryOwner,
    name: repositoryName,
  })

  const nodes = repository?.refs?.nodes

  if (!nodes) {
    throw new Error('No branches found.')
  }

  debug(
    `Found ${nodes.length} branches in total (including non-stale branches).`,
  )

  return nodes
    .filter(node => node?.associatedPullRequests.nodes?.length === 0)
    .filter(hasCommitTarget)
    .map(node => ({
      ...node,
      daysDiff: dayjs().diff(dayjs(node.target.committedDate), 'd'),
    }))
    .sort((a, b) => a.daysDiff - b.daysDiff)
}
