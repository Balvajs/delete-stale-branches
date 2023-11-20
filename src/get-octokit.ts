import { Octokit } from '@octokit/action'
import { paginateGraphql } from '@octokit/plugin-paginate-graphql'
import fetch from 'node-fetch'

export const getOctokit = ({ ghToken }: { ghToken: string }) => {
  const OctokitWithPlugins = Octokit.plugin(paginateGraphql)
  return new OctokitWithPlugins({ auth: ghToken, request: { fetch } })
}
