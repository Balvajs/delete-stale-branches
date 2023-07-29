/**
 * Copyright (c) ProductBoard, Inc.
 * All rights reserved.
 */
import { Octokit } from '@octokit/core'
import { paginateGraphql } from '@octokit/plugin-paginate-graphql'

export const getOctokit = ({ ghToken }: { ghToken: string }) => {
  const OctokitWithPlugins = Octokit.plugin(paginateGraphql)
  return new OctokitWithPlugins({ auth: ghToken })
}
