/**
 * Copyright (c) ProductBoard, Inc.
 * All rights reserved.
 */
import { Octokit } from '@octokit/core'
import { paginateGraphql } from '@octokit/plugin-paginate-graphql'
import fetch from 'node-fetch'

export const getOctokit = ({ ghToken }: { ghToken: string }) => {
  const OctokitWithPlugins = Octokit.plugin(paginateGraphql)
  return new OctokitWithPlugins({ auth: ghToken, request: { fetch } })
}
