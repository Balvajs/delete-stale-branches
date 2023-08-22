/* eslint-disable */
/**
 * This file is generated, don’t edit it manually. Run `pnpm generate` to re-generate.
 */

import * as Types from '../base-graphql-types.js'

export type BranchesQueryVariables = Types.Exact<{
  cursor: Types.InputMaybe<Types.Scalars['String']['input']>
  name: Types.Scalars['String']['input']
  owner: Types.Scalars['String']['input']
}>

export type BranchesQuery = {
  readonly repository: {
    readonly refs: {
      readonly pageInfo: {
        readonly hasNextPage: boolean
        readonly endCursor: string | null
      }
      readonly nodes: ReadonlyArray<{
        readonly name: string
        readonly associatedPullRequests: {
          readonly nodes: ReadonlyArray<{
            readonly number: number
          } | null> | null
        }
        readonly target:
          | { readonly __typename: 'Blob' }
          | { readonly __typename: 'Commit'; readonly committedDate: string }
          | { readonly __typename: 'Tag' }
          | { readonly __typename: 'Tree' }
          | null
      } | null> | null
    } | null
  } | null
}
