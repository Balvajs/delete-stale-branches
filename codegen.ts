/**
 * Copyright (c) ProductBoard, Inc.
 * All rights reserved.
 */

import path from 'path'

import { schema } from '@octokit/graphql-schema'

import { CodegenConfig } from '@graphql-codegen/cli'

const config: CodegenConfig = {
  schema: schema.idl,
  documents: '**/*.ts',
  emitLegacyCommonJSImports: false,
  generates: {
    '/': {
      preset: 'near-operation-file',
      presetConfig: {
        baseTypesPath: path.join(process.cwd(), 'src', 'base-graphql-types.ts'),
        extension: '.graphql.ts',
        folder: '__generated__',
      },
      plugins: [
        {
          add: {
            content: `/* eslint-disable */
               /**
               * This file is generated, don’t edit it manually. Run \`yarn generate\` to re-generate.
               */
             `,
          },
        },
        {
          'typescript-operations': {
            enumsAsTypes: true,
            immutableTypes: true,
            avoidOptionals: true,
            skipTypename: true,
            scalars: {
              DateTime: 'string',
            },
          },
        },
      ],
      hooks: {
        afterOneFileWrite: 'prettier --write',
      },
    },
  },
}

export default config
