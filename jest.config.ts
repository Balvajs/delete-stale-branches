import type { Config } from 'jest'

const esModules = [
  'chalk',
  'node-fetch',
  'data-uri-to-buffer',
  'fetch-blob',
  'formdata-polyfill',
].join('|')

const config: Config = {
  clearMocks: true,
  moduleFileExtensions: ['js', 'ts'],
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.(t|j)s$': '@swc/jest',
  },
  transformIgnorePatterns: [`/node_modules/(?!${esModules})`],
  verbose: true,
  testEnvironment: 'node',
}

export default config
