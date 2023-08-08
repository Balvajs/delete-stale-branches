import { getInput } from '@actions/core'
import { getInputs } from './get-inputs.ts'

const expectedInputs: Record<string, string> = {
  token: 'randomString',
  'days-to-delete': '90',
  repository: 'balvajs/delete-stale-branches',
  'dry-run': 'true',
}

jest.mock('@actions/core')

const mockGetInput = (override?: { key: string; value: string }) =>
  (
    getInput as unknown as jest.MockedFunction<typeof getInput>
  ).mockImplementation(key =>
    key === override?.key ? override?.value : expectedInputs[key],
  )

describe('getInputs', () => {
  beforeEach(() => {
    mockGetInput()
  })

  it('works with expected inputs', () => {
    expect(getInputs()).toMatchObject({})
  })

  describe('token', () => {
    it('returns token as string', () => {
      mockGetInput({ key: 'token', value: 'token' })

      expect(getInputs()).toMatchObject({ ghToken: 'token' })
    })
  })

  describe('dry-run', () => {
    it('returns dry-run as boolean', () => {
      mockGetInput({ key: 'dry-run', value: 'false' })

      expect(getInputs()).toMatchObject({ dryRun: false })
    })

    it('fails if dry-run isn’t true or false', () => {
      mockGetInput({ key: 'dry-run', value: '1' })

      expect(getInputs).toThrowError()
    })
  })

  describe('days-to-delete input', () => {
    it('returns days-to-delete as number', () => {
      mockGetInput({ key: 'days-to-delete', value: '42' })

      expect(getInputs()).toMatchObject({ daysToDelete: 42 })
    })

    it('fails if the input is a text', () => {
      mockGetInput({ key: 'days-to-delete', value: 'text' })

      expect(getInputs).toThrowError()
    })

    it('fails if the input is a text with number', () => {
      mockGetInput({ key: 'days-to-delete', value: '4text' })

      expect(getInputs).toThrowError()
    })

    it('fails if the input is a smaller than 0', () => {
      mockGetInput({ key: 'days-to-delete', value: '-1' })

      expect(getInputs).toThrowError()
    })
  })

  describe('repository', () => {
    it('splits repository into repositoryOwner and repositoryName', () => {
      mockGetInput({ key: 'repository', value: 'owner/name' })

      expect(getInputs()).toMatchObject({
        repositoryOwner: 'owner',
        repositoryName: 'name',
      })
    })

    it('fails if the input contains more than one /', () => {
      mockGetInput({ key: 'repository', value: 'owner/name/another' })

      expect(getInputs).toThrowError()
    })
  })
})
