import { webcrypto } from 'one-webcrypto'
import hkdf from '../src/hkdf'
import { mock } from './utils'

describe('hkdf', () => {
    it('implements operation methods', async () => {
      const key = await hkdf.deriveKey(mock.iv, mock.iv)
      expect(key).toBeTruthy()
      expect(key).toHaveProperty('algorithm')
      expect(key).toHaveProperty('type')
    })
  })