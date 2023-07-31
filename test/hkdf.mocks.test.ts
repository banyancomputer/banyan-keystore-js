import { webcrypto } from 'one-webcrypto'
import hkdf from '../src/hkdf'
import { mock, cryptoMethodMock } from './utils'

describe('aes', () => {
    describe('operations', () => {
      cryptoMethodMock({
        desc: 'deriveKey',
        setMock: fake => {
          webcrypto.subtle.deriveBits = fake
          webcrypto.subtle.importKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
        },
        mockResp: mock.symmKey,
        simpleReq: () => hkdf.deriveKey(mock.iv, mock.iv),
        paramChecks: [],
        shouldThrows: []
      }) 
    })
  })