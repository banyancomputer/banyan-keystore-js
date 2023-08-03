import { webcrypto } from 'one-webcrypto'
import aes from '../src/aes'
import utils from '../src/utils'
import { ExportKeyFormat, SymmAlg, SymmKeyLength } from '../src/types'
import { mock, cryptoMethodMock, arrBufEq } from './utils'

describe('aes mocks', () => {
    describe('keys', () => {
      cryptoMethodMock({
        desc: 'genKey',
        setMock: fake => webcrypto.subtle.generateKey = fake,
        mockResp: mock.symmKey,
        simpleReq: () => aes.genKey(),
        simpleParams: [
          { name: 'AES-GCM', length: 256 },
          true,
          [ 'encrypt', 'decrypt']
        ],
        paramChecks: [
          {
            desc: 'handles only AES-GCM',
            req: () => aes.genKey(),
            params: (params: any) => 
              params[0]?.name === 'AES-GCM' &&
              params[0]?.length === 256
          }
        ],
        shouldThrows: []
      })
      cryptoMethodMock({
        desc: 'importKey',
        setMock: fake => webcrypto.subtle.importKey = fake,
        mockResp: mock.symmKey,
        simpleReq: () => aes.importKey(mock.keyBase64),
        simpleParams: [
          ExportKeyFormat.RAW,
          utils.base64ToArrBuf(mock.keyBase64),
          { name: 'AES-GCM', length: 256 },
          false,
          [ 'encrypt', 'decrypt']
        ],
        paramChecks: [],
        shouldThrows: []
      })
      cryptoMethodMock({
        desc: 'exportKey',
        setMock: fake => webcrypto.subtle.exportKey = fake,
        mockResp: utils.base64ToArrBuf(mock.keyBase64),
        expectedResp: mock.keyBase64,
        simpleReq: () => aes.exportKey(mock.symmKey),
        simpleParams: [
          ExportKeyFormat.RAW,
          mock.symmKey
        ],
        paramChecks: [],
        shouldThrows: []
      })
    })
    describe('operations', () => {
      cryptoMethodMock({
        desc: 'encrypt',
        setMock: fake => {
          webcrypto.subtle.encrypt = fake
          webcrypto.subtle.importKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
          webcrypto.getRandomValues = jest.fn(() => new Promise(r => r(new Uint8Array(16)))) as any
        },
        mockResp: mock.cipherBytes,
        expectedResp: mock.cipherWithIVStr,
        simpleReq: () => aes.importKey(mock.keyBase64).then(key => aes.encrypt(mock.msgStr, key, { iv: mock.iv })),
        paramChecks: [
          {
            desc: 'correctly passes params with AES-GCM',
            req: () => aes.importKey(mock.keyBase64).then(key => aes.encrypt(mock.msgStr, key, { iv: mock.iv })),
            params: (params: any) => (
              params[0]?.name === 'AES-GCM'
              && arrBufEq(params[0]?.iv, mock.iv)
              && params[1] === mock.symmKey
              && arrBufEq(params[2], mock.msgBytes)
            )
          }
        ],
        shouldThrows: []
      })
      cryptoMethodMock({
        desc: 'decrypt',
        setMock: fake => {
          webcrypto.subtle.decrypt = fake
          webcrypto.subtle.importKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
        },
        mockResp: mock.msgBytes,
        expectedResp: mock.msgStr,
        simpleReq: () => aes.importKey(mock.keyBase64).then(key => aes.decrypt(mock.cipherWithIVStr, key)),
        paramChecks: [
          {
            desc: 'correctly passes params with AES-GCM',
            req: () => aes.importKey(mock.keyBase64).then(key => aes.decrypt(mock.cipherWithIVStr, key)),
            params: (params: any) => (
              params[0].name === 'AES-GCM'
              && arrBufEq(params[0].iv, mock.iv)
              && params[1] === mock.symmKey
              && arrBufEq(params[2], mock.cipherBytes)
            )
          }
        ],
        shouldThrows: []
      })
    })
})
