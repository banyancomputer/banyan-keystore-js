import { webcrypto } from 'one-webcrypto'
import ecc from '../src/ecc'
import errors from '../src/errors'
import utils from '../src/utils'
import { DEFAULT_CHAR_SIZE } from '../src/constants'
import { KeyUse, EccCurve, HashAlg, SymmAlg, ExportKeyFormat, PublicKey, PrivateKey } from '../src/types'
import { mock, cryptoMethodMock, arrBufEq } from './utils'
import aes from '../src/aes'

describe('ecc mocks', () => {
    cryptoMethodMock({
      desc: 'genKeyPair',
      setMock: fake => webcrypto.subtle.generateKey = fake,
      mockResp: mock.keys,
      simpleReq: () => ecc.genKeyPair(EccCurve.P_384, KeyUse.Exchange),
      simpleParams: [
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
          ['deriveBits']
      ],
      paramChecks: [
        {
          desc: 'handles write keys',
          req: () => ecc.genKeyPair(EccCurve.P_384, KeyUse.Write),
          params: [
            { name: 'ECDSA', namedCurve: 'P-384' },
            true,
            ['sign', 'verify']
          ]
        }
      ],
      shouldThrows: [
        {
          desc: 'throws an error when passing in an invalid use',
          req: () => ecc.genKeyPair(EccCurve.P_384, 'sigBytes' as any),
          error: errors.InvalidKeyUse
        }
      ]
    })
    cryptoMethodMock({
      desc: 'importPublicKey',
      setMock: fake => webcrypto.subtle.importKey = fake,
      mockResp: mock.keys.publicKey,
      expectedResp: mock.keys.publicKey,
      simpleReq: () => ecc.importPublicKey(mock.keyBase64, EccCurve.P_384, KeyUse.Exchange),
      simpleParams: [
        ExportKeyFormat.SPKI,
        utils.base64ToArrBuf(mock.keyBase64),
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
        ['deriveBits']
      ],
      paramChecks: [
        {
          desc: 'handles write keys',
          req: () => ecc.importPublicKey(mock.keyBase64, EccCurve.P_384, KeyUse.Write),
          params: [
            ExportKeyFormat.SPKI,
            utils.base64ToArrBuf(mock.keyBase64),
            { name: 'ECDSA', namedCurve: 'P-384' },
            true,
            ['verify']
          ]
        }
      ],
      shouldThrows: []
    })
    cryptoMethodMock({
      desc: 'sign',
      setMock: fake => webcrypto.subtle.sign = fake,
      mockResp: mock.sigBytes,
      simpleReq: () => ecc.sign(
        mock.msgBytes,
        mock.keys.privateKey
      ),
      simpleParams: [
        { name: 'ECDSA', hash: { name: 'SHA-256' }},
        mock.keys.privateKey,
        mock.msgBytes
      ],
      paramChecks: [
        {
          desc: 'handles multiple hash algorithms',
          req: () => ecc.sign(
            mock.msgBytes,
            mock.keys.privateKey,
            DEFAULT_CHAR_SIZE,
            HashAlg.SHA_512
          ),
          params: (params: any) => params[0]?.hash?.name === 'SHA-512'
        },
      ],
      shouldThrows: []
    })
    cryptoMethodMock({
      desc: 'verify',
      setMock: fake => webcrypto.subtle.verify = fake,
      mockResp: true,
      simpleReq: () => ecc.verify(
        mock.msgBytes,
        mock.sigBytes,
        mock.keys.publicKey
      ),
      simpleParams: [
        { name: 'ECDSA', hash: { name: 'SHA-256' }},
        mock.keys.publicKey,
        mock.sigBytes,
        mock.msgBytes
      ],
      paramChecks: [
        {
          desc: 'handles multiple hash algorithms',
          req: () => ecc.verify(
            mock.msgBytes,
            mock.sigBytes,
            mock.keys.publicKey,
            DEFAULT_CHAR_SIZE,
            HashAlg.SHA_512
          ),
          params: (params: any) => params[0]?.hash?.name === 'SHA-512'
        }
      ],
      shouldThrows: []
    })
    cryptoMethodMock({
      desc: 'encrypt',
      setMock: fake => {
        webcrypto.subtle.encrypt = fake
        webcrypto.subtle.importKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
        webcrypto.subtle.deriveBits = jest.fn(() => new Promise(r => r(mock.derivedBits)))
        webcrypto.subtle.deriveKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
        webcrypto.getRandomValues = jest.fn(() => new Promise(r => r(new Uint8Array(16)))) as any
      },
      mockResp: mock.cipherBytes,
      simpleReq: () => ecc.encrypt(
        mock.msgBytes,
        mock.keys.privateKey,
        mock.keys.publicKey,
        mock.iv
      ),
      paramChecks: [],
      shouldThrows: []
    })
    cryptoMethodMock({
      desc: 'decrypt',
      setMock: fake => {
        webcrypto.subtle.decrypt = fake
        webcrypto.subtle.importKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
        webcrypto.subtle.deriveBits = jest.fn(() => new Promise(r => r(mock.derivedBits)))
        webcrypto.subtle.deriveKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
      },
      mockResp: mock.msgBytes,
      simpleReq: () => ecc.decrypt(
        mock.cipherWithIVBytes,
        mock.keys.privateKey,
        mock.keys.publicKey,
        mock.iv
      ),
      paramChecks: [],
      shouldThrows: []
    })
})
