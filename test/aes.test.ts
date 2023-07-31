import { webcrypto } from 'one-webcrypto'
import aes from '../src/aes'
import utils from '../src/utils'
import { ExportKeyFormat, SymmAlg, SymmKeyLength } from '../src/types'
import { mock, cryptoMethodMock, arrBufEq } from './utils'

describe('aes', () => {
    it('implements key methods', async () => {
      const key = await aes.genKey();
      expect(key).toBeTruthy()
      const exportedKey = await aes.exportKey(key)
      expect(exportedKey).toBeTruthy()
      const importedKey  = await aes.importKey(exportedKey)
      expect(importedKey).toBeTruthy()
    })
    it('implments operation methods', async () => {
      const key = await aes.genKey();
      expect(key).toBeTruthy()
      const cipher = await aes.encrypt(mock.msgStr, key)
      const [ iv, cipherBytes ] = utils.splitCipherText(utils.base64ToArrBuf(cipher))
      expect(iv.byteLength).toEqual(16)
      const msg = await aes.decrypt(cipher, key)
      expect(msg).toEqual(mock.msgStr)
    })
})
