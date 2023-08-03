import ecc from '../src/ecc'
import { KeyUse, EccCurve, PrivateKey } from '../src/types'
import aes from '../src/aes'
import { mock } from './utils'
import utils from '../src/utils'
import { DEFAULT_CHAR_SIZE } from '../src/constants'

describe('ecc', () => {
    // Unset the mock
    it('implements key methods', async () => {
      // Generate a key pair
      const keys = await ecc.genKeyPair(EccCurve.P_384, KeyUse.Exchange)
      expect(keys).toBeTruthy()
      expect(keys).toHaveProperty('publicKey')
      expect(keys).toHaveProperty('privateKey')

      const exportedPublicKey = await ecc.exportPublicKey(keys.publicKey as CryptoKey)
      expect(exportedPublicKey).toBeTruthy()
      const imported = await ecc.importPublicKey(exportedPublicKey, EccCurve.P_384, KeyUse.Exchange)
      expect(imported).toBeTruthy()
      
      const wrappingKey = await aes.genKey(['wrapKey', 'unwrapKey']);
      const escrowedPrivateKey = await ecc.exportEscrowedPrivateKey(keys.privateKey as PrivateKey, wrappingKey);
      const unwrappedPrivateKey = await ecc.importEscrowedKeyPair(exportedPublicKey, escrowedPrivateKey, wrappingKey, EccCurve.P_384,  KeyUse.Exchange);
      expect(unwrappedPrivateKey).toBeTruthy();
    })

    it('implements operation methods', async () => {
        const w_keys = await ecc.genKeyPair(EccCurve.P_384, KeyUse.Write)
        expect(w_keys).toBeTruthy()
        const e_keys = await ecc.genKeyPair(EccCurve.P_384, KeyUse.Exchange)
        expect(e_keys).toBeTruthy()
        // Sign and verify
        const msg = 'hello world'
        const sig = await ecc.sign(msg, w_keys.privateKey as PrivateKey)
        expect(sig).toBeTruthy()
        const verified = await ecc.verify(msg, sig, w_keys.publicKey as CryptoKey)
        expect(verified).toBeTruthy()

        // Encrypt and decrypt
        const msgBytes = utils.strToArrBuf(msg, DEFAULT_CHAR_SIZE);
        const cipher = await ecc.encrypt(msgBytes, e_keys.privateKey as PrivateKey, e_keys.publicKey as CryptoKey, mock.iv)
        expect(cipher).toBeTruthy()
        const [ iv, eh ] = utils.splitCipherText(cipher)
        expect(iv.byteLength).toEqual(16)
        const decrypted = await ecc.decrypt(cipher, e_keys.privateKey as PrivateKey, e_keys.publicKey as CryptoKey, mock.iv)
        expect(decrypted).toEqual(msgBytes)
    });
})
