import { webcrypto } from 'one-webcrypto';
import utils from '../utils.js';
import {
  DEFAULT_SALT_LENGTH,
  ECC_EXCHANGE_ALG,
  ECC_WRITE_ALG,
} from '../constants.js';
import {
  EccCurve,
  KeyUse,
  PublicKey,
  ExportKeyFormat,
  SymmKey,
  PrivateKey,
} from '../types.js';
import { checkValidKeyUse } from '../errors.js';

/**
 * Generate a new ECC key pair
 * @param curve The curve to use
 * @param use The use of the key pair, either exchange or write
 */
export async function genKeyPair(
  curve: EccCurve,
  use: KeyUse
): Promise<CryptoKeyPair> {
  checkValidKeyUse(use);
  const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALG : ECC_WRITE_ALG;
  const uses: KeyUsage[] =
    use === KeyUse.Exchange ? ['deriveBits'] : ['sign', 'verify'];
  return webcrypto.subtle.generateKey(
    { name: alg, namedCurve: curve },
    true,
    uses
  );
}

/**
 * Import a public key from a base64 string
 * @param base64Key The base64 encoded public key
 * @param curve The curve to use
 * @param use The use of the key pair, either exchange or write
 */
export async function importPublicKey(
  base64Key: string,
  curve: EccCurve,
  use: KeyUse
): Promise<PublicKey> {
  checkValidKeyUse(use);
  const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALG : ECC_WRITE_ALG;
  const uses: KeyUsage[] =
    use === KeyUse.Exchange ? ['deriveBits'] : ['verify'];
  const buf = utils.base64ToArrBuf(base64Key);
  return webcrypto.subtle.importKey(
    ExportKeyFormat.SPKI,
    buf,
    { name: alg, namedCurve: curve },
    true,
    uses
  );
}

/**
 * Import an escrowed private key
 * @param wrappedPrivateKeyStr The wrapped private key to import
 * @param unwrappingKey The symmetric key to use for unwrapping -- This cannot be AES-KW
 * @param curve The curve to use for the recovered key pair
 * @param use The use of the recovered key pair
 */
export async function importEscrowedPrivateKey(
  wrappedPrivateKeyStr: string,
  unwrappingKey: SymmKey,
  curve: EccCurve,
  use: KeyUse
): Promise<PrivateKey> {
  const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALG : ECC_WRITE_ALG;
  const uses: KeyUsage[] = use === KeyUse.Exchange ? ['deriveBits'] : ['sign'];
  const cipherText = utils.normalizeBase64ToBuf(wrappedPrivateKeyStr);
  const [iv, cipherBytes] = utils.splitCipherText(cipherText);
  const privateKey = await webcrypto.subtle.unwrapKey(
    ExportKeyFormat.PKCS8,
    cipherBytes,
    unwrappingKey,
    {
      name: 'AES-GCM',
      iv,
    },
    {
      name: alg,
      namedCurve: curve,
    },
    true,
    uses
  );
  return privateKey as PrivateKey;
}

export async function importEscrowedKeyPair(
  publicKeyStr: string,
  wrappedPrivateKeyStr: string,
  unwrappingKey: SymmKey,
  curve: EccCurve,
  use: KeyUse
): Promise<CryptoKeyPair> {
  const privateKey = await importEscrowedPrivateKey(
    wrappedPrivateKeyStr,
    unwrappingKey,
    curve,
    use
  );
  const publicKey = await importPublicKey(publicKeyStr, curve, use);
  return { publicKey, privateKey };
}

/**
 * Export a public key to a base64 string
 * @param publicKey The public key to export
 */
export async function exportPublicKey(publicKey: PublicKey): Promise<string> {
  const exp = await webcrypto.subtle.exportKey(ExportKeyFormat.SPKI, publicKey);
  return utils.arrBufToBase64(exp);
}

/**
 * Escrow the private portion of an ECC key pair
 * @param privateKey The private key to escrow
 * @param wrappingKey The symmetric key to use for wrapping
 */
export async function exportEscrowedPrivateKey(
  privateKey: PrivateKey,
  wrappingKey: SymmKey
): Promise<string> {
  const salt = utils.randomBuf(DEFAULT_SALT_LENGTH);
  return await webcrypto.subtle
    .wrapKey(ExportKeyFormat.PKCS8, privateKey, wrappingKey, {
      name: 'AES-GCM',
      iv: salt,
    })
    .then((cipherBuf) => utils.joinCipherText(salt, cipherBuf))
    .then(utils.arrBufToBase64);
}

export default {
  genKeyPair,
  importPublicKey,
  exportPublicKey,
  exportEscrowedPrivateKey,
  importEscrowedPrivateKey,
  importEscrowedKeyPair,
};
