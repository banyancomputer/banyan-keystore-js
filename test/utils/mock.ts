import utils from '../../src/utils';

const iv = new Uint8Array([1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4])
  .buffer;
const derivedBits = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer;
const msgStr = 'test msg bytes';
const msgBytes = utils.strToArrBuf(msgStr, 16);
const sigStr = 'dGVzdCBzaWduYXR1cmU=';
const sigBytes = utils.base64ToArrBuf(sigStr);
const cipherStr = 'dGVzdCBlbmghUkpUiplJIUNhkMNyeXB0ZWQgYnl0ZXM=';
const cipherBytes = utils.base64ToArrBuf(cipherStr);
const cipherWithIVBytes = utils.joinCipherText(iv, cipherBytes);
const cipherWithIVStr = utils.arrBufToBase64(cipherWithIVBytes);

/* eslint-disable @typescript-eslint/no-explicit-any */
export const mock = {
  idbStore: {
    type: 'fake-store',
  } as any,
  keys: {
    publicKey: { type: 'pub' } as any,
    privateKey: { type: 'priv' } as any,
  } as any,
  writeKeys: {
    publicKey: { type: 'write-pub' } as any,
    privateKey: {
      algorithm: { name: 'ECDSA', namedCurve: 'P-384' },
      type: 'private',
      extractable: true,
      usages: ['sign', 'verify'],
    } as CryptoKey,
  } as any,
  exchnageKeys: {
    publicKey: { type: 'exchange-pub' } as any,
    privateKey: { type: 'exchange-priv' } as any,
  } as any,
  symmKey: { type: 'symm', algorithm: 'AES-GCM' } as any,
  symmKeyName: 'symm-key',
  keyBase64: 'q83vEjRWeJA=',
  iv,
  derivedBits,
  msgStr,
  msgBytes,
  sigStr,
  sigBytes,
  cipherStr,
  cipherBytes,
  cipherWithIVStr,
  cipherWithIVBytes,
};

export default mock;
/* eslint-enable @typescript-eslint/no-explicit-any */
