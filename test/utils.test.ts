import errors from '../src/errors';
import utils from '../src/utils';
import { EccCurve, KeyUse, PublicKey } from '../src/types';
import * as ecc from '../src/ecc';

const PRETTY_FINGERPRINT_REGEX = new RegExp('^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2})*$');

describe('utils', () => {
  it('uses rejection sampling to generate ', async () => {
    let hasAboveMax = false
    const max = 10

    for (let i = 0; i < 1000; i++) {
      const byte = new Uint8Array(utils.randomBuf(1, { max }))[0]
      if (byte > max) {
        hasAboveMax = true
        break
      }
    }

    expect(hasAboveMax).toBe(false)
  })

  it('returns ArrayBuffer of specified length', async () => {
    const buf1 = new Uint8Array(utils.randomBuf(2))
    const buf2 = new Uint8Array(utils.randomBuf(45, { max: 15 }))

    expect(buf1.length).toBe(2)
    expect(buf2.length).toBe(45)
  })

  it('does not support max values above 255', async () => {
    const fn = () => utils.randomBuf(1, { max: 256 })
    expect(fn).toThrow(errors.InvalidMaxValue)
  })

  it('does not support max values below 1', async () => {
    const fn = () => utils.randomBuf(1, { max: -20 })
    expect(fn).toThrow(errors.InvalidMaxValue)
  })

  it('fingerprints are valid', async () => {
    const keyPair = await ecc.genKeyPair(EccCurve.P_384, KeyUse.Write)
    const fingerprint = await utils.fingerprintEcPublicKey(keyPair.publicKey as PublicKey)
    // Expect the fingerprint to be a sha1 hash
    expect(fingerprint.length).toBe(20);
    const prettyFingerprint = utils.prettyFingerprint(fingerprint)
    expect(prettyFingerprint).toMatch(PRETTY_FINGERPRINT_REGEX)
  })
})
