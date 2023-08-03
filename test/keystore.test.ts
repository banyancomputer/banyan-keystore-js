import * as KeyStore from '../src/keystore'
import keys from '../src/ecc/keys'
import config from '../src/config'
import idb from '../src/idb'
import { EccCurve, KeyUse } from '../src/types'
import { mock } from './utils'

jest.mock('../src/idb')
jest.mock('../src/ecc/keys')

describe("KeyStore", () => {
  describe("init", () => {

    let response: any
    let fakeStore: jest.SpyInstance
    let fakeGen: jest.SpyInstance
    let fakeCreateifDNE: jest.SpyInstance
    let fakeEccEnabled: jest.SpyInstance

    beforeAll(async () => {
      fakeStore = jest.spyOn(idb, 'createStore')
      fakeStore.mockReturnValue(mock.idbStore)

      fakeGen = jest.spyOn(keys, 'genKeyPair')
      fakeGen.mockReturnValue(mock.keys)

      fakeEccEnabled = jest.spyOn(config, 'eccEnabled')
      fakeEccEnabled.mockResolvedValue(true)

      fakeCreateifDNE = jest.spyOn(idb, 'createIfDoesNotExist')
      fakeCreateifDNE.mockImplementation((_name, makeFn, _store) => {
        makeFn()
      })

      response = await KeyStore.init({ 
        exchangeKeyPairName: 'test-exchange', 
        writeKeyPairName: 'test-write',
        escrowKeyName: 'test-escrow'
      })
      await response.genExchangeKeyPair()
      await response.genWriteKeyPair()
    })

    it('should call createIfDoesNotExist with correct params (exchange key)', () => {
      expect(fakeCreateifDNE.mock.calls[0][0]).toEqual('test-exchange')
      expect(fakeCreateifDNE.mock.calls[0][2]).toEqual(mock.idbStore)
    })

    it('should call createIfDoesNotExist with correct params (write key)', () => {
      expect(fakeCreateifDNE.mock.calls[1][0]).toEqual('test-write')
      expect(fakeCreateifDNE.mock.calls[1][2]).toEqual(mock.idbStore)
    })

    it('should call genKeyPair with correct params (exchange key)', () => {
      expect(fakeGen.mock.calls[0]).toEqual([
        EccCurve.P_384,
        KeyUse.Exchange
      ])
    })

    it('should call genKeyPair with correct params (write key)', () => {
      expect(fakeGen.mock.calls[1]).toEqual([
        EccCurve.P_384,
        KeyUse.Write
      ])
    })
  })
})
