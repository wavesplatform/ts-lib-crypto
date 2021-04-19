import { TBinaryIn, TChainId, MAIN_NET_CHAIN_ID, PUBLIC_KEY_LENGTH } from './interface'
import { ChaidId } from '../extensions/chain-id'
import { _fromIn } from '../conversions/param'
import { _hashChain } from './hashing'
import { address } from './address-keys-seed'
import axlsign from '../libs/axlsign'

export const verifyAddress = (addr: TBinaryIn, optional?: { chainId?: TChainId, publicKey?: TBinaryIn }): boolean => {

  const chainId = optional ? optional.chainId : undefined

  try {
    const addressBytes = _fromIn(addr)

    if (addressBytes[0] != 1 || (chainId ? addressBytes[1] != ChaidId.toNumber(chainId) : false))
      return false

    const key = addressBytes.slice(0, 22)
    const check = addressBytes.slice(22, 26)
    const keyHash = _hashChain(key).slice(0, 4)

    for (let i = 0; i < 4; i++) {
      if (check[i] != keyHash[i])
        return false
    }

    if (optional && optional.publicKey) {
      const a = address({ publicKey: optional.publicKey }, chainId)
      if (addressBytes.length !== a.length)
        return false

      for (let i = 0; i < a.length; i++) {
        if (a[i] !== addressBytes[i])
          return false
      }
    }

  } catch (ex) {
    return false
  }

  return true
}

export const verifySignature = (publicKey: TBinaryIn, bytes: TBinaryIn, signature: TBinaryIn): boolean => {
  try {
    return axlsign.verify(_fromIn(publicKey), _fromIn(bytes), _fromIn(signature))
  } catch (error) {
    return false
  }
}

export const verifyPublicKey = (publicKey: TBinaryIn): boolean => _fromIn(publicKey).length === PUBLIC_KEY_LENGTH