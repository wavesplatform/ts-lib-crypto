import { TBinaryIn, TChainId, MAIN_NET_CHAIN_ID, PUBLIC_KEY_LENGTH } from '.'
import { ChaidId } from './extensions/chain-id'
import { _fromIn } from './conversions/param'
import { _hashChain } from './hashing'
import { address } from './address-keys-seed'
import axlsign from './libs/axlsign'

export const verifyAddress = (addr: TBinaryIn, optional?: { chainId?: TChainId, publicKey?: TBinaryIn }): boolean => {

  const chainId = ChaidId.toNumber(optional ? optional.chainId || MAIN_NET_CHAIN_ID : MAIN_NET_CHAIN_ID)

  try {
    const addressBytes = _fromIn(addr)

    if (addressBytes[0] != 1 || addressBytes[1] != chainId)
      return false

    const key = addressBytes.slice(0, 22)
    const check = addressBytes.slice(22, 26)
    const keyHash = _hashChain(key).slice(0, 4)

    for (let i = 0; i < 4; i++) {
      if (check[i] != keyHash[i])
        return false
    }
  } catch (ex) {
    return false
  }

  if (optional && optional.publicKey) {
    return address({ publicKey: optional.publicKey }, chainId) === addr
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