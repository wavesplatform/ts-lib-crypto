import { TSeed, INonceSeed, TBytes, TChainId, MAIN_NET_CHAIN_ID, TPublicKey, TBinaryIn, TKeyPair, TPrivateKey } from './interface'
import { Seed } from '../extensions/seed'
import { _hashChain, sha256 } from './hashing'
import { _fromIn } from '../conversions/param'
import { concat } from './concat-split'
import { isPublicKey, isPrivateKey } from './util'
import axlsign from '../libs/axlsign'

export const seedWithNonce = (seed: TSeed, nonce: number): INonceSeed => ({ seed: Seed.toBinary(seed).seed, nonce })

export const buildAddress = (publicKeyBytes: TBytes, chainId: TChainId = MAIN_NET_CHAIN_ID): TBytes => {
  const prefix = [1, typeof chainId === 'string' ? chainId.charCodeAt(0) : chainId]
  const publicKeyHashPart = _hashChain(publicKeyBytes).slice(0, 20)
  const rawAddress = concat(prefix, publicKeyHashPart)
  const addressHash = _hashChain(rawAddress).slice(0, 4)
  return concat(rawAddress, addressHash)
}

const buildSeedHash = (seedBytes: Uint8Array, nonce?: number): TBytes => {
  const nonceArray = [0, 0, 0, 0]
  if (nonce && nonce > 0) {
    let remainder = nonce
    for (let i = 3; i >= 0; i--) {
      nonceArray[3 - i] = Math.floor(remainder / 2 ** (i * 8))
      remainder = remainder % 2 ** (i * 8)
    }
  }
  const seedBytesWithNonce = concat(nonceArray, seedBytes)
  const seedHash = _hashChain(seedBytesWithNonce)
  return sha256(seedHash)
}

export const keyPair = (seed: TSeed): TKeyPair<TBytes> => {
  const { seed: seedBytes, nonce } = Seed.toBinary(seed)

  const seedHash = buildSeedHash(seedBytes, nonce)
  const keys = axlsign.generateKeyPair(seedHash)

  return {
    privateKey: keys.private,
    publicKey: keys.public,
  }
}

export const address = (seedOrPublicKey: TSeed | TPublicKey<TBinaryIn>, chainId: TChainId = MAIN_NET_CHAIN_ID): TBytes =>
  isPublicKey(seedOrPublicKey) ?
    buildAddress(_fromIn(seedOrPublicKey.publicKey), chainId) :
    address(keyPair(seedOrPublicKey), chainId)

export const publicKey = (seedOrPrivateKey: TSeed | TPrivateKey<TBinaryIn>): TBytes =>
  isPrivateKey(seedOrPrivateKey) ?
    axlsign.generateKeyPair(_fromIn(seedOrPrivateKey.privateKey)).public :
    keyPair(seedOrPrivateKey).publicKey

export const privateKey = (seed: TSeed): TBytes =>
  keyPair(seed).privateKey
