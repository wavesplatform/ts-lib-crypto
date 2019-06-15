import axlsign from './libs/axlsign'
import { IWavesCrypto, TBinaryIn, TBytes, TBinaryOut, TSeed, TPrivateKey, TChainId, MAIN_NET_CHAIN_ID, PUBLIC_KEY_LENGTH, ISeedRelated, ISeedEmbeded, TEST_NET_CHAIN_ID } from './interface'
import { secureRandom } from './random'
import { seedWordsList } from './seed-words-list'
import { aesEncrypt, aesDecrypt, messageDecrypt, messageEncrypt, sharedKey } from './encryption'
import { base58Encode, base64Decode, base64Encode, base16Decode, base16Encode, base58Decode } from './conversions/base-xx'
import { _fromIn, _toWords, _fromRawIn, _fromWords } from './conversions/param'
import { bytesToString, stringToBytes } from './conversions/string-bytes'
import { concat, split } from './concat-split'
import { _hashChain, sha256, keccak, blake2b } from './hashing'
import { privateKey, address, publicKey, keyPair, seed } from './address-keys-seed'
import { isPrivateKey } from './util'

export { IWavesCrypto, TBinaryIn, TBytes, TBase58, TBinaryOut, TBase64, TBase16, TKeyPair, TSeed, IBinarySeed, TPrivateKey, TChainId, MAIN_NET_CHAIN_ID, TPublicKey, PUBLIC_KEY_LENGTH, TRawStringIn, ISeedRelated, ISeedEmbeded } from './interface'
export { seedWordsList as words } from './seed-words-list'
export { secureRandom } from './random'

type TTypesMap = {
  Bytes: Uint8Array
  Base58: string
}

type TDefaultOut = 'Base58'
type TOutput = keyof TTypesMap
type TOptions<T extends TBinaryOut = TDefaultOut, S extends TSeed | undefined = undefined> = { output?: T, seed?: S }
type TWavesCrypto<T extends TBinaryOut = TDefaultOut, S extends TSeed | undefined = undefined> =
  IWavesCrypto<T> & (S extends undefined ? ISeedRelated<T> : ISeedEmbeded<T>)

export const verifySignature = (publicKey: TBinaryIn, bytes: TBinaryIn, signature: TBinaryIn): boolean => {
  try {
    return axlsign.verify(_fromIn(publicKey), _fromIn(bytes), _fromIn(signature))
  } catch (error) {
    return false
  }
}

export const verifyPublicKey = (publicKey: TBinaryIn): boolean => _fromIn(publicKey).length === PUBLIC_KEY_LENGTH






export const randomBytes = (length: number): TBytes =>
  secureRandom(length, 'Uint8Array')

export const randomSeed = (wordsCount: number = 15): string =>
  secureRandom(wordsCount, 'Array32')
    .map(x => seedWordsList[x % seedWordsList.length])
    .join(' ')


export const crypto = <TOut extends TOutput = TDefaultOut, S extends TSeed | undefined = undefined>(options?: TOptions<TOut, S>): TWavesCrypto<TTypesMap[TOut], S> => {

  if (options && options.seed == '')
    throw new Error('Empty seed is not allowed.')

  type T = TTypesMap[TOut]

  const c1 = <T1, R>(f: (a: T1) => R) => (a: T1) => () => f(a)
  const c2 = <T1, T2, R>(f: (a: T1, b: T2) => R) => (a: T1) => (b: T2) => f(a, b)
  const c3 = <T1, T2, T3, R>(f: (a: T1, b: T2, c: T3) => R) => (a: T1) => (b: T2, c: T3) => f(a, b, c)

  const concat = (...arrays: TBinaryIn[]): T =>
    _toOut(arrays.reduce<Uint8Array>((a, b) => Uint8Array.from([...a, ..._fromIn(b)]), new Uint8Array(0)))


  const _toOut = (bytes: TBytes): T => {
    if (options && options.output) {
      return (options.output === 'Base58' ? base58Encode(bytes) : bytes) as T
    }
    return base58Encode(bytes) as T
  }

  const signBytes = (seedOrPrivateKey: TSeed | TPrivateKey<TBinaryIn>, bytes: TBinaryIn, random?: TBinaryIn): T =>
    _toOut(
      axlsign.sign(_fromIn(isPrivateKey(seedOrPrivateKey)
        ? seedOrPrivateKey.privateKey
        : privateKey(seedOrPrivateKey)),
        _fromIn(bytes), _fromIn(random || randomBytes(64)))
    )

  const verifyAddress = (addr: TBinaryIn, optional?: { chainId?: TChainId, publicKey?: TBinaryIn }): boolean => {

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

  const s = (options && options.seed) ? options.seed as TSeed : undefined

  return <unknown>{
    signBytes: s ? c3(signBytes)(s) : signBytes,
    keyPair: s ? c1(keyPair)(s) : keyPair,
    publicKey: s ? c1(publicKey)(s) : publicKey,
    privateKey: s ? c1(privateKey)(s) : privateKey,
    address: s ? c2(address)(s) : address,
    seed,
    blake2b,
    keccak,
    sha256,
    base64Encode,
    base64Decode,
    base58Encode,
    base58Decode,
    base16Encode,
    base16Decode,
    stringToBytes,
    bytesToString,
    randomBytes,
    randomSeed,
    verifySignature,
    verifyPublicKey,
    verifyAddress,
    sharedKey,
    messageDecrypt,
    messageEncrypt,
    aesDecrypt,
    aesEncrypt,
    split,
    concat,
  } as TWavesCrypto<T, S>
}


export const ChaidId = {
  toNumber(chainId: TChainId): number {
    return (typeof chainId === 'string' ? chainId.charCodeAt(0) : chainId)
  },
  isMainnet(chainId: TChainId): boolean {
    return ChaidId.toNumber(chainId) === MAIN_NET_CHAIN_ID
  },
  isTestnet(chainId: TChainId): boolean {
    return ChaidId.toNumber(chainId) === TEST_NET_CHAIN_ID
  },
}
