import { IWavesCrypto, TBinaryOut, TSeed, ISeedRelated, ISeedEmbeded, TKeyPair } from './interface'
import { randomBytes, randomSeed } from './random'
import { aesEncrypt, aesDecrypt, messageDecrypt, messageEncrypt, sharedKey } from './encryption'
import { base58Encode, base64Decode, base64Encode, base16Decode, base16Encode, base58Decode } from '../conversions/base-xx'
import { _fromIn, _toWords, _fromRawIn, _fromWords } from '../conversions/param'
import { bytesToString, stringToBytes } from '../conversions/string-bytes'
import { concat, split } from './concat-split'
import { _hashChain, sha256, keccak, blake2b } from './hashing'
import { privateKey, address, publicKey, keyPair, seedWithNonce } from './address-keys-seed'
import { signBytes } from './sign'
import { verifyAddress, verifyPublicKey, verifySignature } from './verification'

type TTypesMap = {
  Bytes: Uint8Array
  Base58: string
}

type TDefaultOut = 'Base58'
type TOutput = keyof TTypesMap
type TOptions<T extends TBinaryOut = TDefaultOut, S extends TSeed | undefined = undefined> = { output?: T, seed?: S }
type TWavesCrypto<T extends TBinaryOut = TDefaultOut, S extends TSeed | undefined = undefined> =
  IWavesCrypto<T> & (S extends undefined ? ISeedRelated<T> : ISeedEmbeded<T>)


export const crypto = <TOut extends TOutput = TDefaultOut, S extends TSeed | undefined = undefined>(options?: TOptions<TOut, S>): TWavesCrypto<TTypesMap[TOut], S> => {

  if (options && options.seed == '')
    throw new Error('Empty seed is not allowed.')

  type T = TTypesMap[TOut]

  const c1 = <T1, R>(f: (a: T1) => R) => (a: T1) => () => f(a)
  const c2 = <T1, T2, R>(f: (a: T1, b: T2) => R) => (a: T1) => (b: T2) => f(a, b)
  const c3 = <T1, T2, T3, R>(f: (a: T1, b: T2, c: T3) => R) => (a: T1) => (b: T2, c: T3) => f(a, b, c)

  const toOut = (f: Function) => (...args: any[]): T => {
    const r = f(...args)
    return (!options || options && options.output === 'Base58') ? base58Encode(r) : r
  }

  const toOutKey = (f: Function) => (...args: any[]): TKeyPair => {
    const r = f(...args) as TKeyPair
    return (!options || options && options.output === 'Base58') ? ({ privateKey: base58Encode(r.privateKey), publicKey: base58Encode(r.publicKey) }) : r
  }

  const s = (options && options.seed) ? options.seed as TSeed : undefined

  return <unknown>{
    signBytes: toOut(s ? c3(signBytes)(s) : signBytes),
    keyPair: toOutKey(s ? c1(keyPair) : keyPair),
    publicKey: toOut(s ? c1(publicKey)(s) : publicKey),
    privateKey: toOut(s ? c1(privateKey)(s) : privateKey),
    address: toOut(s ? c2(address)(s) : address),
    blake2b: toOut(blake2b),
    keccak: toOut(keccak),
    sha256: toOut(sha256),
    sharedKey: toOut(sharedKey),
    seedWithNonce: s ? c2(seedWithNonce)(s) : seedWithNonce,
    base64Encode,
    base64Decode,
    base58Encode,
    base58Decode,
    base16Encode,
    base16Decode,
    stringToBytes,
    bytesToString,
    randomSeed,
    randomBytes,
    verifySignature,
    verifyPublicKey,
    verifyAddress,
    messageDecrypt,
    messageEncrypt,
    aesDecrypt,
    aesEncrypt,
    split,
    concat,
  } as TWavesCrypto<T, S>
}


