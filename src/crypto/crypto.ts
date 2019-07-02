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

  type ArgsFirstRest<TFunc> = TFunc extends (a: infer A, ...args: infer U) => any ? [A, U] : never
  type ArgsAll<TFunc> = TFunc extends (...args: infer U) => any ? U : never
  type Return<TFunc> = TFunc extends (...args: any) => infer R ? R : unknown

  const c = <TFunc extends Function>(f: TFunc, first: ArgsFirstRest<TFunc>[0]) =>
    (...args: ArgsFirstRest<TFunc>[1]) => f(first, ...args) as Return<TFunc>

  const toOut = <F extends Function>(f: F) => (...args: ArgsAll<F>): TTypesMap[TOut] => {
    const r = f(...args)
    return (!options || options && options.output === 'Base58') ? base58Encode(r) : r
  }

  const toOutKey = <F extends Function>(f: F) => (...args: ArgsAll<F>): TKeyPair<TTypesMap[TOut]> => {
    const r = f(...args) as TKeyPair
    return ((!options || options && options.output === 'Base58') ?
      ({ privateKey: base58Encode(r.privateKey), publicKey: base58Encode(r.publicKey) }) :
      r) as TKeyPair<TTypesMap[TOut]>
  }

  const s = (options && options.seed) ? options.seed as TSeed : undefined

  const seedPart = {
    seedWithNonce: s ? c(seedWithNonce, s) : seedWithNonce,
    signBytes: toOut(s ? c(signBytes, s) : signBytes),
    keyPair: toOutKey(s ? c(keyPair, s) : keyPair),
    publicKey: toOut(s ? c(publicKey, s) : publicKey),
    privateKey: toOut(s ? c(privateKey, s) : privateKey),
    address: toOut(s ? c(address, s) : address),
  } as S extends undefined ? ISeedRelated<TTypesMap[TOut]> : ISeedEmbeded<TTypesMap[TOut]>

  return {
    ...seedPart,
    sharedKey: toOut(sharedKey),
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
  }
}


