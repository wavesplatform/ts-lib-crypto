// Copyright (c) 2018 Yuriy Naydenov
// 
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

import * as CryptoJS from 'crypto-js'
import * as Long from 'long'
import * as blake from './libs/blake2b'
import { keccak256 } from './libs/sha3'
import base58 from './libs/base58'
import axlsign from './libs/axlsign'
import { ValidationResult, noError, mergeValidationResults, isValid } from './validation'

declare function unescape(s: string): string

function buildAddress(publicKeyBytes: Uint8Array, chainId: string = 'W'): string {
  const prefix = [1, chainId.charCodeAt(0)]
  const publicKeyHashPart = hashChain(publicKeyBytes).slice(0, 20)
  const rawAddress = concat(prefix, publicKeyHashPart)
  const addressHash = Uint8Array.from(hashChain(rawAddress).slice(0, 4))
  return base58.encode(concat(rawAddress, addressHash))
}

function buildSeedHash(seedBytes: Uint8Array): Uint8Array {
  const nonce = [0, 0, 0, 0]
  const seedBytesWithNonce = concat(nonce, seedBytes)
  const seedHash = hashChain(seedBytesWithNonce)
  return sha256(seedHash)
}

function byteArrayToWordArrayEx(arr: Uint8Array) {
  const len = arr.length
  const words: any = []
  for (let i = 0; i < len; i++) {
    words[i >>> 2] |= (arr[i] & 0xff) << (24 - (i % 4) * 8)
  }
  return CryptoJS.lib.WordArray.create(words)
}

function wordArrayToByteArrayEx(wordArray: any) {
  let words = wordArray.words
  let sigBytes = wordArray.sigBytes

  let u8 = new Uint8Array(sigBytes)
  for (let i = 0; i < sigBytes; i++) {
    let byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
    u8[i] = byte
  }

  return u8
}

const stringToUint8Array = (str: string) =>
  Uint8Array.from([...unescape(encodeURIComponent(str))].map(c => c.charCodeAt(0)))

export type PUBLIC_KEY_TYPES = string | PublicKey | Uint8Array
export type Option<T> = T | null | undefined

export const publicKeyToString = (pk: PUBLIC_KEY_TYPES) =>
  typeof pk === 'string' ? pk : (pk instanceof Uint8Array ? base58encode(pk) : pk.public)

export const ADDRESS_LENGTH = 26
export const PUBLIC_KEY_LENGTH = 32
export const PRIVATE_KEY_LENGTH = 32
export const SIGNATURE_LENGTH = 64

export function blake2b(input: Uint8Array): Uint8Array {
  return blake.blake2b(input, null, 32)
}

export function keccak(input: Uint8Array): Uint8Array {
  return (keccak256 as any).array(input)
}

export function sha256(input: Uint8Array): Uint8Array {
  const wordArray = byteArrayToWordArrayEx(input)
  const resultWordArray = CryptoJS.SHA256(wordArray)
  return wordArrayToByteArrayEx(resultWordArray)
}

function hashChain(input: Uint8Array): Uint8Array {
  return Uint8Array.from(keccak(blake2b(input)))
}

export const base58encode = (input: Uint8Array): string =>
  base58.encode(input)

export const base58decode = (input: string): Uint8Array =>
  base58.decode(input)

export interface PublicKey {
  public: string
}

export interface PrivateKey {
  private: string
}

export type KeyPair = PublicKey & PrivateKey

export const keyPair = (seed: string): KeyPair => {
  const seedBytes = stringToUint8Array(seed)
  const seedHash = buildSeedHash(seedBytes)
  const keys = axlsign.generateKeyPair(seedHash);
  return {
    private: base58.encode(keys.private),
    public: base58.encode(keys.public)
  }
}

export const publicKey = (seed: string): string =>
  keyPair(seed).public

export const privateKey = (seed: string): string =>
  keyPair(seed).private

export const address = (keyOrSeed: KeyPair | PublicKey | string, chainId: string = 'W'): string =>
  typeof keyOrSeed === 'string' ?
    address(keyPair(keyOrSeed), chainId) :
    buildAddress(base58.decode(keyOrSeed.public), chainId)

export const signBytes = (bytes: Uint8Array, seed: string): string =>
  buildTransactionSignature(bytes, privateKey(seed))

export const verifySignature = (publicKey: string, bytes: Uint8Array, signature: string): boolean => {
  const signatureBytes = BASE58_STRING(signature)
  return (
    signatureBytes.length == SIGNATURE_LENGTH &&
    axlsign.verify(BASE58_STRING(publicKey), bytes, signatureBytes)
  )
}

export function arraysEqual(a: any[] | Uint8Array, b: any[] | Uint8Array): boolean {
  if (a === b) return true
  if (a == null || b == null) return false
  if (a.length != b.length) return false

  for (var i = 0; i < a.length; ++i)
    if (a[i] !== b[i]) return false
  return true
}

export const validateAddress = (addr: string, chainId: string = 'W', publicKey?: string | PublicKey): ValidationResult => {
  const prefix = [1, chainId.charCodeAt(0)]
  const addressBytes = base58decode(addr)

  if (publicKey && publicKeyToString(publicKey))
    return mergeValidationResults(address(publicKey, chainId) !== addr ? 'Invalid addres for publicKey and chainId.' : noError)

  if (addressBytes.length != ADDRESS_LENGTH)
    return [`Address length is ${addressBytes.length} but should be ${ADDRESS_LENGTH}.`]

  const versionAndChainId = mergeValidationResults(
    addressBytes[0] == prefix[0] ? noError : `Address version is ${addressBytes[0]} but ${prefix[0]} is only supported.`,
    addressBytes[1] == prefix[1] ? noError : `Address chainId is ${String.fromCharCode(addressBytes[1])} but ${String.fromCharCode(prefix[1])} is expected.`)

  if (!isValid(versionAndChainId))
    return versionAndChainId

  return mergeValidationResults(arraysEqual(hashChain(addressBytes.slice(0, 22)).slice(0, 4), addressBytes.slice(22, 26)) ? noError : 'Address checksum is invalid.')
}

export const validatePublicKey = (publicKey: PUBLIC_KEY_TYPES): ValidationResult => {
  const pkBytes = base58decode(publicKeyToString(publicKey))
  return mergeValidationResults(
    pkBytes.length == PUBLIC_KEY_LENGTH ? noError : `Public key length is ${pkBytes.length} but should be ${PUBLIC_KEY_LENGTH}.`
  )
}

export const hashBytes = (bytes: Uint8Array) => base58.encode(blake2b(bytes))

const buildTransactionSignature = (dataBytes: Uint8Array, privateKey: string): string => {
  const privateKeyBytes = base58.decode(privateKey)
  const signature = axlsign.sign(privateKeyBytes, dataBytes, randomUint8Array(64))
  return base58.encode(signature)
}

function nodeRandom(count: any, options: any) {
  const crypto = require('crypto')
  const buf = crypto.randomBytes(count)

  switch (options.type) {
    case 'Array':
      return [].slice.call(buf)
    case 'Buffer':
      return buf
    case 'Uint8Array':
      const arr = new Uint8Array(count)
      for (let i = 0; i < count; ++i) {
        arr[i] = buf.readUInt8(i)
      }
      return arr
    default:
      throw new Error(options.type + ' is unsupported.')
  }
}

function browserRandom(count: any, options: any) {
  const nativeArr = new Uint8Array(count)
  const crypto = (global as any).crypto || (global as any).msCrypto
  crypto.getRandomValues(nativeArr)

  switch (options.type) {
    case 'Array':
      return [].slice.call(nativeArr)
    case 'Buffer':
      try {
        const b = new Buffer(1)
      } catch (e) {
        throw new Error('Buffer not supported in this environment. Use Node.js or Browserify for browser support.')
      }
      return new Buffer(nativeArr)
    case 'Uint8Array':
      return nativeArr;
    default:
      throw new Error(options.type + ' is unsupported.')
  }
}

function secureRandom(count: any, options: any) {
  options = options || { type: 'Array' }

  if (((global as any).crypto || (global as any).msCrypto) != undefined) {
    return browserRandom(count, options)
  } else if (typeof exports === 'object' && typeof module !== 'undefined') {
    return nodeRandom(count, options)
  } else {
    throw new Error('Your environment is not defined');
  }
}

export function randomUint8Array(length: number): Uint8Array {
  return secureRandom(length, { type: 'Uint8Array' })
}

export type serializer<T> = (value: T) => Uint8Array

export const concat = (...arrays: (Uint8Array | number[])[]): Uint8Array =>
  arrays.reduce((a, b) => Uint8Array.from([...a, ...b]), new Uint8Array(0)) as Uint8Array

export const empty: Uint8Array = Uint8Array.from([])
export const zero: Uint8Array = Uint8Array.from([0])
export const one: Uint8Array = Uint8Array.from([1])

export const BASE58_STRING: serializer<string> = (value: string) => base58.decode(value)

export const BASE64_STRING: serializer<string> = (value: string) => Uint8Array.from(Buffer.from(value, 'base64'))

export const STRING: serializer<Option<string>> = (value: Option<string>) => value ? stringToUint8Array(value) : empty

export const BYTE: serializer<number> = (value: number) => Uint8Array.from([value])

export const BOOL: serializer<boolean> = (value: boolean) => BYTE(value == true ? 1 : 0)

export const BYTES: serializer<Uint8Array | Buffer | number[]> = (value: Uint8Array | number[]) => Uint8Array.from(value)

export const SHORT: serializer<number> = (value: number) => {
  const b = new Buffer(2)
  b.writeUInt16BE(value, 0)
  return Uint8Array.from([...b])
}
export const INT: serializer<number> = (value: number) => {
  const b = new Buffer(4)
  b.writeInt32BE(value, 0)
  return Uint8Array.from([...b])
}
export const OPTION = <T, R = T | null | undefined>(s: serializer<T>): serializer<R> => (value: R) =>
  value == null
    || (typeof value == 'string' && value.length == 0)
    ? zero : concat(one, s(value as any))

export const LEN = (lenSerializer: serializer<number>) => <T>(valueSerializer: serializer<T>): serializer<T> => (value: T) => {
  const data = valueSerializer(value)
  const len = lenSerializer(data.length)
  return concat(len, data)
}

export const COUNT = (countSerializer: serializer<number>) => <T>(itemSerializer: serializer<T>) => (items: T[]) => {
  const data = concat(...items.map(x => itemSerializer(x)))
  const len = countSerializer(items.length)
  return concat(len, data)
}

export const LONG: serializer<number | string> = (value: number | string) => {
  const l = Long.fromValue(value)
  const b = new Buffer(8)
  b.writeInt32BE(l.getHighBits(), 0)
  b.writeInt32BE(l.getLowBits(), 4)
  return Uint8Array.from(b)
}