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
  const words = []
  for (let i = 0; i < len; i++) {
    words[i >>> 2] |= (arr[i] & 0xff) << (24 - (i % 4) * 8)
  }
  return CryptoJS.lib.WordArray.create(words)
}

function wordArrayToByteArrayEx(wordArray) {
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

export const verifySignature = (publicKey: string, bytes: Uint8Array, signature: string): boolean =>
  axlsign.verify(BASE58_STRING(publicKey), bytes, BASE58_STRING(signature))

export const hashBytes = (bytes: Uint8Array) => base58.encode(blake2b(bytes))

const buildTransactionSignature = (dataBytes: Uint8Array, privateKey: string): string => {
  const privateKeyBytes = base58.decode(privateKey)
  const signature = axlsign.sign(privateKeyBytes, dataBytes, randomUint8Array(64))
  return base58.encode(signature)
}

function nodeRandom(count, options) {
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

function browserRandom(count, options) {
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

function secureRandom(count, options) {
  options = options || { type: 'Array' }

  if (((global as any).crypto || (global as any).msCrypto) != undefined) {
    return browserRandom(count, options)
  } else if (typeof exports === 'object' && typeof module !== 'undefined') {
    return nodeRandom(count, options)
  } else {
    throw new Error('Your environment is not defined');
  }
}

function randomUint8Array(byteCount) {
  return secureRandom(byteCount, { type: 'Uint8Array' })
}

export type serializer<T> = (value: T) => Uint8Array

export const concat = (...arrays: (Uint8Array | number[])[]): Uint8Array =>
  arrays.reduce((a, b) => Uint8Array.from([...a, ...b]), new Uint8Array(0)) as Uint8Array

export const empty: Uint8Array = Uint8Array.from([])
export const zero: Uint8Array = Uint8Array.from([0])
export const one: Uint8Array = Uint8Array.from([1])

export const BASE58_STRING: serializer<string> = (value: string) => base58.decode(value)

export const BASE64_STRING: serializer<string> = (value: string) => Uint8Array.from(Buffer.from(value, 'base64'))

export const STRING: serializer<string> = (value: string) => value ? stringToUint8Array(value) : empty

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
export const OPTION = <T>(s: serializer<T>) => (value: T) =>
  value == undefined
    || value == null
    || (typeof value == 'string' && value.length == 0)
    ? zero : concat(one, s(value))

export const LEN = <T>(lenSerializer: serializer<number>) => (valueSerializer: serializer<T>) => (value: T) => {
  const data = valueSerializer(value)
  const len = lenSerializer(data.length)
  return concat(len, data)
}

export const COUNT = <T>(countSerializer: serializer<number>) => (itemSerializer: serializer<T>) => (items: T[]) => {
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
