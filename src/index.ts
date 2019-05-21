// Copyright (c) 2018 Yuriy Naydenov
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

import * as CryptoJS from 'crypto-js'
import * as blake from './libs/blake2b'
import { keccak256 } from './libs/sha3'
import base58 from './libs/base58'
import axlsign from './libs/axlsign'

export const libs = {
  CryptoJS,
  blake,
  keccak256,
  base58,
  axlsign,
}

export const concat = (...arrays: (Uint8Array | number[])[]): Uint8Array =>
  arrays.reduce((a, b) => Uint8Array.from([...a, ...b]), new Uint8Array(0)) as Uint8Array

export function buildAddress(publicKeyBytes: Uint8Array, chainId: string = 'W'): string {
  const prefix = [1, chainId.charCodeAt(0)]
  const publicKeyHashPart = hashChain(publicKeyBytes).slice(0, 20)
  const rawAddress = concat(prefix, publicKeyHashPart)
  const addressHash = Uint8Array.from(hashChain(rawAddress).slice(0, 4))
  return base58.encode(concat(rawAddress, addressHash))
}

export function buildSeedHash(seed: Seed): Uint8Array {
  const seedBytes = stringToUint8Array(seed.phrase);
  const nonce = seed.nonce;
  const nonceArray = [0, 0, 0, 0]
  if (nonce && nonce > 0) {
    let remainder = nonce
    for (let i = 3; i >= 0; i--) {
      nonceArray[3 - i] = Math.floor(remainder / 2 ** (i * 8))
      remainder = remainder % 2 ** (i * 8)
    }
  }
  const seedBytesWithNonce = concat(nonceArray, seedBytes)
  const seedHash = hashChain(seedBytesWithNonce)
  return sha256(seedHash)
}

function byteArrayToWordArrayEx(arr: Uint8Array) {
  const len = arr.length
  const words: any = []
  for (let i = 0; i < len; i++) {
    words[i >>> 2] |= (arr[i] & 0xff) << (24 - (i % 4) * 8)
  }
  return (CryptoJS.lib.WordArray.create as any)(words, len)
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

export const stringToUint8Array = (str: string) =>
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

export interface Seed {
  phrase: string
  nonce: number
}

export function Seed(phraseOrSeed: string | Seed, nonce: number = 0): Seed {
  return typeof phraseOrSeed === 'string' ? { phrase: phraseOrSeed, nonce: nonce } : phraseOrSeed;
}

export type KeyPair = PublicKey & PrivateKey

export const keyPair = (seed: string | Seed): KeyPair => {
  const seedHash = buildSeedHash(Seed(seed))
  const keys = axlsign.generateKeyPair(seedHash)
  return {
    private: base58.encode(keys.private),
    public: base58.encode(keys.public),
  }
}

export const publicKey = (seed: string | Seed): string =>
  keyPair(Seed(seed)).public

export const privateKey = (seed: string | Seed): string =>
  keyPair(Seed(seed)).private

export const address = (keyOrSeed: KeyPair | PublicKey | Seed | string, chainId: string = 'W'): string => {
  if ((typeof (keyOrSeed) === 'string') || ('phrase' in keyOrSeed)) {
    const seed = Seed(keyOrSeed);
    return address(keyPair(seed), chainId);
  }
  return buildAddress(base58.decode(keyOrSeed.public), chainId);
}

export const signBytes = (bytes: Uint8Array, seed: string | Seed): string =>
  signWithPrivateKey(bytes, privateKey(Seed(seed)))

export const verifySignature = (publicKey: string, bytes: Uint8Array, signature: string): boolean => {
  const signatureBytes = base58.decode(signature)
  return (
    signatureBytes.length == SIGNATURE_LENGTH &&
    axlsign.verify(base58.decode(publicKey), bytes, signatureBytes)
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

export const hashBytes = (bytes: Uint8Array) => base58.encode(blake2b(bytes))

export const signWithPrivateKey = (dataBytes: Uint8Array, privateKey: string): string => {
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
      return Uint8Array.from(buf)
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
      return nativeArr
    default:
      throw new Error(options.type + ' is unsupported.')
  }
}

const isBrowser = typeof window !== 'undefined' && ({}).toString.call(window) === '[object Window]'
const isNode = typeof global !== 'undefined' && ({}).toString.call(global) === '[object global]'
const isJest = process.env.JEST_WORKER_ID !== undefined

function secureRandom(count: any, options: any) {
  options = options || { type: 'Array' }

  if (isBrowser) {
    return browserRandom(count, options)
  } else if (isNode) {
    return nodeRandom(count, options)
  } else if (isJest) {
    return nodeRandom(count, options)
  } else {
    throw new Error('Your environment is not defined')
  }
}

export function randomUint8Array(length: number): Uint8Array {
  return secureRandom(length, { type: 'Uint8Array' })
}

const charToNibble: Record<string, number> = {
  '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
  a: 10, A: 10, b: 11, B: 11, c: 12, C: 12, d: 13, D: 13, e: 14, E: 14, f: 15, F: 15,
}

const nibbleToChar: string[] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']

export function byteArrayToHexString(bytes: Uint8Array) {
  let str = ''
  for (let i = 0; i < bytes.length; ++i) {
    if (bytes[i] < 0) {
      bytes[i] += 256
    }
    str += nibbleToChar[bytes[i] >> 4] + nibbleToChar[bytes[i] & 0x0F]
  }
  return str
}

export function hexStringToByteArray(str: string) {
  let bytes = []
  let i = 0
  if (0 !== str.length % 2) {
    bytes.push(charToNibble[str.charAt(0)])
    ++i
  }

  for (; i < str.length - 1; i += 2)
    bytes.push((charToNibble[str.charAt(i)] << 4) + charToNibble[str.charAt(i + 1)])

  return bytes
}

export function getSharedKey(privateKeyFrom: string, publicKeyTo: string): Uint8Array {
  const prvk = base58decode(privateKeyFrom)
  const pubk = base58decode(publicKeyTo)
  return axlsign.sharedKey(prvk, pubk)
}

export function getKEK(sharedKey: string, prefix = 'waves'): { KEK: CryptoJS.WordArray, P: Uint8Array } {

  const decodeKey = (k: string) => {
    const key = base58decode(k)
    if (!key || key.length < 32)
      throw new Error('Invalid sharedKey length')
    return key
  }

  const bytesSharedKey = decodeKey(sharedKey)
  const P = stringToUint8Array(prefix)

  const KEK_Bytes = new Uint8Array(bytesSharedKey.length + P.length)
  KEK_Bytes.set(bytesSharedKey)
  KEK_Bytes.set(P, bytesSharedKey.length)

  const KEK = CryptoJS.SHA256(byteArrayToWordArrayEx(KEK_Bytes))

  return {
    KEK,
    P,
  }
}

export function encryptMessage(sharedKey: string, message: string, prefix = 'waves') {
  const { KEK, P } = getKEK(sharedKey, prefix)
  const M = CryptoJS.enc.Utf8.parse(message)
  const CEK_Bytes = randomUint8Array(32)
  const CEK = byteArrayToWordArrayEx(CEK_Bytes)
  const IV_Bytes = randomUint8Array(16)

  const CEK_FOR_HMAC = CEK_Bytes.map((byte, index) => byte | P[index % P.length])
  const Cc = CryptoJS.AES.encrypt(M, CEK, {
    iv: byteArrayToWordArrayEx(IV_Bytes),
    mode: CryptoJS.mode.CTR,
  })
  const C = CryptoJS.enc.Base64.parse(Cc.toString())

  const Mhmac = CryptoJS.HmacSHA256(M, CEK)
  const Ccek = CryptoJS.enc.Base64.parse(CryptoJS.AES.encrypt(CEK, KEK, { mode: CryptoJS.mode.ECB }).toString())
  const CEKhmac = CryptoJS.HmacSHA256(byteArrayToWordArrayEx(CEK_FOR_HMAC), KEK)

  const CcekBytes = wordArrayToByteArrayEx(Ccek)
  const CEKhmacBytes = wordArrayToByteArrayEx(CEKhmac)
  const CBytes = wordArrayToByteArrayEx(C)
  const MhmacBytes = wordArrayToByteArrayEx(Mhmac)


  const packageBytes = new Uint8Array(CcekBytes.length + CEKhmacBytes.length + CBytes.length + MhmacBytes.length + IV_Bytes.length)
  packageBytes.set(CcekBytes)
  packageBytes.set(CEKhmacBytes, CcekBytes.length)
  packageBytes.set(CBytes, CcekBytes.length + CEKhmacBytes.length)
  packageBytes.set(MhmacBytes, CcekBytes.length + CEKhmacBytes.length + CBytes.length)
  packageBytes.set(IV_Bytes, CcekBytes.length + CEKhmacBytes.length + CBytes.length + MhmacBytes.length)

  return CryptoJS.enc.Base64.stringify(byteArrayToWordArrayEx(packageBytes))
}

export function decryptMessage(sharedKey: string, encryptedMessage: string, prefix = 'waves') {
  const { KEK, P } = getKEK(sharedKey, prefix)

  const packageBytes = wordArrayToByteArrayEx(CryptoJS.enc.Base64.parse(encryptedMessage))
  const IV_Bytes = packageBytes.slice(-16)
  const MhmacBytes = packageBytes.slice(-(16 + 32), -16)
  const CcekBytes = packageBytes.slice(0, 48)
  const CEKhmacBytes = packageBytes.slice(48, 48 + 32)
  const CBytes = packageBytes.slice(48 + 32, -(16 + 32))

  const CEK = byteArrayToWordArrayEx(wordArrayToByteArrayEx(CryptoJS.AES.decrypt(
    CryptoJS.enc.Base64.stringify(byteArrayToWordArrayEx(CcekBytes)),
    KEK,
    { mode: CryptoJS.mode.ECB }
  )))

  const CEK_FOR_HMAC = wordArrayToByteArrayEx(CEK).map((byte, index) => byte | P[index % P.length])
  const CEKhmac = wordArrayToByteArrayEx(CryptoJS.HmacSHA256(byteArrayToWordArrayEx(CEK_FOR_HMAC), KEK))

  const isValidKey = CEKhmac.every((v, i) => v === CEKhmacBytes[i])

  if (!isValidKey) {
    throw new Error('Invalid message')
  }

  const M = CryptoJS.AES.decrypt(
    CryptoJS.enc.Base64.stringify(byteArrayToWordArrayEx(CBytes)),
    CEK,
    {
      iv: byteArrayToWordArrayEx(IV_Bytes),
      mode: CryptoJS.mode.CTR,
    })

  const Mhmac = wordArrayToByteArrayEx(CryptoJS.HmacSHA256(byteArrayToWordArrayEx(wordArrayToByteArrayEx(M)), CEK))

  const isValidMessage = Mhmac.every((v, i) => v === MhmacBytes[i])

  if (!isValidMessage) {
    throw new Error('Invalid message')
  }

  return M.toString(CryptoJS.enc.Utf8)
}
