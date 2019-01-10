// Copyright (c) 2018 Yuriy Naydenov
// 
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

import * as CryptoJS from 'crypto-js'
import * as blake from './libs/blake2b'
import { keccak256 } from './libs/sha3'
import base58 from './libs/base58'
import axlsign from './libs/axlsign'
import dictionary from "./dictionary";
import converters from "./libs/converters";

export const libs = {
  CryptoJS,
  blake,
  keccak256,
  base58,
  axlsign
}

export const concat = (...arrays: (Uint8Array | number[])[]): Uint8Array =>
  arrays.reduce((a, b) => Uint8Array.from([...a, ...b]), new Uint8Array(0)) as Uint8Array

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
  options = options || {type: 'Array'}

  if (((global as any).crypto || (global as any).msCrypto) != undefined) {
    return browserRandom(count, options)
  } else if (typeof exports === 'object' && typeof module !== 'undefined') {
    return nodeRandom(count, options)
  } else {
    throw new Error('Your environment is not defined');
  }
}

export function randomUint8Array(length: number): Uint8Array {
  return secureRandom(length, {type: 'Uint8Array'})
}


export function generateNewSeed(length: number) {
  const random = Array.from({length})
    .map(_ => randomUint8Array(4)
      .reduce((acc, next, i) => acc + next * 2 ** (i * 4), 0)
    );

  const wordCount = dictionary.length;
  const phrase = [];

  for (let i = 0; i < length; i++) {
    const wordIndex = random[i] % wordCount;
    phrase.push(dictionary[wordIndex]);
  }

  return phrase.join(' ');
}



function strengthenPassword(password: string, rounds: number = 5000): string {
  while (rounds--) {
    const bytes = converters.stringToByteArray(password);
    const wordArray = converters.byteArrayToWordArrayEx(Uint8Array.from(bytes));
    const resultWordArray = CryptoJS.SHA256(wordArray);
    const byteArrayPassword = converters.wordArrayToByteArrayEx(resultWordArray);
    password = converters.byteArrayToHexString(byteArrayPassword)
  }
  return password;
}

export function encryptSeed(seed: string, password: string, encryptionRounds?: number): string {

  if (!seed || typeof seed !== 'string') {
    throw new Error('Seed is required');
  }

  if (!password || typeof password !== 'string') {
    throw new Error('Password is required');
  }

  password = strengthenPassword(password, encryptionRounds);
  return CryptoJS.AES.encrypt(seed, password).toString();

}


export function decryptSeed(encryptedSeed: string, password: string, encryptionRounds?: number): string {

  if (!encryptedSeed || typeof encryptedSeed !== 'string') {
    throw new Error('Encrypted seed is required');
  }

  if (!password || typeof password !== 'string') {
    throw new Error('Password is required');
  }

  password = strengthenPassword(password, encryptionRounds);
  const hexSeed = CryptoJS.AES.decrypt(encryptedSeed, password);
  return converters.hexStringToString(hexSeed.toString());

}

