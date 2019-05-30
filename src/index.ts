// Copyright (c) 2018 Yuriy Naydenov
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

import * as CryptoJS from 'crypto-js'
import * as blake from './libs/blake2b'
import { keccak256 } from './libs/sha3'
import base58 from './libs/base58'
import axlsign from './libs/axlsign'
import { IWavesCrypto, TBinaryIn, TBytes, TBase58, TBinaryOut, TBase64, TBase16, TKeyPair, TSeed, ISeedWithNonce, TPrivateKey, TChainId, MAIN_NET_CHAIN_ID, TPublicKey, PUBLIC_KEY_LENGTH, TRawIn } from './crypto'
export { IWavesCrypto, TBinaryIn, TBytes, TBase58, TBinaryOut, TBase64, TBase16, TKeyPair, TSeed, ISeedWithNonce, TPrivateKey, TChainId, MAIN_NET_CHAIN_ID, TPublicKey } from './crypto'
import { secureRandom } from './random'

export const output = {
  Bytes: Uint8Array.from([]),
  Base58: '',
}

type TOptions<T extends TBinaryOut> = { output: T }
type Words = CryptoJS.LibWordArray | CryptoJS.WordArray

export const crypto = <T extends TBinaryOut = TBytes>(options?: TOptions<T>): IWavesCrypto<T> => {

  const isWords = (val: any): val is Words =>
    (<CryptoJS.LibWordArray>val).words !== undefined ||
    (<CryptoJS.WordArray>val).key !== undefined

  const isUint8Array = (val: Uint8Array | number[]): val is Uint8Array =>
    (<Uint8Array>val).buffer !== undefined

  const isString = (val: any): val is string =>
    typeof val === 'string'

  const isSeedWithNonce = (val: any): val is ISeedWithNonce =>
    (<ISeedWithNonce>val).nonce !== undefined

  const isPublicKey = <T extends TBinaryIn>(val: any): val is TPublicKey<T> =>
    (<TPublicKey>val).publicKey !== undefined

  const isPrivateKey = <T extends TBinaryIn>(val: any): val is TPrivateKey<T> =>
    (<TPrivateKey>val).privateKey !== undefined

  const decomposeSeed = (seed: TSeed): { seed: Uint8Array, nonce?: number } => {
    if (isSeedWithNonce(seed))
      return { seed: decomposeSeed(seed.seed).seed, nonce: seed.nonce }

    if (isString(seed))
      return { seed: stringToBytes(seed), nonce: undefined }

    return { seed: fromIn(seed), nonce: undefined }
  }

  const split = (binary: TBinaryIn, ...sizes: number[]): TBytes[] => {
    const r = sizes.reduce<{ arr: TBytes, r: TBytes[] }>((a, s) => ({ arr: a.arr.slice(s), r: [...a.r, a.arr.slice(0, s)] }), { arr: fromIn(binary), r: [] })
    return [...r.r, r.arr]
  }

  const chainIdToNumber = (chainId: TChainId): number =>
    typeof chainId === 'string' ? chainId.charCodeAt(0) : chainId

  const hashChain = (input: TBytes): TBytes =>
    fromIn(keccak(blake2b(input)))

  const concat = (...arrays: (TBinaryIn | Words)[]): TBytes =>
    arrays.reduce<Uint8Array>((a, b) => Uint8Array.from([...a, ...(isWords(b) ? fromWords(b) : fromIn(b))]), new Uint8Array(0))

  const byteArrayToWordArrayEx = (arr: Uint8Array) => {
    const len = arr.length
    const words: any = []
    for (let i = 0; i < len; i++) {
      words[i >>> 2] |= (arr[i] & 0xff) << (24 - (i % 4) * 8)
    }
    return (CryptoJS.lib.WordArray.create as any)(words, len)
  }

  const wordArrayToByteArrayEx = (wordArray: any) => {
    let words = wordArray.words
    let sigBytes = wordArray.sigBytes

    let u8 = new Uint8Array(sigBytes)
    for (let i = 0; i < sigBytes; i++) {
      let byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
      u8[i] = byte
    }

    return u8
  }

  const fromWords = (inValue: Words): TBytes =>
    wordArrayToByteArrayEx(inValue)

  const fromIn = (inValue: TBinaryIn): TBytes => {
    if (isString(inValue))
      return base58Decode(inValue)

    if (isUint8Array(inValue))
      return inValue

    return Uint8Array.from(inValue)
  }

  const fromRawIn = (inValue: TBinaryIn): TBytes => {
    if (isString(inValue))
      return stringToBytes(inValue)

    if (isUint8Array(inValue))
      return inValue

    return Uint8Array.from(inValue)
  }

  const toOut = (bytes: TBytes): T => {
    if (typeof (options || { output: output.Bytes }).output == 'string')
      return base58Encode(bytes) as T

    return bytes as T
  }

  const convert = (inValue: TBinaryIn): T => toOut(fromIn(inValue))

  const blake2b = (input: TBinaryIn): T =>
    convert(blake.blake2b(fromIn(input), null, 32))

  const keccak = (input: TBinaryIn): T =>
    convert(keccak256.array(fromIn(input)))

  const sha256 = (input: TBinaryIn): T => {
    const wordArray = byteArrayToWordArrayEx(fromIn(input))
    const resultWordArray = CryptoJS.SHA256(wordArray)
    return toOut(wordArrayToByteArrayEx(resultWordArray))
  }

  const base64Encode = (input: TBinaryIn): TBase64 =>
    CryptoJS.enc.Base64.stringify(byteArrayToWordArrayEx(fromIn(input)))

  const base64Decode = (input: TBase64): TBytes =>
    wordArrayToByteArrayEx(CryptoJS.enc.Base64.parse(input))

  const base58Encode = (input: TBinaryIn): TBase58 =>
    base58.encode(fromIn(input))

  const base58Decode = (input: TBase58): TBytes =>
    base58.decode(input)

  const base16Encode = (input: TBinaryIn): TBase16 =>
    CryptoJS.enc.Hex.stringify(byteArrayToWordArrayEx(fromIn(input)))

  const base16Decode = (input: TBase16): TBytes =>
    wordArrayToByteArrayEx(CryptoJS.enc.Hex.parse(input))

  const stringToBytes = (str: string): TBytes =>
    Uint8Array.from([...unescape(encodeURIComponent(str))].map(c => c.charCodeAt(0)))

  const buildSeedHash = (seedBytes: Uint8Array, nonce?: number): Uint8Array => {
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
    return fromIn(sha256(seedHash))
  }

  const keyPair = (seed: TSeed): TKeyPair<T> => {
    const { seed: seedBytes, nonce } = decomposeSeed(seed)

    const seedHash = buildSeedHash(seedBytes, nonce)
    const keys = axlsign.generateKeyPair(seedHash)
    return {
      privateKey: toOut(keys.private),
      publicKey: toOut(keys.public),
    }
  }

  const publicKey = (seed: TSeed): T =>
    keyPair(seed).publicKey

  const privateKey = (seed: TSeed): T =>
    keyPair(seed).privateKey

  const buildAddress = (publicKeyBytes: TBytes, chainId: TChainId = MAIN_NET_CHAIN_ID): T => {
    const prefix = [1, typeof chainId === 'string' ? chainId.charCodeAt(0) : chainId]
    const publicKeyHashPart = hashChain(publicKeyBytes).slice(0, 20)
    const rawAddress = concat(prefix, publicKeyHashPart)
    const addressHash = hashChain(rawAddress).slice(0, 4)
    return toOut(concat(rawAddress, addressHash))
  }

  const address = (seedOrPublicKey: TSeed | TPublicKey<TBinaryIn>, chainId: TChainId = MAIN_NET_CHAIN_ID): T =>
    isPublicKey(seedOrPublicKey) ?
      buildAddress(fromIn(seedOrPublicKey.publicKey), chainId) :
      address(keyPair(seedOrPublicKey), chainId)

  const randomBytes = (length: number): TBytes =>
    secureRandom(length, { type: 'Uint8Array' })

  const randomSeed = (): T => {
    return toOut(Uint8Array.from([]))
  }

  const signBytes = (bytes: TBinaryIn, seedOrPrivateKey: TSeed | TPrivateKey<TBinaryIn>, random?: TBinaryIn): T =>
    toOut(
      axlsign.sign(fromIn(isPrivateKey(seedOrPrivateKey)
        ? seedOrPrivateKey.privateKey
        : privateKey(seedOrPrivateKey)),
        fromIn(bytes), random || randomBytes(64))
    )

  const verifySignature = (publicKey: TBinaryIn, bytes: TBinaryIn, signature: TBinaryIn): boolean => {
    try {
      return axlsign.verify(fromIn(publicKey), fromIn(bytes), fromIn(signature))
    } catch (error) {
      return false
    }
  }

  const verifyPublicKey = (publicKey: TBinaryIn): boolean => fromIn(publicKey).length === PUBLIC_KEY_LENGTH

  const verifyAddress = (addr: TBinaryIn, optional?: { chainId?: TChainId, publicKey?: TBinaryIn }): boolean => {

    const chainId = chainIdToNumber(optional ? optional.chainId || MAIN_NET_CHAIN_ID : MAIN_NET_CHAIN_ID)

    try {
      const addressBytes = fromIn(addr)

      if (addressBytes[0] != 1 || addressBytes[1] != chainId)
        return false

      const key = addressBytes.slice(0, 22)
      const check = addressBytes.slice(22, 26)
      const keyHash = hashChain(key).slice(0, 4)

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

  const seed = (seed: TSeed, nonce: number): ISeedWithNonce => ({ seed: decomposeSeed(seed).seed, nonce })

  const aesEncrypt = (data: TBinaryIn, secret: TBinaryIn, iv?: TBinaryIn, mode: 'ECB' | 'CTR' = 'ECB'): T =>
    toOut(
      base64Decode(
        CryptoJS.AES.encrypt(byteArrayToWordArrayEx(fromIn(data)), byteArrayToWordArrayEx(fromIn(secret)),
          {
            iv: iv ? byteArrayToWordArrayEx(fromIn(iv)) : undefined,
            mode: mode === 'ECB' ? CryptoJS.mode.ECB : CryptoJS.mode.CTR,
          })
          .toString()
      )
    )

  const aesDecrypt = (encryptedMessage: TBinaryIn, secret: TBinaryIn, iv?: TBinaryIn, mode: 'ECB' | 'CTR' = 'ECB'): T =>
    toOut(
      wordArrayToByteArrayEx(
        CryptoJS.AES.decrypt(base64Encode(encryptedMessage), byteArrayToWordArrayEx(fromIn(secret)),
          {
            iv: iv ? byteArrayToWordArrayEx(fromIn(iv)) : undefined,
            mode: mode === 'ECB' ? CryptoJS.mode.ECB : CryptoJS.mode.CTR,
          })
      )
    )

  const hmacSHA256 = (message: TBinaryIn, key: TBinaryIn): T =>
    toOut(wordArrayToByteArrayEx(CryptoJS.HmacSHA256(byteArrayToWordArrayEx(fromIn(message)), byteArrayToWordArrayEx(fromIn(key)))))

  const sharedKey = (privateKeyFrom: TBinaryIn, publicKeyTo: TBinaryIn, prefix: TRawIn): T => {
    const sharedKey = axlsign.sharedKey(fromIn(privateKeyFrom), fromIn(publicKeyTo))
    const prefixHash = sha256(fromRawIn(prefix))
    return hmacSHA256(sharedKey, prefixHash)
  }

  const messageEncrypt = (sharedKey: TBinaryIn, message: TRawIn, prefix: TRawIn): T => {
    const KEK = fromIn(sharedKey)
    const CEK = randomBytes(32)
    const IV = randomBytes(16)
    const p = fromRawIn(prefix)
    const m = fromRawIn(message)

    const CEK_FOR_HMAC = CEK.map((byte, index) => byte | p[index % p.length])

    const Cc = aesEncrypt(m, CEK, IV, 'CTR')
    const Ccek = aesEncrypt(CEK, sharedKey)
    const Mhmac = hmacSHA256(m, CEK)
    const CEKhmac = hmacSHA256(CEK_FOR_HMAC, KEK)

    const packageBytes = concat(
      Ccek,
      CEKhmac,
      Cc,
      Mhmac,
      IV
    )

    return toOut(packageBytes)
  }

  const messageDecrypt = (sharedKey: TBinaryIn, encryptedMessage: TBinaryIn, prefix: TRawIn): string => {
    const P = fromRawIn(prefix)

    const [
      Ccek,
      _CEKhmac,
      Cc,
      _Mhmac,
      iv,
    ] = split(encryptedMessage, 48, 32, 32, 32, 16)

    const CEK = fromIn(aesDecrypt(Ccek, sharedKey))

    const CEK_FOR_HMAC = CEK.map((byte, index) => byte | P[index % P.length])
    const CEKhmac = fromIn(hmacSHA256(CEK_FOR_HMAC, fromIn(sharedKey)))

    const isValidKey = CEKhmac.every((v, i) => v === _CEKhmac[i])
    if (!isValidKey)
      throw new Error('Invalid message')

    const M = fromIn(aesDecrypt(Cc, CEK, iv, 'CTR'))
    const Mhmac = fromIn(hmacSHA256(M, CEK))

    const isValidMessage = Mhmac.every((v, i) => v === _Mhmac[i])
    if (!isValidMessage)
      throw new Error('Invalid message')

    return String.fromCharCode.apply(null, Array.from(M))
  }

  return {
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
    keyPair,
    publicKey,
    privateKey,
    address,
    randomBytes,
    randomSeed,
    signBytes,
    verifySignature,
    verifyPublicKey,
    verifyAddress,
    sharedKey,
    messageDecrypt,
    messageEncrypt,
    split,
  }
}
