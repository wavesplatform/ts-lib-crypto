import * as CryptoJS from 'crypto-js'
import * as blake from './libs/blake2b'
import { keccak256 } from './libs/sha3'
import base58 from './libs/base58'
import axlsign from './libs/axlsign'
import { IWavesCrypto, TBinaryIn, TBytes, TBase58, TBinaryOut, TBase64, TBase16, TKeyPair, TSeed, ISeedWithNonce, TPrivateKey, TChainId, MAIN_NET_CHAIN_ID, TPublicKey, PUBLIC_KEY_LENGTH, TRawStringIn, ISeedRelated, ISeedEmbeded } from './crypto'
import { secureRandom } from './random'
import { words } from './words'

export { IWavesCrypto, TBinaryIn, TBytes, TBase58, TBinaryOut, TBase64, TBase16, TKeyPair, TSeed, ISeedWithNonce, TPrivateKey, TChainId, MAIN_NET_CHAIN_ID, TPublicKey, PUBLIC_KEY_LENGTH, TRawStringIn, ISeedRelated, ISeedEmbeded } from './crypto'
export { words } from './words'
export { secureRandom } from './random'


type TTypesMap = {
  Bytes: Uint8Array
  Base58: string
}

type TDefaultOut = 'Base58'
type TOutput = keyof TTypesMap
type TOptions<T extends TBinaryOut = TDefaultOut, S extends TSeed | undefined = undefined> = { output?: T, seed?: S }
type Words = CryptoJS.LibWordArray | CryptoJS.WordArray | CryptoJS.DecryptedMessage
type TWavesCrypto<T extends TBinaryOut = TDefaultOut, S extends TSeed | undefined = undefined> =
  IWavesCrypto<T> & (S extends undefined ? ISeedRelated<T> : ISeedEmbeded<T>)

export const crypto = <TOut extends TOutput = TDefaultOut, S extends TSeed | undefined = undefined>(options?: TOptions<TOut, S>): TWavesCrypto<TTypesMap[TOut], S> => {

  if (options && options.seed == '')
    throw new Error('Empty seed is not allowed.')

  type T = TTypesMap[TOut]

  const c1 = <T1, R>(f: (a: T1) => R) => (a: T1) => () => f(a)
  const c2 = <T1, T2, R>(f: (a: T1, b: T2) => R) => (a: T1) => (b: T2) => f(a, b)
  const c3 = <T1, T2, T3, R>(f: (a: T1, b: T2, c: T3) => R) => (a: T1) => (b: T2) => (c: T3) => f(a, b, c)

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

    return { seed: _fromIn(seed), nonce: undefined }
  }

  const split = (binary: TBinaryIn, ...sizes: number[]): TBytes[] => {
    const r = sizes.reduce<{ arr: TBytes, r: TBytes[] }>((a, s) => ({ arr: a.arr.slice(s), r: [...a.r, a.arr.slice(0, s)] }), { arr: _fromIn(binary), r: [] })
    return [...r.r, r.arr]
  }

  const chainIdToNumber = (chainId: TChainId): number =>
    typeof chainId === 'string' ? chainId.charCodeAt(0) : chainId

  const _hashChain = (input: TBytes): TBytes =>
    _fromIn(keccak(blake2b(input)))

  const _toWords = (arr: Uint8Array) => {
    const len = arr.length
    const words: any = []
    for (let i = 0; i < len; i++) {
      words[i >>> 2] |= (arr[i] & 0xff) << (24 - (i % 4) * 8)
    }
    return (CryptoJS.lib.WordArray.create as any)(words, len)
  }

  const _fromWords = (inValue: Words): TBytes => {
    let words = (<any>inValue).words
    let sigBytes = (<any>inValue).sigBytes

    let u8 = new Uint8Array(sigBytes)
    for (let i = 0; i < sigBytes; i++) {
      let byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
      u8[i] = byte
    }

    return u8
  }

  const _fromIn = (inValue: TBinaryIn): TBytes => {
    if (isString(inValue))
      return base58Decode(inValue)

    if (isUint8Array(inValue))
      return inValue

    return Uint8Array.from(inValue)
  }

  const _fromRawIn = (inValue: TBinaryIn): TBytes => {
    if (isString(inValue))
      return stringToBytes(inValue)

    if (isUint8Array(inValue))
      return inValue

    return Uint8Array.from(inValue)
  }

  const _toOut = (bytes: TBytes): T => {
    if (options && options.output) {
      return (options.output === 'Base58' ? base58Encode(bytes) : bytes) as T
    }
    return base58Encode(bytes) as T
  }

  const _concat = (...arrays: (TBinaryIn | Words)[]): TBytes =>
    arrays.reduce<Uint8Array>((a, b) => Uint8Array.from([...a, ...(isWords(b) ? _fromWords(b) : _fromIn(b))]), new Uint8Array(0))

  const concat = (...arrays: TBinaryIn[]): T =>
    _toOut(arrays.reduce<Uint8Array>((a, b) => Uint8Array.from([...a, ..._fromIn(b)]), new Uint8Array(0)))

  const _convert = (inValue: TBinaryIn): T => _toOut(_fromIn(inValue))

  const blake2b = (input: TBinaryIn): T =>
    _convert(blake.blake2b(_fromIn(input), null, 32))

  const keccak = (input: TBinaryIn): T =>
    _convert(keccak256.array(_fromIn(input)))

  const sha256 = (input: TBinaryIn): T => {
    const wordArray = _toWords(_fromIn(input))
    const resultWordArray = CryptoJS.SHA256(wordArray)
    return _toOut(_fromWords(resultWordArray))
  }

  const base64Encode = (input: TBinaryIn): TBase64 =>
    CryptoJS.enc.Base64.stringify(_toWords(_fromIn(input)))

  const base64Decode = (input: TBase64): TBytes =>
    _fromWords(CryptoJS.enc.Base64.parse(input))

  const base58Encode = (input: TBinaryIn): TBase58 =>
    base58.encode(_fromIn(input))

  const base58Decode = (input: TBase58): TBytes =>
    base58.decode(input)

  const base16Encode = (input: TBinaryIn): TBase16 =>
    CryptoJS.enc.Hex.stringify(_toWords(_fromIn(input)))

  const base16Decode = (input: TBase16): TBytes =>
    _fromWords(CryptoJS.enc.Hex.parse(input))

  const stringToBytes = (str: string): TBytes =>
    Uint8Array.from([...unescape(encodeURIComponent(str))].map(c => c.charCodeAt(0)))

  const bytesToString = (bytes: TBinaryIn): string =>
    String.fromCharCode.apply(null, Array.from(_fromIn(bytes)))

  const buildSeedHash = (seedBytes: Uint8Array, nonce?: number): Uint8Array => {
    const nonceArray = [0, 0, 0, 0]
    if (nonce && nonce > 0) {
      let remainder = nonce
      for (let i = 3; i >= 0; i--) {
        nonceArray[3 - i] = Math.floor(remainder / 2 ** (i * 8))
        remainder = remainder % 2 ** (i * 8)
      }
    }
    const seedBytesWithNonce = _concat(nonceArray, seedBytes)
    const seedHash = _hashChain(seedBytesWithNonce)
    return _fromIn(sha256(seedHash))
  }

  const keyPair = (seed: TSeed): TKeyPair<T> => {
    const { seed: seedBytes, nonce } = decomposeSeed(seed)

    const seedHash = buildSeedHash(seedBytes, nonce)
    const keys = axlsign.generateKeyPair(seedHash)
    return {
      privateKey: _toOut(keys.private),
      publicKey: _toOut(keys.public),
    }
  }

  const publicKey = (seed: TSeed): T =>
    keyPair(seed).publicKey

  const privateKey = (seed: TSeed): T =>
    keyPair(seed).privateKey

  const buildAddress = (publicKeyBytes: TBytes, chainId: TChainId = MAIN_NET_CHAIN_ID): T => {
    const prefix = [1, typeof chainId === 'string' ? chainId.charCodeAt(0) : chainId]
    const publicKeyHashPart = _hashChain(publicKeyBytes).slice(0, 20)
    const rawAddress = _concat(prefix, publicKeyHashPart)
    const addressHash = _hashChain(rawAddress).slice(0, 4)
    return _toOut(_concat(rawAddress, addressHash))
  }

  const address = (seedOrPublicKey: TSeed | TPublicKey<TBinaryIn>, chainId: TChainId = MAIN_NET_CHAIN_ID): T =>
    isPublicKey(seedOrPublicKey) ?
      buildAddress(_fromIn(seedOrPublicKey.publicKey), chainId) :
      address(keyPair(seedOrPublicKey), chainId)

  const randomBytes = (length: number): TBytes =>
    secureRandom(length, 'Uint8Array')

  const randomSeed = (wordsCount: number = 15): string =>
    secureRandom(wordsCount, 'Array32')
      .map(x => words[x % words.length])
      .join(' ')

  const signBytes = (seedOrPrivateKey: TSeed | TPrivateKey<TBinaryIn>, bytes: TBinaryIn, random?: TBinaryIn): T =>
    _toOut(
      axlsign.sign(_fromIn(isPrivateKey(seedOrPrivateKey)
        ? seedOrPrivateKey.privateKey
        : privateKey(seedOrPrivateKey)),
        _fromIn(bytes), random || randomBytes(64))
    )

  const verifySignature = (publicKey: TBinaryIn, bytes: TBinaryIn, signature: TBinaryIn): boolean => {
    try {
      return axlsign.verify(_fromIn(publicKey), _fromIn(bytes), _fromIn(signature))
    } catch (error) {
      return false
    }
  }

  const verifyPublicKey = (publicKey: TBinaryIn): boolean => _fromIn(publicKey).length === PUBLIC_KEY_LENGTH

  const verifyAddress = (addr: TBinaryIn, optional?: { chainId?: TChainId, publicKey?: TBinaryIn }): boolean => {

    const chainId = chainIdToNumber(optional ? optional.chainId || MAIN_NET_CHAIN_ID : MAIN_NET_CHAIN_ID)

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

  const seed = (seed: TSeed, nonce: number): ISeedWithNonce => ({ seed: decomposeSeed(seed).seed, nonce })

  const aesEncrypt = (data: TBinaryIn, secret: TBinaryIn, iv?: TBinaryIn, mode: 'ECB' | 'CTR' = 'ECB'): T =>
    _toOut(
      base64Decode(
        CryptoJS.AES.encrypt(_toWords(_fromIn(data)), _toWords(_fromIn(secret)),
          {
            iv: iv ? _toWords(_fromIn(iv)) : undefined,
            mode: mode === 'ECB' ? CryptoJS.mode.ECB : CryptoJS.mode.CTR,
          })
          .toString()
      )
    )

  const aesDecrypt = (encryptedMessage: TBinaryIn, secret: TBinaryIn, iv?: TBinaryIn, mode: 'ECB' | 'CTR' = 'ECB'): T =>
    _toOut(
      _fromWords(
        CryptoJS.AES.decrypt(base64Encode(encryptedMessage), _toWords(_fromIn(secret)),
          {
            iv: iv ? _toWords(_fromIn(iv)) : undefined,
            mode: mode === 'ECB' ? CryptoJS.mode.ECB : CryptoJS.mode.CTR,
          })
      )
    )

  const hmacSHA256 = (message: TBinaryIn, key: TBinaryIn): T =>
    _toOut(_fromWords(CryptoJS.HmacSHA256(_toWords(_fromIn(message)), _toWords(_fromIn(key)))))

  const sharedKey = (privateKeyFrom: TBinaryIn, publicKeyTo: TBinaryIn, prefix: TRawStringIn): T => {
    const sharedKey = axlsign.sharedKey(_fromIn(privateKeyFrom), _fromIn(publicKeyTo))
    const prefixHash = sha256(_fromRawIn(prefix))
    return hmacSHA256(sharedKey, prefixHash)
  }

  const messageEncrypt = (sharedKey: TBinaryIn, message: TRawStringIn, prefix: TRawStringIn): T => {
    const KEK = _fromIn(sharedKey)
    const CEK = randomBytes(32)
    const IV = randomBytes(16)
    const p = _fromRawIn(prefix)
    const m = _fromRawIn(message)

    const CEK_FOR_HMAC = CEK.map((byte, index) => byte | p[index % p.length])

    const Cc = aesEncrypt(m, CEK, IV, 'CTR')
    const Ccek = aesEncrypt(CEK, sharedKey)
    const Mhmac = hmacSHA256(m, CEK)
    const CEKhmac = hmacSHA256(CEK_FOR_HMAC, KEK)

    const packageBytes = _concat(
      Ccek,
      CEKhmac,
      Cc,
      Mhmac,
      IV
    )

    return _toOut(packageBytes)
  }

  const messageDecrypt = (sharedKey: TBinaryIn, encryptedMessage: TBinaryIn, prefix: TRawStringIn): string => {
    const P = _fromRawIn(prefix)

    const [
      Ccek,
      _CEKhmac,
      Cc,
      _Mhmac,
      iv,
    ] = split(encryptedMessage, 48, 32, 32, 32, 16)

    const CEK = _fromIn(aesDecrypt(Ccek, sharedKey))

    const CEK_FOR_HMAC = CEK.map((byte, index) => byte | P[index % P.length])
    const CEKhmac = _fromIn(hmacSHA256(CEK_FOR_HMAC, _fromIn(sharedKey)))

    const isValidKey = CEKhmac.every((v, i) => v === _CEKhmac[i])
    if (!isValidKey)
      throw new Error('Invalid message')

    const M = _fromIn(aesDecrypt(Cc, CEK, iv, 'CTR'))
    const Mhmac = _fromIn(hmacSHA256(M, CEK))

    const isValidMessage = Mhmac.every((v, i) => v === _Mhmac[i])
    if (!isValidMessage)
      throw new Error('Invalid message')

    return String.fromCharCode.apply(null, Array.from(M))
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
    split,
    concat,
  } as TWavesCrypto<T, S>
}
