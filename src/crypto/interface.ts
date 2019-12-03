export const PUBLIC_KEY_LENGTH = 32
export const PRIVATE_KEY_LENGTH = 32
export const SIGNATURE_LENGTH = 64
export const ADDRESS_LENGTH = 26

export const MAIN_NET_CHAIN_ID = 87 // W
export const TEST_NET_CHAIN_ID = 84 // T

export interface INonceSeed {
  seed: TBytes
  nonce?: number
}

export type AESMode = 'CBC' | 'CFB' | 'CTR' | 'OFB' | 'ECB' | 'GCM'

export type RSADigestAlgorithm =
  'MD5'
  | 'SHA1'
  | 'SHA224'
  | 'SHA256'
  | 'SHA384'
  | 'SHA512'
  | 'SHA3-224'
  | 'SHA3-256'
  | 'SHA3-384'
  | 'SHA3-512'

export type TRandomTypesMap = {
  Array8: number[]
  Array16: number[]
  Array32: number[]
  Buffer: Buffer
  Uint8Array: Uint8Array
  Uint16Array: Uint16Array
  Uint32Array: Uint32Array
}

/* Type aliases used to increase flexibility and be able
   to extend these types later on. Also type aliases allows
   names to be more self explanatory like in BASE58 case. */

export type TBytes = Uint8Array

export type TBase64 = string
export type TBase58 = string
export type TBase16 = string //Same as HEX

export type TChainId = string | number

//Every binary parameter could be represented as Uint8Array or number[] or base58 string
export type TBinaryIn = TBytes | TBase58 | number[]

export type TRawStringInDiscriminator = { TRawStringIn: null }

//Every input string could be represented as Uint8Array or number[] or a string itself
export type TRawStringIn = TBytes | string | number[] | TRawStringInDiscriminator

export type TBinaryOut = TBytes | TBase58

//TPublicKey is a BASE58 string representation of a public key.
export type TPublicKey<T extends TBinaryIn = TBase58> = { publicKey: T }

//TPrivateKey is a BASE58 string representation of a private key.
export type TPrivateKey<T extends TBinaryIn = TBase58> = { privateKey: T }

export type TKeyPair<T extends TBinaryIn = TBase58> = TPublicKey<T> & TPrivateKey<T>

//TSeed is a union of types that could represent a Waves seed.
export type TSeed = TRawStringIn | INonceSeed

//TRSAKeyPair is X509Encoded RSA key pair
export type TRSAKeyPair = {
  rsaPublic: TBytes
  rsaPrivate: TBytes
}

/* Consider that every method should handle TSeed
   seamlessly so in case of absence of type union operator
   overloads should be implemented for each possible TSeed type */

/* Waves Crypto is a collection of essential cryptography and hashing
   algorithms used by Waves, protocol entities and binary structures. */

export interface ISeedRelated<TDesiredOut extends TBinaryOut = TBase58> {
  //Seeds, keys and addresses
  seedWithNonce: (seed: TSeed, nonce: number) => INonceSeed
  keyPair: (seed: TSeed) => TKeyPair<TDesiredOut>
  publicKey: (seedOrPrivateKey: TSeed | TPrivateKey<TBinaryIn>) => TDesiredOut
  privateKey: (seed: TSeed) => TDesiredOut
  address: (seedOrPublicKey: TSeed | TPublicKey<TBinaryIn>, chainId?: TChainId) => TDesiredOut

  //Signature
  signBytes: (seedOrPrivateKey: TSeed | TPrivateKey<TBinaryIn>, bytes: TBinaryIn, random?: TBinaryIn) => TDesiredOut
}

export interface ISeedEmbeded<TDesiredOut extends TBinaryOut = TBase58> {
  //Seeds, keys and addresses
  seedWithNonce: (nonce: number) => INonceSeed
  keyPair: () => TKeyPair<TDesiredOut>
  publicKey: () => TDesiredOut
  privateKey: () => TDesiredOut
  address: (chainId?: TChainId) => TDesiredOut

  //Bytes hashing and signing
  signBytes: (bytes: TBinaryIn, random?: TBinaryIn) => TDesiredOut
}

export interface IWavesCrypto<TDesiredOut extends TBinaryOut = TBase58> {

  //Hashing
  blake2b: (input: TBinaryIn) => TBytes
  keccak: (input: TBinaryIn) => TBytes
  sha256: (input: TBinaryIn) => TBytes

  //Base encoding\decoding
  base64Encode: (input: TBinaryIn) => TBase64
  base64Decode: (input: TBase64) => TBytes //throws (invalid input)
  base58Encode: (input: TBinaryIn) => TBase58
  base58Decode: (input: TBase58) => TBytes //throws (invalid input)
  base16Encode: (input: TBinaryIn) => TBase16
  base16Decode: (input: TBase16) => TBytes //throws (invalid input)

  //Utils
  stringToBytes: (input: string, encoding?: 'utf8' | 'raw') => TBytes
  bytesToString: (input: TBinaryIn, encoding?: 'utf8' | 'raw') => string
  split: (binary: TBinaryIn, ...sizes: number[]) => TBytes[]
  concat: (...binaries: TBinaryIn[]) => TBytes
  buildAddress: (publicKeyBytes: TBytes, chainId: TChainId) => TBytes

  //Random
  random<T extends keyof TRandomTypesMap>(count: number, type: T): TRandomTypesMap[T]

  randomBytes: (size: number) => TBytes
  randomSeed: (wordsCount?: number) => string

  //Verification
  verifySignature: (publicKey: TBinaryIn, bytes: TBinaryIn, signature: TBinaryIn) => boolean
  verifyPublicKey: (publicKey: TBinaryIn) => boolean
  verifyAddress: (address: TBinaryIn, optional?: { chainId?: TChainId, publicKey?: TBinaryIn }) => boolean

  //Messaging
  sharedKey: (privateKeyFrom: TBinaryIn, publicKeyTo: TBinaryIn, prefix: TRawStringIn) => TDesiredOut
  messageDecrypt: (sharedKey: TBinaryIn, encryptedMessage: TBinaryIn) => string
  messageEncrypt: (sharedKey: TBinaryIn, message: string) => TBytes

  //Encryption
  aesEncrypt: (data: TBinaryIn, encryptionKey: TBinaryIn, mode?: AESMode, iv?: TBinaryIn) => TBytes
  aesDecrypt: (encryptedData: TBinaryIn, encryptionKey: TBinaryIn, mode?: AESMode, iv?: TBinaryIn) => TBytes

  //Seed encryption (Same algorithm as in waves client and wavesKeeper).
  //Uses EvpKDF to derive key and iv from password. Then outputs AES-CBC encrypted seed in OpenSSL format as Base64 string
  encryptSeed: (seed: string, password: string, encryptionRounds?: number) => TBase64
  decryptSeed: (encryptedSeed: TBase64, password: string, encryptionRounds?: number) => string

  //RSA
  rsaKeyPair: (bits?: number, e?: number) => Promise<TRSAKeyPair>
  rsaKeyPairSync: (bits?: number, e?: number) => TRSAKeyPair
  rsaSign: (rsaPrivateKey: TBytes, message: TBytes, digest?: RSADigestAlgorithm) => TBytes
  rsaVerify: (rsaPublicKey: TBytes, message: TBytes, signature: TBytes, digest?: RSADigestAlgorithm) => boolean

  //Merkle
  merkleVerify: (rootHash: Uint8Array, merkleProof: Uint8Array, leafData: Uint8Array) => boolean
}
