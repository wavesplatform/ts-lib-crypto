
export const PUBLIC_KEY_LENGTH = 32
export const PRIVATE_KEY_LENGTH = 32
export const SIGNATURE_LENGTH = 64

export const MAIN_NET_CHAIN_ID = 87 //W
export const TEST_NET_CHAIN_ID = 84 //T

export interface ISeedWithNonce {
  seed: TBytes
  nonce: number
}

/* Type aliases used to increase flexibility and be able
   to extend these types later on. Also type aliases allows
   names to be more self explanatory like in BASE58 case. */

export type TBytes = Uint8Array

export type TBase64 = string
export type TBase58 = string
export type TBase16 = string //Same as HEX

export type TChainId = string | number

//So almost every binary parameter could be represented as Uint8Array or number[] or base58 string
export type TBinaryIn = TBytes | TBase58 | number[]

export type TBinaryOut = TBytes | TBase58

//TPublicKey is a BASE58 string representation of a public key.
export type TPublicKey<T extends TBinaryIn = TBytes> = { publicKey: T }

//TPrivateKey is a BASE58 string representation of a private key.
export type TPrivateKey<T extends TBinaryIn = TBytes> = { privateKey: T }

export type TKeyPair<T extends TBinaryIn = TBytes> = TPublicKey<T> & TPrivateKey<T>

//TSeed is a union of types that could represent a Waves seed.
export type TSeed = string | TBinaryIn | ISeedWithNonce

/* Consider that every method should handle TSeed
   seamlessly so in case of absence of type union operator
   overloads should be implemented for each possible TSeed type */


/* Waves Crypto is a collection of essential cryptography and hashing
   algorithms used by Waves, protocol entities and binary structures. */

export interface IWavesCrypto<TDesiredOut extends TBinaryOut> {
  seed: (seed: TSeed, nonce: number) => ISeedWithNonce

  //Hashing 
  blake2b: (input: TBinaryIn) => TDesiredOut
  keccak: (input: TBinaryIn) => TDesiredOut
  sha256: (input: TBinaryIn) => TDesiredOut

  //Base encoding\decoding
  base64Encode: (input: TBinaryIn) => TBase64
  base64Decode: (input: TBase64) => TBytes //throws (invalid input)
  base58Encode: (input: TBinaryIn) => TBase58
  base58Decode: (input: TBase58) => TBytes //throws (invalid input)
  base16Encode: (input: TBinaryIn) => TBase16
  base16Decode: (input: TBase16) => TBytes //throws (invalid input)

  stringToBytes: (input: string) => TBytes

  //Keys, seeds and addresses
  keyPair: (seed: TSeed) => TKeyPair<TDesiredOut>
  publicKey: (seed: TSeed) => TDesiredOut
  privateKey: (seed: TSeed) => TDesiredOut
  address: (seedOrKeys: TSeed | TPublicKey<TBinaryIn>, chainId?: TChainId) => TDesiredOut

  //Random
  randomBytes: (size: number) => TBytes
  randomSeed: () => TDesiredOut

  //Bytes hashing and signing
  signBytes: (bytes: TBinaryIn, seedOrPrivateKey: TSeed | TPrivateKey<TBinaryIn>, random?: TBinaryIn) => TDesiredOut

  //Verification
  verifySignature: (publicKey: TBinaryIn, bytes: TBinaryIn, signature: TBinaryIn) => boolean
  verifyPublicKey: (publicKey: TBinaryIn) => boolean
  verifyAddress: (address: TBinaryIn, optional?: { chainId?: TChainId, publicKey?: TBinaryIn }) => boolean

  //TODO Messaging
  //sharedKey: (privateKeyFrom: TKey, publicKeyTo: TKey) => TKey
  //messageDecrypt: (sharedKey: TKey, encryptedMessage: TBase58) => string
  //messageEncrypt: (sharedKey: TKey, message: string) => TBase58

}


