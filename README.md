# ts-lib-crypto [![npm version](https://badge.fury.io/js/%40waves%2Fts-lib-crypto.svg)](https://www.npmjs.com/package/@waves/ts-lib-crypto)

The waves protocol is a set of rules named consensus by which nodes reach an agreement on the network, and format which nodes use to communicate with each other. It based on several well described hash and crypto algorithms and has predefined set of entries to operate on network. This library contains all algorithm implementations like signature verification and protocol entries like address used in waves protocol. Also it contains utility methods and format converters to help 3rd party developers.

## Agenda
- **[Installation](#installation)**
- **[Import styles](#import-styles)**
- **[Inputs](#inputs)**
- **[Outputs](#outputs)**
 - **[Seed generation](#seed-generation)**
	 - [randomSeed](#randomseed)
	 - [seedWordsList](#seedwordslist)
 - **[Keys and address](#keys-and-address)**
	 - [publicKey](#publickey)
	 - [privateKey](#privatekey)
	 - [keyPair](#keypair)
	 - [address](#address)
 - **[Signatures](#signatures)**
	 - [signBytes](#signbytes)
	 - [verifySignature](#verifySignature)
- **[Hashing](#hashing)**
	 - [blake2b](#blake2b)
	 - [keccak](#keccak)
	 - [sha256](#sha256)
 - **[Random](#random)**
	 - [randomBytes](#randomBytes)
	 - [random](#random)
 - **[Base encoding\decoding](#base-encodingdecoding)**
	 - [base16](#base-encodingdecoding)
	 - [base58](#base-encodingdecoding)
	 - [base64](#base-encodingdecoding)
 - **[Messaging](#messaging)**
	 - [sharedKey](#sharedKey)
	 - [messageEncrypt](#messageEncrypt)
	 - [messageDecrypt](#messageDecrypt)
 - **[Encryption](#encryption)**
	 - [aesEncrypt](#aesEncrypt)
	 - [aesDecrypt](#aesDecrypt)
- **[Seed encryption](#Seed-encryption)**
 - **[Utils](#utils)**
	 - [split](#split)
	 - [concat](#concat)
	 - [stringToBytes](#stringtobytes)
	 - [bytesToString](#bytestostring)
- **[Constants](#constants)**
- **[Interface](#interface)**
- **[More examples](#more-examples)**
## Installation
```
npm install @waves/ts-lib-crypto
```
## Import styles
The is several ways of doing things when using **ts-lib-crypto**.
You can import functions strait-forward:
```ts
import { address } from  '@waves/ts-lib-crypto'
address('my secret seed') // 3PAP3wkgbGjdd1FuBLn9ajXvo6edBMCa115
```
Or you can use a crypto constructor function:
```ts
import { crypto } from  '@waves/ts-lib-crypto'
const { address } = crypto()
address('my secret seed') // 3PAP3wkgbGjdd1FuBLn9ajXvo6edBMCa115
```
The second approach gives you more flexibility, using this approach you are able to embed the **seed** and use all seed-dependant functions without **seed** parameter:
```ts
import { crypto } from  '@waves/ts-lib-crypto'
const { address } = crypto({seed: 'my secret seed'})
address() // 3PAP3wkgbGjdd1FuBLn9ajXvo6edBMCa115
```

## Inputs 
**ts-lib-crypto** is even more flexible. Any function argument that represents binary data or seed could be passed in several ways. Let's take a look on the following example:
```ts
import { address } from  '@waves/ts-lib-crypto'
const  seedString  =  'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
const  seedBytesAsArray  = [117, 110, 99, 108, 101, 32, 112, 117, 115, 104, 32, 104, 117, 109, 97, 110, 32, 98, 117, 115, 32, 101, 99, 104, 111, 32, 100, 114, 97, 115, 116, 105, 99, 32, 103, 97, 114, 100, 101, 110, 32, 106, 111, 107, 101, 32, 115, 97, 110, 100, 32, 119, 97, 114, 102, 97, 114, 101, 32, 115, 101, 110, 116, 101, 110, 99, 101, 32, 102, 111, 115, 115, 105, 108, 32, 116, 105, 116, 108, 101, 32, 99, 111, 108, 111, 114, 32, 99, 111, 109, 98, 105, 110, 101]
const  seedBytesAsUintArray  =  Uint8Array.from(seedBytesAsArray)
address(seedString) // 3P9KR33QyXwfTXv8kKtNGZYtgKk3RXSUk36
address(seedBytesAsArray) // 3P9KR33QyXwfTXv8kKtNGZYtgKk3RXSUk36
address(seedBytesAsUintArray) // 3P9KR33QyXwfTXv8kKtNGZYtgKk3RXSUk36
```
As you can see **seed** parameter is treated the same way for **number[]** or **Uint8Array**.
When you pass binary data is could be represented as  **number[]** or **Uint8Array** or even **base58**:
```ts
import { address, randomSeed, sha256 } from '@waves/ts-lib-crypto'
const seed = randomSeed() // uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine
const addressBase58 = address(seed) // 3P9KR33QyXwfTXv8kKtNGZYtgKk3RXSUk36
sha256(addressBase58) // DMPenguwWdLdZ7tesiZY6grw7mjKU2Dob1cn9Uq9TKfp
```
Here we got **sha256** hash from address bytes represented as **base58** *(3P9KR33QyXwfTXv8kKtNGZYtgKk3RXSUk36)*. 
Be aware that **sha256** value is not based on "*3P9KR33QyXwfTXv8kKtNGZYtgKk3RXSUk36*" string itself, this value was treated as a **binary data** and **base58Decode** was applied.

## Outputs
As you've noticed from the previous section *address()* output is **base58** string like:
```ts
// 3PAP3wkgbGjdd1FuBLn9ajXvo6edBMCa115
```
 By default functions from the following list output **base58** string as a result,
 no matter what import-style you choose:
```
keyPair
publicKey
privateKey
address
sharedKey
signBytes
```

If you prefer **binary** output, you can alter this behaviour and make those functions to return **UInt8Array** instead.

When using inline import style:
```ts
// You can use [/bytes] module when importing functions to set output to UInt8Array
import { address } from  '@waves/ts-lib-crypto/bytes'
address('uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine')
// => Uint8Array [1,87,55,118,79,89,6,115,207,200,130,220,32,33,101,69,108,108,53,48,167,127,203,18,143,121]
```
When using crypto constructor function:
```ts
import { crypto } from  '@waves/ts-lib-crypto'
const { address } = crypto({ output: 'Bytes' })
address('uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine')
// => Uint8Array [1,87,55,118,79,89,6,115,207,200,130,220,32,33,101,69,108,108,53,48,167,127,203,18,143,121]
```

## Seed generation

The seed is a set of words or bytes that private and public keys are generated from. The usual Waves seed looks like:
```
uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine
```
There are couple ways to generate seed: 
```ts
const handWrittenSeedString = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
const handWrittenSeedBytes = [117, 110, 99, 108, 101, 32, 112, 117, 115, 104, 32, 104, 117, 109, 97, 110, 32, 98, 117, 115, 32, 101, 99, 104, 111, 32, 100, 114, 97, 115, 116, 105, 99, 32, 103, 97, 114, 100, 101, 110, 32, 106, 111, 107, 101, 32, 115, 97, 110, 100, 32, 119, 97, 114, 102, 97, 114, 101, 32, 115, 101, 110, 116, 101, 110, 99, 101, 32, 102, 111, 115, 115, 105, 108, 32, 116, 105, 116, 108, 101, 32, 99, 111, 108, 111, 114, 32, 99, 111, 109, 98, 105, 110, 101]
```
Or if you need seed with nonce:
```ts
import { seedWithNonce, randomSeed, address } from '@waves/ts-lib-crypto'

const nonce = 1
const seedphrase = randomSeed() // uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine
const seed = seedWithNonce(seedphrase, nonce)

//Now you can use seed as usual
address(seed)
```
Seed could be any **string** or **number[]** or **Uint8Array** or **ISeedWithNonce**.

There is also a way to generate seed-phrase using **ts-lib-crypto** described in the next section.

### randomSeed
```ts
import { randomSeed } from '@waves/ts-lib-crypto'

randomSeed() //uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine
```
You can also specify seed-phrase size:
```ts
randomSeed(3) //uncle push human
```
The default seed size is 15 words.

### seedWordsList
If you want to get all the valid seed words that official waves-client generates seed-phrase from, use **seedWordsList** the 2048 word array.
```ts
import { seedWordsList } from '@waves/ts-lib-crypto'
console.log(seedWordsList) // [ 'abandon','ability','able', ... 2045 more items ]
```
## Keys and address

### publicKey
You could get public key either from raw seed-phrase or seed with nonce:
```ts
import { publicKey, seedWithNonce } from '@waves/ts-lib-crypto'
const seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
publicKey(seed) // 4KxUVD9NtyRJjU3BCvPgJSttoJX7cb3DMdDTNucLN121
publicKey(seedWithNonce(seed, 0)) // 4KxUVD9NtyRJjU3BCvPgJSttoJX7cb3DMdDTNucLN121
```
Or even from private key, it's usefull in some cases:
```ts
import { publicKey, privateKey, seedWithNonce } from '@waves/ts-lib-crypto'
const seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
const pk = privateKey(seed)
publicKey({ privateKey: pk }) // 4KxUVD9NtyRJjU3BCvPgJSttoJX7cb3DMdDTNucLN121
```

### privateKey
Same with private key:
```ts
import { privateKey, seedWithNonce } from '@waves/ts-lib-crypto'
const  seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
privateKey(seed)
privateKey(seedWithNonce(seed, 99))
```
### keyPair
You could also obtain a keyPair:
```ts
import { keyPair } from '@waves/ts-lib-crypto'
const  seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
keyPair(seed)
// => { 
//      publicKey:  '4KxUVD9NtyRJjU3BCvPgJSttoJX7cb3DMdDTNucLN121',
//      privateKey: '6zFSymZAoaua3gtJPbAUwM584tRETdKYdEG9BeEnZaGW'
//    }
```
### address
You can create an address for *Mainnet*:
```ts
import { address } from '@waves/ts-lib-crypto'
const  seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
address(seed) // 3P9KR33QyXwfTXv8kKtNGZYtgKk3RXSUk36
```
or *Testnet*:
```ts
address(seed, 'T') // 3MwJc5iX7QQGq5ciVFdNK7B5KSEGbUCVxDw
```
alternatively You could use **TEST_NET_CHAIN_ID** constant instead of **T** literal like this:
```ts
import { address, TEST_NET_CHAIN_ID } from '@waves/ts-lib-crypto'
const  seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
address(seed, TEST_NET_CHAIN_ID) // 3MwJc5iX7QQGq5ciVFdNK7B5KSEGbUCVxDw
```
There are several more useful constants, you can check them in [\[constants\]](/#constants) section.
## Signatures
#### signBytes
To sign arbitrary bytes or usually transaction bytes you should use the **signBytes** function.
Here is sign with seed example:
```ts
import { signBytes } from '@waves/ts-lib-crypto'
const bytes = [117, 110, 99, 108, 101]
const seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
signBytes(seed, bytes) // 5ZpULwrnUYoxQZcw26km6tgGbj1y23ywYB4A9bLCpax6PUdrhkCmmoLBP6C1G5yiMJ7drqN9jNxPym6f8vrPsWnm
```
Also you can use private key to sign bytes:
```ts
import { signBytes, privateKey } from '@waves/ts-lib-crypto'
const bytes = [117, 110, 99, 108, 101]
const seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
const key = privateKey(seed)
signBytes({ privateKey: key }, bytes)
```
Remember that you can use **base58** strings when it's about binary data, so you can represent bytes as **base58** too:
```ts
signBytes({ privateKey:  key }, 'Fk1sjwdPSwZ4bPwvpCGPH6')
```
You can learn more about it in the [outputs](#outputs) section.
#### verifySignature
Verifying signature is a way to proof what particular bytes was signed with a particular private key or seed which correspond to public key that we are checking against:
```ts
import { signBytes, verifySignature, keyPair } from '@waves/ts-lib-crypto'
//Signature roundtrip
const bytes = [117, 110, 99, 108, 101]
const seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
const keys = keyPair(seed)
const signature = signBytes(keys, bytes)
verifySignature(keys.publicKey, bytes, signature) // true
```
## Hashing
There are three hashing algorithms available in **ts-lib-crypto**.
#### blake2b
```ts
import { blake2b } from '@waves/ts-lib-crypto'
const bytesArray = [117, 110, 99, 108, 101]
const bytesUint = Uint8Array.from([117, 110, 99, 108, 101])
const bytesBase58 = 'EFRr9cp'
blake2b(bytesArray)  // 9DqBU9wZAR85PyrUSJpwaU9DggM8veyMxRMvFe1q6atu
blake2b(bytesUint)   // 9DqBU9wZAR85PyrUSJpwaU9DggM8veyMxRMvFe1q6atu
blake2b(bytesBase58) // 9DqBU9wZAR85PyrUSJpwaU9DggM8veyMxRMvFe1q6atu

```
#### keccak
```ts
import { keccak } from '@waves/ts-lib-crypto'
const bytesArray = [117, 110, 99, 108, 101]
const bytesUint = Uint8Array.from([117, 110, 99, 108, 101])
const bytesBase58 = 'EFRr9cp'
keccak(bytesArray)  // 5cqz9N2PPjDkSBSwga8AttKzQEHfn8aQ95rcZZmabLA7
keccak(bytesUint)   // 5cqz9N2PPjDkSBSwga8AttKzQEHfn8aQ95rcZZmabLA7
keccak(bytesBase58) // 5cqz9N2PPjDkSBSwga8AttKzQEHfn8aQ95rcZZmabLA7
```
#### sha256
```ts
import { sha256 } from '@waves/ts-lib-crypto'
const bytesArray = [117, 110, 99, 108, 101]
const bytesUint = Uint8Array.from([117, 110, 99, 108, 101])
const bytesBase58 = 'EFRr9cp'
sha256(bytesArray)  // 4JPydqbhxhZF7kpuGA2tJWkXDmevJYfig45gqdV1UF9E
sha256(bytesUint)   // 4JPydqbhxhZF7kpuGA2tJWkXDmevJYfig45gqdV1UF9E
sha256(bytesBase58) // 4JPydqbhxhZF7kpuGA2tJWkXDmevJYfig45gqdV1UF9E
```
## Random
There is several ways to get random values in **ts-lib-crypto**.
To get an **Uint8Array** of random values simply use:
#### randomBytes
```ts
import { randomBytes } from '@waves/ts-lib-crypto'
randomBytes(3) // Uint8Array [ 120, 46, 179 ]             
```
If you want more control over the values format you could use:
#### random
```ts
import { random } from '@waves/ts-lib-crypto'

const length = 3     
random(length, 'Array8')       // [ 19, 172, 130 ]   
random(length, 'Array16')      // [ 61736, 48261, 38395 ] 
random(length, 'Array32')      // [ 406628961, 307686833, 2604847943 ]       
random(length, 'Buffer')       // <Buffer db ff fb>       
random(length, 'Uint8Array')   // Uint8Array [ 137, 85, 212 ]   
random(length, 'Uint16Array')  // Uint16Array [ 35881, 51653, 55967 ]  
random(length, 'Uint32Array')  // Uint32Array [ 698646076, 2957331816, 2073997581 ]    
```
## Base encoding\decoding


```ts
import { base16Encode, base16Decode, base58Encode, base58Decode, base64Encode, base64Decode, randomBytes } from '@waves/ts-lib-crypto'

const bytes = randomBytes(32)

// Base16 same as Hex
const base16String = base16Encode(bytes) // 2059ec5d9ed640b75722ec6a2ff76890e523ea4624887549db761d678ba8f899
const bytesFromBase16 = base16Decode(base16String)

// Base58
const base58String = base58Encode(bytes) // 3BHaM9Q5HhUobQ5oZAqjdkE9HRpmqMx4XLq3GXTMD5tU
const bytesFromBase58 = base58Decode(base58String)

// Base64
const base64String = base64Encode(bytes) // IFnsXZ7WQLdXIuxqL/dokOUj6kYkiHVJ23YdZ4uo+Jk=
const bytesFromBase64 = base64Decode(base64String)
```
## Messaging
These methods implement waves messaging protocol 
- sharedKey 
- messageDecrypt
- messageEncrypt
```typescript
import { sharedKey, messageEncrypt, messageDecrypt, keyPair } from '@waves/ts-lib-crypto'

const bobKeyPair = keyPair('Bob')
const aliceKeyPair = keyPair('Alice')
const msg = 'hello world'

// Alice derives shared key and encrypts message
const sharedKeyA = sharedKey(aliceKeyPair.privateKey, bobKeyPair.publicKey, 'waves') 
const encrypted = messageEncrypt(sharedKeyA, msg)

// Bob decrypts message derives shared key and decrypts message
const sharedKeyB = sharedKey(aliceKeyPair.privateKey, bobKeyPair.publicKey, 'waves') 
const decrypted = messageDecrypt(sharedKeyB, encrypted)
```
## Encryption
This is low level functionality where you have to generate key and iv yourself 
#### aesEncrypt
Encrypt bytes using AES algorithm. 
```typescript
import { aesEncrypt, randomBytes } from '@waves/ts-lib-crypto'

const data = Uint8Arraty.from([1,2,3])
const mode =  'CBC' // Possible modes are 'CBC' | 'CFB' | 'CTR' | 'OFB' | 'ECB' | 'GCM'

const key = randomBytes(32)
const iv = randomBytes(32)

const encrypted = aesEncrypt(data, key, mode, iv)

```
#### aesDecrypt
Decrypt bytes using AES algorithm
```typescript
const decrypted = aesDecrypt(encrypted, key, mode, iv)
```

## Seed encryption
These functions implements seed encryption protocol used in DexClient and WavesKeeper
```typescript
import { encryptSeed, decryptSeed } from '@waves/ts-lib-crypto'

const seed = 'some secret seed phrase i use'
const encrypted = encryptSeed(seed, 'secure password')
const decrypted = decryptSeed(encryptSeed, 'secure password')

```
## Utils
Utility functions designed to help 3rd party developers working with js binary types like Uint8Array and Buffer.
#### split
You can use split for splitting bytes to sub arrays.
```ts
import { split, randomBytes } from '@waves/ts-lib-crypto'
const bytes = randomBytes(2 + 3 + 4 + 10)
split(bytes, 2, 3, 4)
// [ 
//   Uint8Array [195, 206],
//   Uint8Array [ 10, 208, 171 ],
//   Uint8Array [ 36, 18, 254, 205 ],
//   Uint8Array [ 244, 232, 55, 11, 113, 47, 80, 194, 170, 216 ]
// ]
```
Alternatively, you can use array deconstruction syntax:
```ts
const [a, b, c, rest] = split(bytes, 2, 3, 4)
// a = Uint8Array [195, 206],
// b = Uint8Array [ 10, 208, 171 ],
// c = Uint8Array [ 36, 18, 254, 205 ],
// rest = Uint8Array [ 244, 232, 55, 11, 113, 47, 80, 194, 170, 216 ]
```
#### concat
Concat is the opposite and pretty self-explanatory:
```ts
import { concat, randomBytes } from '@waves/ts-lib-crypto'
const bytesA = randomBytes(2)
const bytesB = randomBytes(2)
concat(bytesA, bytesB) // Uint8Array [ 36, 18, 254, 205 ]
```
#### stringToBytes
```ts
import { stringToBytes } from '@waves/ts-lib-crypto'
stringToBytes('Waves!') // Uint8Array [ 87, 97, 118, 101, 115, 33 ]
```
#### bytesToString
```ts
import { bytesToString } from '@waves/ts-lib-crypto'
bytesToString([ 87, 97, 118, 101, 115, 33 ]) // Waves!
```
## Constants
There is several useful constants declared at **ts-lib-crypto**:
```ts
const PUBLIC_KEY_LENGTH = 32
const PRIVATE_KEY_LENGTH = 32
const SIGNATURE_LENGTH = 64
const ADDRESS_LENGTH = 26

const MAIN_NET_CHAIN_ID = 87 // W
const TEST_NET_CHAIN_ID = 84 // T
```
## Interface 
The full **IWavesCrypto** interface can be found on the [project`s github](https://github.com/wavesplatform/ts-lib-crypto) in [interface.ts](https://github.com/wavesplatform/ts-lib-crypto/blob/master/src/crypto/interface.ts).
```ts
  //Seeds, keys and addresses
  seedWithNonce: (seed: TSeed, nonce: number) => INonceSeed
  keyPair: (seed: TSeed) => TKeyPair<TBytesOrBase58>
  publicKey: (seed: TSeed) => TBytesOrBase58
  privateKey: (seed: TSeed) => TBytesOrBase58
  address: (seedOrPublicKey: TSeed | TPublicKey<TBinaryIn>, chainId?: TChainId) => TBytesOrBase58

  //Signature
  signBytes: (seedOrPrivateKey: TSeed | TPrivateKey<TBinaryIn>, bytes: TBinaryIn, random?: TBinaryIn) => TDesiredOut
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
  stringToBytes: (input: string) => TBytes
  bytesToString: (input: TBinaryIn) => string
  split: (binary: TBinaryIn, ...sizes: number[]) => TBytes[]
  concat: (...binaries: TBinaryIn[]) => TBytes

  //Random
  random<T extends keyof TRandomTypesMap>(count: number, type: T): TRandomTypesMap[T]
  randomBytes: (size: number) => TBytes
  randomSeed: (wordsCount?: number) => string

  //Verification
  verifySignature: (publicKey: TBinaryIn, bytes: TBinaryIn, signature: TBinaryIn) => boolean
  verifyPublicKey: (publicKey: TBinaryIn) => boolean
  verifyAddress: (address: TBinaryIn, optional?: { chainId?: TChainId, publicKey?: TBinaryIn }) => boolean

  //Messaging
  sharedKey: (privateKeyFrom: TBinaryIn, publicKeyTo: TBinaryIn, prefix: TRawStringIn) => TBytesOrBase58
  messageDecrypt: (sharedKey: TBinaryIn, encryptedMessage: TBinaryIn) => string
  messageEncrypt: (sharedKey: TBinaryIn, message: TRawStringIn) => TBytes

  //Encryption
  aesEncrypt: (data: TRawStringIn, secret: TBinaryIn, mode?: AESMode, iv?: TBinaryIn) => TBytes
  aesDecrypt: (encryptedData: TBinaryIn, secret: TBinaryIn, mode?: AESMode, iv?: TBinaryIn) => TBytes
```
## More examples
Every example used in this document and many more can be found on the [project`s github](https://github.com/wavesplatform/ts-lib-crypto) inside [examples](https://github.com/wavesplatform/ts-lib-crypto/tree/master/examples) folder.


