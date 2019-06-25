# waves-crypto [![npm version](https://badge.fury.io/js/%40waves%2Fwaves-crypto.svg)](https://www.npmjs.com/package/@waves/waves-crypto)

[lib-name]: waves-crypto


  This library contains crypto primitives used in Waves protocol. 
  It could be split into 9 main categories:
 
 - Seed generation
	 - randomSeed
	 - seedWordsList
 - Keys and address
	 - keyPair
	 - publicKey
	 - privateKey
	 - address
 - Signatures
	- signBytes
	- verifySignature
- Hashing
	 - blake2b
	 - keccak
	 - sha256
 - Random
	 - randomBytes
 - Base encoding\decoding
	 -   base64Encode
	 -   base64Decode
	 -   base58Encode
	 -   base58Decode
	 -   base16Encode
	 -   base16Decode
 - Messaging
	 - sharedKey
	 - messageDecrypt
	 - messageEncrypt
 - Encryption
	 - aesEncrypt
	 - aesDecrypt
 - Utils
	 - split
	 - concat
	 - stringToBytes
	 - bytesToString

# Import styles
The is several ways of doing things when using [lib-name].
You can import functions strait-forward:
```ts
import { address } from  '@waves/waves-crypto'
address('my secret seed') // 3PAP3wkgbGjdd1FuBLn9ajXvo6edBMCa115
```
Or you can use a crypto constructor function:
```ts
import { crypto } from  '@waves/waves-crypto'
const { address } = crypto()
address('my secret seed') // 3PAP3wkgbGjdd1FuBLn9ajXvo6edBMCa115
```
The second approach gives you more flexibility, using this approach you are able to embed the **seed** and use all seed-dependant functions without **seed** parameter:
```ts
import { crypto } from  '@waves/waves-crypto'
const { address } = crypto({seed: 'my secret seed'})
address() // 3PAP3wkgbGjdd1FuBLn9ajXvo6edBMCa115
```
# Outputs
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
blake2b
keccak
sha256
sharedKey
signBytes
```

If you prefer **binary** output, you can alter this behaviour and make those functions to return **UInt8Array** instead.

When using inline import style:
```ts
// You can use /bytes module when importing functions to set output to UInt8Array
import { address } from  '@waves/waves-crypto/bytes'
address('my secret seed') //Uint8Array [1,87,55,118,79,89,6,115,207,200,130,220,32,33,101,69,108,108,53,48,167,127,203,18,143,121]
```
When using crypto constructor function:
```ts
import { crypto } from  '@waves/waves-crypto'
const { address } = crypto({ output: 'Bytes' })
address('my secret seed') //Uint8Array [1,87,55,118,79,89,6,115,207,200,130,220,32,33,101,69,108,108,53,48,167,127,203,18,143,121]
```


# Seed generation

The seed is a set of words or bytes that private and public keys are generated from.
The usual Waves seed looks like:
```
uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine
```
But seed could be any string or bytes.
The are several ways to generate seed using [lib-name]:

### randomSeed
```ts
import { randomSeed } from  '@waves/waves-crypto'

randomSeed() //uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine
```

You can also specify seed size:
```ts
randomSeed(3) //uncle push human
```
The default seed size is 15 words.

### seedWordsList
If you want to get all the valid seed words, use **seedWordsList** - 2048 word array.
```ts
import { seedWordsList } from  '@waves/waves-crypto'
console.log(seedWordsList) // [ 'abandon','ability','able', ... 2045 more items ]
```
# Keys and address

... to be continued 