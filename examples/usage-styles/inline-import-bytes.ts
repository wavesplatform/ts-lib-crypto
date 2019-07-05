// You can use /bytes module when importing functions to set output to UInt8Array
// The flollowing functions will return UInt8Array:

// signBytes
// keyPair
// publicKey
// privateKey
// address
// blake2b
// keccak
// sha256
// sharedKey

import { address } from '@waves/ts-lib-crypto/bytes'

const seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'

address(seed) //Uint8Array [1,87,55,118,79,89,6,115,207,200,130,220,32,33,101,69,108,108,53,48,167,127,203,18,143,121]
