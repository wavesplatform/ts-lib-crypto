import { signBytes, verifySignature, keyPair } from '@waves/ts-lib-crypto'

//Signature roundtrip
const bytes = [117, 110, 99, 108, 101]
const seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
const keys = keyPair(seed)
const signature = signBytes(keys, bytes)
verifySignature(keys.publicKey, bytes, signature) // true