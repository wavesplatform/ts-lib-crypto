import { crypto, MAIN_NET_CHAIN_ID } from '../src/index'
import * as CryptoJS from 'crypto-js'

const { seed, aesDecrypt, aesEncrypt, address, concat, split, sharedKey, messageEncrypt, messageDecrypt, randomBytes, bytesToString, stringToBytes, keyPair, publicKey, privateKey, signBytes, verifySignature, verifyAddress, base58Decode, base58Encode, base16Decode, base16Encode, base64Decode, base64Encode } = crypto({ output: 'Base58' })

const s = 'seed'

test('encrypt and decrypt aes roundtrip', () => {
  const prefix = 'waves'
  const a = keyPair(s)
  const b = keyPair(s + s)
  const sk = sharedKey(a.privateKey, b.publicKey, prefix)

  const message = 'message'
  const enc = aesEncrypt(message, sk, 'ECB')
  const decoded = bytesToString(aesDecrypt(enc, sk, 'ECB'))
  expect(message).toEqual(decoded)
})