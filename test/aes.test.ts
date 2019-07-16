import { crypto } from '../src/crypto/crypto'
const { aesDecrypt, aesEncrypt, sharedKey, bytesToString, keyPair, randomBytes, stringToBytes } = crypto({ output: 'Base58' })


const s = 'seed'

test('encrypt and decrypt aes roundtrip', () => {
  const prefix = 'waves'
  const a = keyPair(s)
  const b = keyPair(s + s)
  const sk = sharedKey(a.privateKey, b.publicKey, prefix)

  const message = 'message'
  const enc = aesEncrypt(stringToBytes(message), sk, 'ECB')
  const decoded = bytesToString(aesDecrypt(enc, sk, 'ECB'))
  expect(message).toEqual(decoded)
})


test('encrypt and decrypt data', () => {
  const key = randomBytes(32)
  const iv = randomBytes(16)

  const message = 'message'
  const enc = aesEncrypt(stringToBytes(message), key, 'CBC', iv)
  const decoded = aesDecrypt(enc, key, 'CBC', iv)
  expect(bytesToString(decoded)).toEqual(message)
})
