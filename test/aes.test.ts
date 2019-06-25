import { crypto } from '../src/crypto/crypto'
const { aesDecrypt, aesEncrypt, sharedKey, bytesToString, keyPair } = crypto({ output: 'Base58' })

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