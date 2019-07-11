import { stringToBytes } from '../src/conversions/string-bytes'
import { pemToBytes, rsaKeyPair, rsaSign, rsaVerify } from '../src/crypto/rsa'
import { base64Encode } from '../src/conversions/base-xx'

test('Should get correct rsa signature', () => {
  const pair = rsaKeyPair()
  const msg = 'hello world'
  const msgBytes = stringToBytes(msg)
  const signature = rsaSign(pair.rsaPrivate, msgBytes)
  const valid = rsaVerify(pair.rsaPublic, msgBytes, signature)
  expect(valid).toBe(true)
})

test('Should get hardcoded signature', () => {
  const hardcodedSignature = 'yBZe9REcRPrDFSvB7iMl8uIzMGAAD/rqKpO0r8e2e9UziShAR3w96IUP+yC1N+Ape6EjeTyHbsHuKTNID/fqaA=='
  const msg = 'hello world'
  const privatePem = '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIBOwIBAAJBAOoxJRf+ya3C6VR2S26WgIbDmIh7M5DGSjIi4mUJoD0c2bsmyI8/\n' +
    'BelIwRbqnETzGI+ONX+j58o6hvHnyR1XuS8CAwEAAQJABIcMs4kOdxiEkEh1Lt8j\n' +
    '/vb7FPBkz9C1kICSJefovCWwLCV05XORS3+4rP35AYpQIsksyBLxr1tcMt+fBgMM\n' +
    'OQIhAPcTZ7wYmcDHyN/4q8b6WJQ6CUAOTT6aVuqTwLpVeDGVAiEA8qab4g0Upukf\n' +
    'qtLzd9b3H0m80ANGi6BsSa5nVMPRVrMCIDupGuZnhlDvrQiwEkKU1ujL7snh6jMQ\n' +
    'r6YrEWGtG73VAiEArSEDB/6dRZn/5jotTMwr9j7+YMx1gRotKUUupOQycNECIQCh\n' +
    'HEpECtXjRr4z7Ef3pq4NRSymNtdlsjpGFYTLCm5PpQ==\n' +
    '-----END RSA PRIVATE KEY-----\n'

  const privateBytes = pemToBytes(privatePem)
  const msgBytes = stringToBytes(msg)
  const signature = base64Encode(rsaSign(privateBytes, msgBytes))
  expect(hardcodedSignature).toEqual(signature)
})


