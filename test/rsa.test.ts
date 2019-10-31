import { stringToBytes } from '../src/conversions/string-bytes'
import { pemToBytes, rsaKeyPair, rsaKeyPairSync, rsaSign, rsaVerify } from '../src/crypto/rsa'
import { base64Decode, base64Encode } from '../src/conversions/base-xx'

test('Should get correct rsa signature', () => {
  const pair = rsaKeyPairSync()
  const msg = 'hello world'
  const msgBytes = stringToBytes(msg)
  const signature = rsaSign(pair.rsaPrivate, msgBytes)
  const valid = rsaVerify(pair.rsaPublic, msgBytes, signature)
  expect(valid).toBe(true)
})

test('Should get correct rsa signature with async keypair generation', async () => {
  const pair = await rsaKeyPair()
  const msg = 'hello world'
  const msgBytes = stringToBytes(msg)
  const signature = rsaSign(pair.rsaPrivate, msgBytes)
  const valid = rsaVerify(pair.rsaPublic, msgBytes, signature)
  expect(valid).toBe(true)
})


test('Should get correct rsa md5 signature with async keypair generation', async () => {
  const pair = await rsaKeyPair()
  const msg = 'hello world'
  const msgBytes = stringToBytes(msg)
  const signature = rsaSign(pair.rsaPrivate, msgBytes, 'MD5')
  const valid = rsaVerify(pair.rsaPublic, msgBytes, signature, 'MD5')
  expect(valid).toBe(true)
})

test('Should get correct rsa signature sha3 message digest', async () => {

  const rsaPublic = base64Decode('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsoF++eHcQwJ6gtPcxHEMAmVTVmpyRrUrxsCQV3oeNu+EiMC45WTDHs5iTEaVgneDOhJ71CmgzJ1HvxRjSmuRtP29M/9HDQOtZjLDKGY+UvroJxjXQcJ/z/PDgTZv1pV6eX754vb+h1z600Vy8MNCoY1P2D36i9v4oN5vnVnHhdrT7h6zU7IyW4UW9arRBZe3K0JXzTLOx+nSxnoFuOb6e5Ruv7sRMZPIirLHM6hUx3eOJP3AWo/B6vRvqMNqXqpSiqDQazJqp8PVljOHsQUpHpx52+/+lzRGREERNirQF7Q+C8gUnFo9B2mRg02j0g8o2TFDBVn+HLQ0NFPQlrc2gQIDAQAB')
  const rsaPrivate = base64Decode('MIIEogIBAAKCAQEAsoF++eHcQwJ6gtPcxHEMAmVTVmpyRrUrxsCQV3oeNu+EiMC45WTDHs5iTEaVgneDOhJ71CmgzJ1HvxRjSmuRtP29M/9HDQOtZjLDKGY+UvroJxjXQcJ/z/PDgTZv1pV6eX754vb+h1z600Vy8MNCoY1P2D36i9v4oN5vnVnHhdrT7h6zU7IyW4UW9arRBZe3K0JXzTLOx+nSxnoFuOb6e5Ruv7sRMZPIirLHM6hUx3eOJP3AWo/B6vRvqMNqXqpSiqDQazJqp8PVljOHsQUpHpx52+/+lzRGREERNirQF7Q+C8gUnFo9B2mRg02j0g8o2TFDBVn+HLQ0NFPQlrc2gQIDAQABAoIBADF2kKjNXSt0VF5MNrB4YsuHKECZ3nCZYzf/w/95Z0XxuNfsD1ABS9ANgE+Cf4tXcpV06bswjc4lBux7ycelZwqwBO2TnyyMCFB5YHqhWkPEIvAygfNG4gPNmC8F1pevc/CWrseliYIY0agZZnAwqxX5Alb5VaPLoGlzOZpwdkkwkySXrr+VH2FKJeR2koq/y5fcO/bVVcu4j4mkXFQof0vsBSYRf4XVO8r80hWf2Ys6MVL2gcNAtWRZt7XGLfKOOm7/v7x9r1C1ajqfQVQBpk8QHlGmcGTMedPTkih8iere1oo3qNJl8xScMfAvGg7QMTlLICgfP/SEzzoQQ3AvO8ECgYEA5XQgpQJRQcMxKhs2DWi1N9HPv1plE7o90laPs+F5MtOn8Xwt2TTrAIL3kJ4nG/mBL692rdDzODBYOIFrx4UiHxB2jWamvoq1e9JsZKLwYAnb5rLdqmO9e3qitePxL8dPJOh9QYpuMDgawDFNb0yMpN0LlQsTF92pJktDLDDYaM8CgYEAxyhqf6reIpOuuIuQLrsTWkBNGaVPBMsoWNJtDg5lKQgTCxsVmRiPfyyZpb76lHKPysN1L/J1K5peeFhRCu5WK9j6dn8OU0TpboPQN07/cDQ9HZ+k6HR3fPfkpOgCVRnp7XqbE+MGXLs+fFa5AyfDBcS2k1EfUG1wf9RSUAkhn68CgYANWY1QrGrX3ahtn7msXAw3HDDvHC5HUI2qQDkKKTMo/uGFjkkImyiVFgmbU2hJG2IlyRqpkD+mZEGtv/HqYNeUYRvUrEVFTsKyWpLN5CECJXCy4nM9J6Jtnbv7wzBULE9xgUlQV+KDUbBUwEmWESkZqnazDDrnJ5Fg1f4pgwoERwKBgBnJq/CYCWdkxAz1VVgXtSvMg688bnzqaXEG3kQhrQuhFgYsHaHTQlFvTv3dOskaBHB22qe4t19L/8uJdAT8U4Ad+mB5lztFAwziWIWw3vaCbR922n2XBxnRZ3PK7vJiBp5Pb+ElVl+Ph0nGWPKFpYULsbBloq5hXV3P+lCOviHVAoGAJfD5s14oil6H4xDDPZMlELOpiuJQFyiIzyU19xR1N3QkyQb/fHlVIdiG5tMHpKaCVd0RryR77sRU3VVxpaYdJkLJQ+xkhwjqOZjyyxw3prO39e2m80s4jddHKKPJ1Bapxu4vY1qR7w0ptgKpxMOQTERcyuMmA4KvDgduW0q9/G0=')
  const msg = 'hello world'
  console.log(base64Encode(stringToBytes(msg)))
  const msgBytes = stringToBytes(msg)
  const signature = rsaSign(rsaPrivate, msgBytes, 'SHA3-256')
  console.log(base64Encode(signature))
  const valid = rsaVerify(rsaPublic, msgBytes, signature, 'SHA3-256')
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


