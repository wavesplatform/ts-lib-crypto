import {
  address,
  keyPair,
  publicKey,
  privateKey,
  signBytes,
  verifySignature,
  base58encode,
  base58decode,
  getSharedKey,
  encryptMessage,
  decryptMessage,
  sha256, buildSeedHash, stringToUint8Array,
} from '../src'

const seed = '1f98af466da54014bdc08bfbaaaf3c67'

test('address', () =>
  expect(address(seed)).toBe('3PKjdoVXMT96VEP8YAZRy4jKKA5GkjovboD')
)

test('keyPair', () =>
  expect(keyPair(seed)).toEqual({
    public: '12wYe4Y5Z5uJXRQw44huYYszidfMfFbwhjyVTparH1wT',
    private: 'AAJPFvUtBgSMWbDQgCJUxzXmYeggKgn8a4LEMGaoWEMj',
  })
)

test('publicKey', () =>
  expect(publicKey(seed)).toBe('12wYe4Y5Z5uJXRQw44huYYszidfMfFbwhjyVTparH1wT')
)

test('privateKey', () =>
  expect(privateKey(seed)).toBe('AAJPFvUtBgSMWbDQgCJUxzXmYeggKgn8a4LEMGaoWEMj')
)

test('signature roundtrip', () => {
  const bytes = Uint8Array.from([1, 2, 3, 4])
  const sig = signBytes(bytes, seed)
  const valid = verifySignature(publicKey(seed), bytes, sig)
  const invalid = verifySignature(publicKey(seed), Uint8Array.from([4, 3, 2, 1]), sig)
  expect(valid).toBe(true)
  expect(invalid).toBe(false)
})

test('base58 roundtrip', () => {
  const base58 = '5k1XmKDYbpxqAN'
  const result = base58encode(base58decode(base58))
  expect(result).toEqual(base58)
})

test('generate shared key', () => {
  const a = keyPair(seed)
  const b = keyPair(seed + seed)
  const shKey = getSharedKey(a.private, b.public)
  const shKey2 = getSharedKey(b.private, a.public)
  expect(shKey.toString()).toEqual(shKey2.toString())
})

test('encrypt and decrypt message', () => {
  const msg = 'test message from me'
  const a = keyPair(seed + seed)
  const b = keyPair(seed + seed + seed)
  const shKey = getSharedKey(a.private, b.public)
  const message = encryptMessage(base58encode(shKey), msg)

  const data = decryptMessage(base58encode(shKey), message)

  expect(data).toEqual(msg)
})

