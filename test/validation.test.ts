import { validateAddress, validatePublicKey, verifySignature, address, base58decode, base58encode, randomUint8Array, signBytes, publicKey } from '../src'
import { isValid } from '../src/validation'

describe('address validation', () => {

  const validAddress = '3P2GVAniTmceyS7LE8HtQg1GEhyoghUZctz'
  const invalidVersion = '5A2nuEb2DXoHGo52QPh9zp6wdq7mAhRtssG'
  const invalidChainId = '3GBXERweZhYn5XjxkiADzRsds1QRecVeTX8'
  const invalidChecksum = '3P2GVAniTmceyS7LE8HtQg1GEhyoghUZSvn'

  it('sunny day', () => {
    expect(isValid(validateAddress(validAddress))).toBe(true)
  })

  it('invalid version', () => {
    const validationErrors = validateAddress(invalidVersion)
    expect(validationErrors[0]).toMatch(/version/i)
  })

  it('invalid chainId', () => {
    const validationErrors = validateAddress(invalidChainId)
    expect(validationErrors[0]).toMatch(/chainid/i)
  })

  it('invalid checksum', () => {
    const validationErrors = validateAddress(invalidChecksum)
    expect(validationErrors[0]).toMatch(/checksum/i)
  })

})

describe('public key validation', () => {

  const validPublicKey = '8utK9Rimqq7JhGxaxBwYddgJhW3hL5UUDQS8bShdZLcx'

  it('sunny day', () => {
    expect(isValid(validatePublicKey(validPublicKey))).toBe(true)
  })

  it('invalid length', () => {
    const validationErrors = validatePublicKey(validPublicKey.slice(14))
    expect(validationErrors[0]).toMatch(/length/i)
  })

})

describe('signarute validation', () => {

  const bytes = randomUint8Array(10)
  const seed = base58encode(randomUint8Array(20))
  const sig = signBytes(bytes, seed)

  it('sunny day', () => {
    expect(verifySignature(publicKey(seed), bytes, sig)).toBe(true)
  })

  it('invalid sig', () => {
    expect(verifySignature(publicKey(seed), randomUint8Array(10), sig)).toBe(false)
  })

})