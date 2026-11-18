// Loads the built bundles the way consumers do (Node ESM import and CJS require) and checks that
// both work and agree. vitest runs against src/, so without this a bundle that only breaks at
// module resolution (as the ESM build did in 1.5.1 and 1.5.2) is published unnoticed.
import { createRequire } from 'node:module'
import assert from 'node:assert/strict'

const esm = await import('../dist/esm/index.mjs')
const cjs = createRequire(import.meta.url)('../dist/cjs/index.cjs')

// Touches every node-forge code path: hashing, hmac (via messageEncrypt), AES, MD5 (seed encryption),
// util (base16/base64), random and RSA.
const run = (c) => {
  const seed = 'check dist seed'
  const kp = c.keyPair(seed)
  const msg = c.stringToBytes('hello')
  const rsa = c.rsaKeyPairSync(512)
  const rsaSig = c.rsaSign(rsa.rsaPrivate, msg, 'SHA256')
  const shared = c.sharedKey(kp.privateKey, c.keyPair('other seed').publicKey, 'waves')
  const key = c.sha256(msg)
  const iv = key.slice(0, 16)
  return {
    address: c.address(seed),
    signed: c.verifySignature(kp.publicKey, msg, c.signBytes(kp, msg)),
    sha256: c.base16Encode(c.sha256(msg)),
    base64: c.base64Encode(msg),
    aes: c.base16Encode(c.aesEncrypt(msg, key, 'CBC', iv)),
    aesRoundTrip: c.bytesToString(c.aesDecrypt(c.aesEncrypt(msg, key, 'CBC', iv), key, 'CBC', iv)),
    seed: c.decryptSeed(c.encryptSeed(seed, 'password'), 'password'),
    message: c.messageDecrypt(shared, c.messageEncrypt(shared, 'hi')),
    random: c.randomBytes(8).length,
    rsa: c.rsaVerify(rsa.rsaPublic, msg, rsaSig, 'SHA256'),
  }
}

const expected = {
  signed: true,
  base64: 'aGVsbG8=',
  aesRoundTrip: 'hello',
  seed: 'check dist seed',
  message: 'hi',
  random: 8,
  rsa: true,
}
const fromEsm = run(esm)
const fromCjs = run(cjs)
assert.deepEqual(fromEsm, fromCjs, 'ESM and CJS bundles disagree')
for (const [k, v] of Object.entries(expected)) assert.equal(fromEsm[k], v, k)
console.log('dist ok: ESM and CJS bundles load and agree')
