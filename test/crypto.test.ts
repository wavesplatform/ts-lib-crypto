import { randomBytes } from 'crypto'
import { keyPair } from '../src/address-keys-seed'
import { sharedKey } from '../src/encryption'
import { base64Decode, base64Encode } from '../src/conversions/base-xx'
import { bytesToString } from '../src/conversions/string-bytes'
import CryptoJS from 'crypto-js'

const s = 'secret test seed'

test('crypto js', () => {
  const bytes = randomBytes(32)
  const prefix = 'waves'
  const a = keyPair(s)
  const b = keyPair(s + s)
  const sk = sharedKey(a.privateKey, b.publicKey, prefix)

  const enc = base64Decode(CryptoJS.AES.encrypt(base64Encode(bytes), bytesToString(sk), { mode: CryptoJS.mode.ECB }).toString())
  const result = base64Decode(CryptoJS.AES.decrypt(base64Encode(enc), bytesToString(sk), { mode: CryptoJS.mode.ECB }).toString(CryptoJS.enc.Utf8))

  expect(bytes).toEqual(result)

})
