import { randomBytes } from '../src/crypto/random'
import { keyPair } from '../src/crypto/address-keys-seed'
import { sharedKey } from '../src/crypto/encryption'
import { base64Decode, base64Encode } from '../src/conversions/base-xx'
import { bytesToString } from '../src/conversions/string-bytes'

const s = 'secret test seed'

test('convertions', () => {

  const bytes = Uint8Array.from([1, 2, 3, 4, 5, 6])
  console.log(base64Decode(base64Encode(bytes)))
})
