import { base16Encode, base16Decode, base58Encode, base58Decode, base64Encode, base64Decode, randomBytes } from '@waves/ts-lib-crypto'

const bytes = randomBytes(32)

// Base16 same as Hex
const base16String = base16Encode(bytes) // 2059ec5d9ed640b75722ec6a2ff76890e523ea4624887549db761d678ba8f899
const bytesFromBase16 = base16Decode(base16String)

// Base58
const base58String = base58Encode(bytes) // 3BHaM9Q5HhUobQ5oZAqjdkE9HRpmqMx4XLq3GXTMD5tU
const bytesFromBase58 = base58Decode(base58String)

// Base64
const base64String = base64Encode(bytes) // IFnsXZ7WQLdXIuxqL/dokOUj6kYkiHVJ23YdZ4uo+Jk=
const bytesFromBase64 = base64Decode(base64String)
