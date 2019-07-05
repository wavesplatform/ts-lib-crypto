import { concat, randomBytes } from '@waves/ts-lib-crypto'

const bytesA = randomBytes(2)
const bytesB = randomBytes(2)
concat(bytesA, bytesB) // Uint8Array [ 36, 18, 254, 205 ]
