import { signBytes } from '@waves/waves-crypto'

const bytes = [117, 110, 99, 108, 101]
const seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'

console.log(signBytes(seed, bytes))