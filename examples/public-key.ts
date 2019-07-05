import { publicKey, seedWithNonce } from '@waves/ts-lib-crypto'
const seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
publicKey(seed) // 4KxUVD9NtyRJjU3BCvPgJSttoJX7cb3DMdDTNucLN121
publicKey(seedWithNonce(seed, 0)) // 4KxUVD9NtyRJjU3BCvPgJSttoJX7cb3DMdDTNucLN121