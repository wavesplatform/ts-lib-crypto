import { seedWithNonce, randomSeed, address } from '@waves/ts-lib-crypto'

const nonce = 1
const seedphrase = randomSeed() // uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine
const seed = seedWithNonce(seedphrase, nonce)

//Now you can use seed as usual

address(seed)
