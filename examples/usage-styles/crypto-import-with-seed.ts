import { crypto, randomSeed } from '@waves/waves-crypto'

const seed = randomSeed()

const { address, publicKey, privateKey, keyPair } = crypto({ seed })

//Primitive functions has no params and use provided [seed] instead

address()

publicKey()

privateKey()

keyPair()