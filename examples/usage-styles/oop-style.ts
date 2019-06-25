import { crypto, randomSeed } from '@waves/waves-crypto'

const seed = randomSeed()

const c = crypto({ seed, output: 'Bytes' })

c.address() // => UInt8Array

c.publicKey()

c.privateKey()

c.keyPair()