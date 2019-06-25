import { crypto } from '@waves/waves-crypto'

const { randomSeed, address, publicKey, privateKey, keyPair } = crypto()

const seed = randomSeed()

address(seed) // 3PAP3wkgbGjdd1FuBLn9ajXvo6edBMCa115

publicKey(seed) // DubrvJC83QaPFJU1hJDWxemgxcRxy482MDf8dxhWJ8K9

privateKey(seed) // 4GDnGxTqHJsWsW6dCugGsbUfkdw5Mhu5NznkuaFifCZC

keyPair(seed) // { publicKey: 'DubrvJC83QaPFJU1hJDWxemgxcRxy482MDf8dxhWJ8K9', privateKey: '4GDnGxTqHJsWsW6dCugGsbUfkdw5Mhu5NznkuaFifCZC' }
