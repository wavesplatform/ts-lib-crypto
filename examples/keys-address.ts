import { crypto } from '@waves/ts-lib-crypto'

const { randomSeed } = crypto()
const seed = randomSeed() //figure soap board earth measure stay can nature will figure clown cross save mention liberty

{ //Simple example

  const { address, publicKey, privateKey, keyPair } = crypto()

  //Functions for creating Waves primitives like addresses and keys

  address(seed) // 3PAP3wkgbGjdd1FuBLn9ajXvo6edBMCa115

  publicKey(seed) // DubrvJC83QaPFJU1hJDWxemgxcRxy482MDf8dxhWJ8K9

  privateKey(seed) // 4GDnGxTqHJsWsW6dCugGsbUfkdw5Mhu5NznkuaFifCZC

  keyPair(seed) // { privateKey: '4GDnGxTqHJsWsW6dCugGsbUfkdw5Mhu5NznkuaFifCZC', publicKey: 'DubrvJC83QaPFJU1hJDWxemgxcRxy482MDf8dxhWJ8K9' }

}

{ //Embeded seed example

  const { address, publicKey, privateKey, keyPair } = crypto({ seed })

  //Primitive functions has no params and use provided [seed] instead

  address()

  publicKey()

  privateKey()

  keyPair()

}

{ //For OOP fans


}



