# waves-crypto  [![npm version](https://badge.fury.io/js/waves-crypto.svg)](https://www.npmjs.com/package/@waves/waves-crypto)

Using this library you can easily create and sign binary data for Waves blockchain.
It provides all you need on crypto and binary layers.
Small and dependency-free.

### Includes:
- Address generation
- Address validation 
- Key pair generation
- Bytes signature
- Signature validation
- Serialization primitives

### Keys and Addresses

```js
const wc = require('waves-crypto')

//Mainnet address
wc.address('seed') //3PGMh3vQekpTbvUAiKwdzhWsLaxoSBEcsFJ

//Testnet address
wc.address('seed', 'T')//3N4Lt6bWndH4yUAkTFge3F93yhT2c2Pmj9z

//Public and private keys from seed
wc.keyPair('seed')

/*{
  public: 'HzSnoJKTVwezUBmo2gh9HYq52F1maKBsvv1ZWrZAHyHV',
  private: '4mmuDf2GQJ6vJrKzVzyKUyGBwv6AfpC5TKpaF3MfEE5w'
}*/

//Public only
wc.publicKey('seed') //HzSnoJKTVwezUBmo2gh9HYq52F1maKBsvv1ZWrZAHyHV

//Private only
wc.privateKey('seed') //4mmuDf2GQJ6vJrKzVzyKUyGBwv6AfpC5TKpaF3MfEE5w

```
### Address validation

```js
const { validateAddress } = require('waves-crypto')

const validationErrors = validateAddress('3P2GVAniTmceyS7LE8HtQg1GEhyoghUZSvn') 
// ['Address checksum is invalid.']

isValid(validationErrors) //false

```

### Signatures and verification

```js
const wc = require('waves-crypto')
const { verifySignature, signBytes, publicKey } = wc

const seed = 'magicseed'
const pubKey = publicKey(seed)

const bytes = Uint8Array.from([1, 2, 3, 4])
const sig = signBytes(bytes, seed)
const isValid = verifySignature(pubKey, bytes, sig) //true

```
