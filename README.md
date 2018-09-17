# waves-crypto  [![npm version](https://badge.fury.io/js/waves-crypto.svg)](https://www.npmjs.com/package/waves-crypto)

Using this library you can easily create and sign binary data for Waves blockchain.
It provides all you need on crypto and binary layers.
Small and dependency-free.

### Includes:
- Address generation
- Key pair generation
- Transaction serialization
- Data signature

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

### Serialization and Signatures

```js
const wc = require('waves-crypto')
const { LONG, SHORT, BYTE, STRING, OPTION, BASE58_STRING, LEN } = wc

//Transfer transaction for 1 waves
const tx = {
  version: 1,
  type: 4,
  recipient: '3P6jpTTGxnVYGKpmaDWjCQWZxadYSdeykMP',
  amount: 1 * Math.pow(10, 8),
  fee: 100000,
  senderPublicKey: wc.publicKey('seed'),
  timestamp: Date.now(),
  assetId: null,
  feeAssetId: null,
  attachment: null,
}

const bytes = wc.concat(
  BYTE(4),
  BYTE(tx.version),
  BASE58_STRING(tx.senderPublicKey),
  OPTION(BASE58_STRING)(tx.assetId),
  OPTION(BASE58_STRING)(tx.feeAssetId),
  LONG(tx.timestamp),
  LONG(tx.amount),
  LONG(tx.fee),
  BASE58_STRING(tx.recipient),
  LEN(SHORT)(STRING)(tx.attachment),
)

wc.signBytes(bytes, 'seed') // 5FSwfLir7YRavgRjdzs9Hg2KEv2Pu8szmXMgNbkt6BAm9fAJGURzDp6PiN1QhRfXBUYU1xJghzqijFebFA9yFXyp

```
