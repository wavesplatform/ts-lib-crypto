import {
    address,
    keyPair,
    publicKey,
    privateKey,
    signBytes,
    verifySignature,
    concat,
    BYTES,
    BASE58_STRING,
    OPTION, LEN, SHORT, BASE64_STRING, LONG
} from '../src'
const tx = {
    "type": 13,
    "version": 1,
    "script": "base64:AQQAAAALYWxpY2VQdWJLZXkBAAAAID3+K0HJI42oXrHhtHFpHijU5PC4nn1fIFVsJp5UWrYABAAAAAlib2JQdWJLZXkBAAAAIBO1uieokBahePoeVqt4/usbhaXRq+i5EvtfsdBILNtuBAAAAAxjb29wZXJQdWJLZXkBAAAAIOfM/qkwkfi4pdngdn18n5yxNwCrBOBC3ihWaFg4gV4yBAAAAAthbGljZVNpZ25lZAMJAAH0AAAAAwgFAAAAAnR4AAAACWJvZHlCeXRlcwkAAZEAAAACCAUAAAACdHgAAAAGcHJvb2ZzAAAAAAAAAAAABQAAAAthbGljZVB1YktleQAAAAAAAAAAAQAAAAAAAAAAAAQAAAAJYm9iU2lnbmVkAwkAAfQAAAADCAUAAAACdHgAAAAJYm9keUJ5dGVzCQABkQAAAAIIBQAAAAJ0eAAAAAZwcm9vZnMAAAAAAAAAAAEFAAAACWJvYlB1YktleQAAAAAAAAAAAQAAAAAAAAAAAAQAAAAMY29vcGVyU2lnbmVkAwkAAfQAAAADCAUAAAACdHgAAAAJYm9keUJ5dGVzCQABkQAAAAIIBQAAAAJ0eAAAAAZwcm9vZnMAAAAAAAAAAAIFAAAADGNvb3BlclB1YktleQAAAAAAAAAAAQAAAAAAAAAAAAkAAGcAAAACCQAAZAAAAAIJAABkAAAAAgUAAAALYWxpY2VTaWduZWQFAAAACWJvYlNpZ25lZAUAAAAMY29vcGVyU2lnbmVkAAAAAAAAAAACVateHg==",
    "fee": 1000000,
    "senderPublicKey": "sxhjjUdX8SpAUg6KWPRJUXhE1tyTWHUyUUaCc8kf5LL",
    "timestamp": 1539622837343,
    "chainId": "W",
    "proofs": [
    "3a2nME5o8eYEYrH6aSpXn1DvNeMkrFhWvRrs7vmNtsWgMTdczcpSd1vm7ejHZJoXa6hmVDjUN4K97LuptVFBu1oS"
],
    "id": "7iKjEshrPQSyjKHtmZ5wA4rzYon5k7cnF1BQvnAkZHmL"
}
const bytes = concat(
    BYTES([tx.type, tx.version, tx.chainId.charCodeAt(0)]),
    BASE58_STRING(tx.senderPublicKey),
    OPTION(LEN(SHORT)(BASE64_STRING))(tx.script ? tx.script.slice(7) : null),
    LONG(tx.fee),
    LONG(tx.timestamp),
)
//
//
// test('asv', ()=>{
//     verifySignature(tx.senderPublicKey, bytes, tx.proofs[0])
//     const s = signBytes(bytes,'abcd')
//     console.log(s)
// })

import {describe, it} from 'mocha';
import {expect} from 'chai';

describe('asd',()=>{
    it('asd', ()=>{
        verifySignature(tx.senderPublicKey, bxytes, tx.proofs[0])
        const s = signBytes(bytes,'abcd')
        console.log(s)
    })
})