import {crypto} from '../src/crypto/crypto'
import {base58Decode, base58Encode} from '../src/conversions/base-xx'
import {describe, expect, it} from 'vitest'

describe('BLS keygen compatibility test', () => {

    it('should derive correct keys, sign and verify message', () => {

        const seed = base58Decode('CuedBd7a6vBC6XXpatEj4S9ZoquLYPB7Ud17b69msZkt')
        const expectedPrivateKeyBase58 = '31C6T1rHYVuHYn14NPrmwmkfGHsyVWoieVLak4jydHFd'
        const expectedPublicKeyBase58  = '7C6PyzoBTrTgNT3nJGUQbRTFCjwQe64wwbkrbtWgQkeR2exLMVLMN82rxZgKjhtmfK'

        const c = crypto({ output: 'Bytes' })
        const { blsSecret, blsPublic } = c.blsKeyPair(seed)

        expect(base58Encode(blsSecret)).toBe(expectedPrivateKeyBase58)
        expect(base58Encode(blsPublic)).toBe(expectedPublicKeyBase58)


        const message = new TextEncoder().encode('BlaBlaBla')

        const expectedSignatureBase58 = 'xhagZTYNfffENgdcyYxWwfbEnU7wRJqVAbxqHKXj1WVDKqr8dvsr2U77WuAbZCFFDzoTbqUaniBNuZftz3eacuudxkqk1khgfAC56uW6EjrYmq63RBqTCj5Rkosjv9t8zwx'

        const signature = c.blsSign(blsSecret, message)
        const signatureBase58 = base58Encode(signature)

        expect(signatureBase58).toBe(expectedSignatureBase58)

        expect(c.blsVerify(blsPublic, message, signature)).toBe(true)

        const wrongMessage = new TextEncoder().encode('tampered')
        expect(c.blsVerify(blsPublic, wrongMessage, signature)).toBe(false)

        const wrongSeed = base58Decode('AnotherSeed123456789912345678991234567899')
        const { blsPublic: wrongPk } = c.blsKeyPair(wrongSeed)
        expect(c.blsVerify(wrongPk, message, signature)).toBe(false)
    })

})
