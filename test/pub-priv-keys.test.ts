import {privateKey, publicKey, randomSeed} from '../src'
import {test, expect} from 'vitest'

test('Should get public key from private', () => {
    const seed = randomSeed()
    const pk = publicKey(seed)

    expect(pk).toEqual(publicKey({privateKey: privateKey(seed)}))
})
