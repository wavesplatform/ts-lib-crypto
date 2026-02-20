import {bytesToString, stringToBytes} from '../src/conversions/string-bytes'
import {expect, test} from 'vitest'

test('Correctly encode and decode utf-8 strings', () => {
    const latinStr = 'wavesplatform'
    const ruStr = 'платформа вейвс'
    const emStr = '🏂По снегу'

    expect(bytesToString(stringToBytes(latinStr))).toEqual(latinStr)
    expect(bytesToString(stringToBytes(ruStr))).toEqual(ruStr)
    expect(bytesToString(stringToBytes(emStr))).toEqual(emStr)

})

