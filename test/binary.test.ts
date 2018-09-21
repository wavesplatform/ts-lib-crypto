import { LONG, SHORT, BYTE, BYTES, STRING, INT, BOOL, OPTION, COUNT, LEN, BASE58_STRING, BASE64_STRING, one, zero } from '../src'


const string = 'TestString'
const bytes = [84, 101, 115, 116, 83, 116, 114, 105, 110, 103]
const base58 = '5k1XmKDYbpxqAN'
const base64 = 'VGVzdFN0cmluZw=='

test('LONG', () => {
  expect(LONG('1')).toEqual(Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 1]))
  expect(LONG(1)).toEqual(Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 1]))
})

test('BYTE', () => {
  expect(BYTE(1)).toEqual(Uint8Array.from([1]))
})

test('BYTES', () => {
  expect(BYTES([34, 192])).toEqual(Uint8Array.from([34, 192]))
})

test('STRING', () => {
  expect(STRING(string)).toEqual(Uint8Array.from(bytes))
})

test('INT', () => {
  expect(INT(1)).toEqual(Uint8Array.from([0, 0, 0, 1]))
})

test('SHORT', () => {
  expect(SHORT(1)).toEqual(Uint8Array.from([0, 1]))
})

test('BOOL', () => {
  expect(BOOL(false)).toEqual(zero)
  expect(BOOL(true)).toEqual(one)
})

test('OPTION', () => {
  expect(OPTION(BOOL)(null)).toEqual(Uint8Array.from([0]))
  expect(OPTION(BOOL)(false)).toEqual(Uint8Array.from([1, 0]))
})

test('COUNT', () => {
  expect(COUNT(BYTE)((x: boolean) => BOOL(x))([true, false, true])).toEqual(Uint8Array.from([3, 1, 0, 1]))
})

test('LEN', () => {
  expect(LEN(BYTE)(BYTES)([1, 2, 3, 4])).toEqual(Uint8Array.from([4, 1, 2, 3, 4]))
})

test('BASE58_STRING', () => {
  expect(BASE58_STRING(base58)).toEqual(Uint8Array.from(bytes))
})

test('BASE64_STRING', () => {
  expect(BASE64_STRING(base64)).toEqual(Uint8Array.from(bytes))
})





