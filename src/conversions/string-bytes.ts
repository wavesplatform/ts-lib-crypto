import { TBytes, TBinaryIn } from '../crypto/interface'
import { _fromIn } from './param'
import { utf8ArrayToStr, strToUtf8Array } from '../libs/Utf8'

/**
 * Converts string to utf-8 array
 */
export const stringToBytes = (str: string): TBytes => strToUtf8Array(str)

/**
 * Reads bytes as utf-8 string
 */
export const bytesToString = (bytes: TBinaryIn): string => utf8ArrayToStr(Array.from(_fromIn(bytes)))

/**
 * Converts each character to byte
 */
export const binaryStringToBytes = (str: string): TBytes =>
  Uint8Array.from([...str].map(c => c.charCodeAt(0)))

/**
 * Reads each byte as individual character
 */
export const bytesToBinaryString = (bytes: TBinaryIn): string =>
  String.fromCharCode.apply(null, Array.from(_fromIn(bytes)))
