import { TBytes, TBinaryIn } from '../crypto/interface'
import { _fromIn } from './param'
import { Utf8ArrayToStr } from '../libs/Utf8ArrayToStr'

export const stringToBytes = (str: string): TBytes =>
  Uint8Array.from([...unescape(encodeURIComponent(str))].map(c => c.charCodeAt(0)))

export const bytesToString = (bytes: TBinaryIn): string => Utf8ArrayToStr(Array.from(_fromIn(bytes)))
