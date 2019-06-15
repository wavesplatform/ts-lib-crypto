import { TBytes, TBinaryIn } from '../interface'
import { _fromIn } from './param'

export const stringToBytes = (str: string): TBytes =>
  Uint8Array.from([...unescape(encodeURIComponent(str))].map(c => c.charCodeAt(0)))

export const bytesToString = (bytes: TBinaryIn): string =>
  String.fromCharCode.apply(null, Array.from(_fromIn(bytes)))