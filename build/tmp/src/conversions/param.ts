import { TBinaryIn, TBytes, TRawStringIn, TRawStringInDiscriminator } from '../crypto/interface'
import { base58Decode } from './base-xx'
import { stringToBytes } from './string-bytes'

const isString = (val: any): val is string => typeof val === 'string' || val instanceof String
const isUint8Array = (val: any): val is Uint8Array => val instanceof Uint8Array

const isTRawStringInDiscriminator = (_: TRawStringIn): _ is TRawStringInDiscriminator => false

export const _fromIn = (inValue: TBinaryIn): TBytes => {
  if (isString(inValue))
    return base58Decode(inValue)

  if (isUint8Array(inValue))
    return inValue

  return Uint8Array.from(inValue)
}

export const _fromRawIn = (inValue: TRawStringIn): TBytes => {
  if (isTRawStringInDiscriminator(inValue))
    throw new Error('')

  if (isString(inValue))
    return stringToBytes(inValue)

  if (isUint8Array(inValue))
    return inValue

  return Uint8Array.from(inValue)
}
