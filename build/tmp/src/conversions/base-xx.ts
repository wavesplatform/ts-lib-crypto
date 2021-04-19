//@ts-ignore
import { encode64, decode64, hexToBytes, bytesToHex } from 'node-forge/lib/util'
import { TBase64, TBytes, TBinaryIn, TBase58, TBase16 } from '../crypto/interface'
import base58 from '../libs/base58'
import { _fromIn } from './param'
import { bytesToString, stringToBytes } from './string-bytes'

export const base64Decode = (input: TBase64): TBytes =>
  stringToBytes(decode64(input), 'raw')

export const base64Encode = (input: TBinaryIn): TBase64 =>
  encode64(bytesToString(_fromIn(input), 'raw'))

export const base58Decode = (input: TBase58): TBytes =>
  base58.decode(input)

export const base58Encode = (input: TBinaryIn): TBase58 =>
  base58.encode(_fromIn(input))

export const base16Decode = (input: TBase16): TBytes =>
  stringToBytes(hexToBytes(input), 'raw')

export const base16Encode = (input: TBinaryIn): TBase16 => bytesToHex(
  bytesToString(_fromIn(input), 'raw')
)
