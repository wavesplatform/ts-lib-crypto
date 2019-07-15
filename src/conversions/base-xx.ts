// import * as CryptoJS from 'crypto-js'
import * as forge from 'node-forge'
import { TBase64, TBytes, TBinaryIn, TBase58, TBase16 } from '../crypto/interface'
import base58 from '../libs/base58'
import { _fromIn } from './param'
import { binaryStringToBytes, bytesToBinaryString, stringToBytes } from './string-bytes'

export const base64Decode = (input: TBase64): TBytes =>
  binaryStringToBytes(forge.util.decode64(input))

export const base64Encode = (input: TBinaryIn): TBase64 =>
  forge.util.encode64(bytesToBinaryString(_fromIn(input)))

export const base58Decode = (input: TBase58): TBytes =>
  base58.decode(input)

export const base58Encode = (input: TBinaryIn): TBase58 =>
  base58.encode(_fromIn(input))

export const base16Decode = (input: TBase16): TBytes =>
  binaryStringToBytes(forge.util.hexToBytes(input))

export const base16Encode = (input: TBinaryIn): TBase16 =>  forge.util.bytesToHex(
  bytesToBinaryString(_fromIn(input))
)
