import * as CryptoJS from 'crypto-js'
import { TBase64, TBytes, TBinaryIn, TBase58, TBase16 } from '../interface'
import base58 from '../libs/base58'
import { _fromWords, _toWords, _fromIn } from './param'

export const base64Decode = (input: TBase64): TBytes =>
  _fromWords(CryptoJS.enc.Base64.parse(input))

export const base64Encode = (input: TBinaryIn): TBase64 =>
  CryptoJS.enc.Base64.stringify(_toWords(_fromIn(input)))

export const base58Decode = (input: TBase58): TBytes =>
  base58.decode(input)

export const base58Encode = (input: TBinaryIn): TBase58 =>
  base58.encode(_fromIn(input))

export const base16Decode = (input: TBase16): TBytes =>
  _fromWords(CryptoJS.enc.Hex.parse(input))

export const base16Encode = (input: TBinaryIn): TBase16 =>
  CryptoJS.enc.Hex.stringify(_toWords(_fromIn(input)))
