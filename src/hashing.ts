import { TBinaryIn, TBytes } from '.'
import { _toWords, _fromIn, _fromWords } from './conversions/param'
import { keccak256 } from './libs/sha3'
import * as CryptoJS from 'crypto-js'
import * as blake from './libs/blake2b'

export const _hashChain = (input: TBinaryIn): TBytes =>
  _fromIn(keccak(blake2b(_fromIn(input))))

export const sha256 = (input: TBinaryIn): TBytes =>
  _fromWords(CryptoJS.SHA256(_toWords(_fromIn(input))))

export const blake2b = (input: TBinaryIn): TBytes =>
  blake.blake2b(_fromIn(input), null, 32)

export const keccak = (input: TBinaryIn): TBytes =>
  _fromIn(keccak256.array(_fromIn(input)))

export const hmacSHA256 = (message: TBinaryIn, key: TBinaryIn): TBytes =>
  _fromWords(CryptoJS.HmacSHA256(_toWords(_fromIn(message)), _toWords(_fromIn(key))))
