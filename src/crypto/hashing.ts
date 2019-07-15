import { TBinaryIn, TBytes } from './interface'
import { _fromIn } from '../conversions/param'
import { keccak256 } from '../libs/sha3'
import * as forge from 'node-forge'
import * as blake from '../libs/blake2b'
import { binaryStringToBytes, bytesToBinaryString } from '../conversions/string-bytes'

export const _hashChain = (input: TBinaryIn): TBytes =>
  _fromIn(keccak(blake2b(_fromIn(input))))

export const sha256 = (input: TBinaryIn): TBytes => {
  const md = forge.md.sha256.create()
  md.update(bytesToBinaryString(input))
  return binaryStringToBytes(md.digest().getBytes())
}

export const blake2b = (input: TBinaryIn): TBytes =>
  blake.blake2b(_fromIn(input), null, 32)

export const keccak = (input: TBinaryIn): TBytes =>
  _fromIn(keccak256.array(_fromIn(input)))

export const hmacSHA256 = (message: TBinaryIn, key: TBinaryIn): TBytes => {
  const hmac = forge.hmac.create()
  hmac.start('sha256', bytesToBinaryString(_fromIn(key)))
  hmac.update(bytesToBinaryString(_fromIn(message)))
  return binaryStringToBytes(hmac.digest().getBytes())
}
