import { TBase64 } from './interface'
import { binaryStringToBytes, bytesToBinaryString, bytesToString, stringToBytes } from '../conversions/string-bytes'
import * as forge from 'node-forge'
import { concat } from './concat-split'
import { aesDecrypt, aesEncrypt } from './encryption'
import { base16Encode, base64Decode, base64Encode } from '../conversions/base-xx'
import { sha256 } from './hashing'
import { randomBytes } from './random'

function strengthenPassword(password: string, rounds: number = 5000): string {
  while (rounds--) {
    const bytes = stringToBytes(password)
    password = base16Encode(sha256(bytes))
  }
  return password
}


function evpKdf(passphrase: Uint8Array, salt: Uint8Array, output = 48){
  const passPlusSalt = bytesToBinaryString(concat(passphrase, salt))
  let key = ''
  let final_key = key
  while (final_key.length < output){
    key = forge.md.md5.create().update(key + passPlusSalt).digest().getBytes()
    final_key += key
  }
  return final_key
}

export const encryptSeed = (seed: string, password: string,  encryptionRounds?: number): TBase64 => {
  const passphrase = strengthenPassword(password, encryptionRounds)
  const salt = randomBytes(8)
  const key_iv = evpKdf(binaryStringToBytes(passphrase), salt)
  const key = binaryStringToBytes(key_iv.slice(0, 32))
  const iv = binaryStringToBytes(key_iv.slice(32))
  const encrypted = aesEncrypt(stringToBytes(seed), key, 'CBC', iv)
  return base64Encode(concat(stringToBytes('Salted__'), salt, encrypted))
}

export const decryptSeed = (encryptedSeed: TBase64, password: string, encryptionRounds?: number): string => {
  const passphrase = strengthenPassword(password, encryptionRounds)
  const encBytes = base64Decode(encryptedSeed)
  const salt = encBytes.slice(8, 16)
  const key_iv = evpKdf(binaryStringToBytes(passphrase), salt)
  const key = binaryStringToBytes(key_iv.slice(0, 32))
  const iv = binaryStringToBytes(key_iv.slice(32))
  return bytesToString(aesDecrypt(encBytes.slice(16), key, 'CBC', iv))
}

