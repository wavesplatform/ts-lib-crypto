import { TBase64 } from './interface'
import { bytesToString, stringToBytes } from '../conversions/string-bytes'
// @ts-ignore
import * as forgeMd5 from 'node-forge/lib/md5'
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
  const passPlusSalt = bytesToString(concat(passphrase, salt), 'raw')
  let key = ''
  let final_key = key
  while (final_key.length < output){
    key = forgeMd5.create().update(key + passPlusSalt).digest().getBytes()
    final_key += key
  }
  return final_key
}

/**
 * Encrypts arbitrary utf8 string with utf8 password. Evp key deriving function is used to get encryption key and IV from
 * password. AES-CBC algorithm is used for encryption. Output format is base64 encoded OpenSSL
 * @param seed - utf8 string to encrypt
 * @param password - utf8 password
 * @param encryptionRounds - how many times password will be hashed. Default = 5000
 */
export const encryptSeed = (seed: string, password: string,  encryptionRounds?: number): TBase64 => {
  const passphrase = strengthenPassword(password, encryptionRounds)
  const salt = randomBytes(8)
  const key_iv = evpKdf(stringToBytes(passphrase, 'raw'), salt)
  const key = stringToBytes(key_iv.slice(0, 32), 'raw')
  const iv = stringToBytes(key_iv.slice(32), 'raw')
  const encrypted = aesEncrypt(stringToBytes(seed), key, 'CBC', iv)
  return base64Encode(concat(stringToBytes('Salted__'), salt, encrypted))
}

export const decryptSeed = (encryptedSeed: TBase64, password: string, encryptionRounds?: number): string => {
  const passphrase = strengthenPassword(password, encryptionRounds)
  const encBytes = base64Decode(encryptedSeed)
  const salt = encBytes.slice(8, 16)
  const key_iv = evpKdf(stringToBytes(passphrase, 'raw'), salt)
  const key = stringToBytes(key_iv.slice(0, 32), 'raw')
  const iv = stringToBytes(key_iv.slice(32), 'raw')
  return bytesToString(aesDecrypt(encBytes.slice(16), key, 'CBC', iv))
}

