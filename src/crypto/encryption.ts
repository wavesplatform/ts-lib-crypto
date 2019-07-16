import * as forge from 'node-forge'
import { TBinaryIn, TRawStringIn, TBytes, AESMode } from './interface'
import { randomBytes } from './random'
import { _fromRawIn, _fromIn } from '../conversions/param'
import { hmacSHA256, sha256 } from './hashing'
import { concat, split } from './concat-split'
import axlsign from '../libs/axlsign'
import { binaryStringToBytes, bytesToBinaryString, stringToBytes } from '../conversions/string-bytes'

export const aesEncrypt = (data: TBinaryIn, key: TBinaryIn, mode: AESMode = 'CBC', iv?: TBinaryIn): TBytes => {
  const cipher = forge.cipher.createCipher(`AES-${mode}` as any, bytesToBinaryString(_fromIn(key)))
  cipher.start({iv: iv && forge.util.createBuffer(bytesToBinaryString(_fromIn(iv)))})
  cipher.update(forge.util.createBuffer(bytesToBinaryString(data)))
  cipher.finish()
  return binaryStringToBytes(cipher.output.getBytes())
}

export const aesDecrypt = (encryptedData: TBinaryIn, key: TBinaryIn, mode: AESMode = 'CBC', iv?: TBinaryIn): TBytes => {
  const decipher = forge.cipher.createDecipher(`AES-${mode}` as any, bytesToBinaryString(_fromIn(key)))
  decipher.start({iv: iv && forge.util.createBuffer(bytesToBinaryString(_fromIn(iv)))})
  const encbuf = forge.util.createBuffer(bytesToBinaryString(_fromIn(encryptedData)))
  decipher.update(encbuf)
  if (!decipher.finish()){
     throw new Error('Failed to decrypt data with provided key')
  }
  return binaryStringToBytes(decipher.output.getBytes())
}

export const messageEncrypt = (sharedKey: TBinaryIn, message: string): TBytes => {
  const CEK = randomBytes(32)
  const IV = randomBytes(16)
  const m = stringToBytes(message)

  const Cc = aesEncrypt(m, CEK, 'CTR', IV)
  const Ccek = aesEncrypt(CEK, sharedKey, 'ECB')
  const Mhmac = hmacSHA256(m, CEK)
  const CEKhmac = hmacSHA256(concat(CEK, IV), sharedKey)

  const packageBytes = concat(
    Ccek,
    CEKhmac,
    Mhmac,
    IV,
    Cc
  )

  return packageBytes
}

export const messageDecrypt = (sharedKey: TBinaryIn, encryptedMessage: TBinaryIn): string => {

  const [
    Ccek,
    _CEKhmac,
    _Mhmac,
    iv,
    Cc,
  ] = split(encryptedMessage, 48, 32, 32, 16)

  const CEK = aesDecrypt(Ccek, sharedKey, 'ECB')

  const CEKhmac = _fromIn(hmacSHA256(concat(CEK, iv), _fromIn(sharedKey)))

  const isValidKey = CEKhmac.every((v: number, i: number) => v === _CEKhmac[i])
  if (!isValidKey)
    throw new Error('Invalid key')

  const M = aesDecrypt(Cc, CEK, 'CTR', iv)
  const Mhmac = _fromIn(hmacSHA256(M, CEK))

  const isValidMessage = Mhmac.every((v: number, i: number) => v === _Mhmac[i])
  if (!isValidMessage)
    throw new Error('Invalid message')

  return String.fromCharCode.apply(null, Array.from(M))
}

export const sharedKey = (privateKeyFrom: TBinaryIn, publicKeyTo: TBinaryIn, prefix: TRawStringIn): TBytes => {
  const sharedKey = axlsign.sharedKey(_fromIn(privateKeyFrom), _fromIn(publicKeyTo))
  const prefixHash = sha256(_fromRawIn(prefix))
  return hmacSHA256(sharedKey, prefixHash)
}
