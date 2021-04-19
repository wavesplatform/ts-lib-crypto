// @ts-ignore
import * as forgeCipher from 'node-forge/lib/cipher'
// @ts-ignore
import * as util from 'node-forge/lib/util'
import { TBinaryIn, TRawStringIn, TBytes, AESMode } from './interface'
import { randomBytes } from './random'
import { _fromRawIn, _fromIn } from '../conversions/param'
import { hmacSHA256, sha256 } from './hashing'
import { concat, split } from './concat-split'
import axlsign from '../libs/axlsign'
import { stringToBytes, bytesToString } from '../conversions/string-bytes'

export const aesEncrypt = (data: TBinaryIn, key: TBinaryIn, mode: AESMode = 'CBC', iv?: TBinaryIn): TBytes => {
  const cipher = forgeCipher.createCipher(`AES-${mode}` as any, bytesToString(_fromIn(key), 'raw'))
  cipher.start({iv: iv && util.createBuffer(bytesToString(_fromIn(iv), 'raw'))})
  cipher.update(util.createBuffer(bytesToString(data, 'raw')))
  cipher.finish()
  return stringToBytes(cipher.output.getBytes(), 'raw')
}

export const aesDecrypt = (encryptedData: TBinaryIn, key: TBinaryIn, mode: AESMode = 'CBC', iv?: TBinaryIn): TBytes => {
  const decipher = forgeCipher.createDecipher(`AES-${mode}` as any, bytesToString(_fromIn(key), 'raw'))
  decipher.start({iv: iv && util.createBuffer(bytesToString(_fromIn(iv), 'raw'))})
  const encbuf = util.createBuffer(bytesToString(_fromIn(encryptedData), 'raw'))
  decipher.update(encbuf)
  if (!decipher.finish()) {
    throw new Error('Failed to decrypt data with provided key')
  }
  return stringToBytes(decipher.output.getBytes(), 'raw')
}

export const messageEncrypt = (sharedKey: TBinaryIn, message: string): TBytes => {
  const version = Uint8Array.from([1])
  const CEK = randomBytes(32)
  const IV = randomBytes(16)
  const m = stringToBytes(message)

  const Cc = aesEncrypt(m, CEK, 'CTR', IV)
  const Ccek = aesEncrypt(CEK, sharedKey, 'ECB')
  const Mhmac = hmacSHA256(m, CEK)
  const CEKhmac = hmacSHA256(concat(CEK, IV), sharedKey)

  const packageBytes = concat(
    version,
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
    version,
    Ccek,
    _CEKhmac,
    _Mhmac,
    iv,
    Cc,
  ] = split(encryptedMessage, 1, 48, 32, 32, 16)

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

  return bytesToString(M)
}

export const sharedKey = (privateKeyFrom: TBinaryIn, publicKeyTo: TBinaryIn, prefix: TRawStringIn): TBytes => {
  const sharedKey = axlsign.sharedKey(_fromIn(privateKeyFrom), _fromIn(publicKeyTo))
  const prefixHash = sha256(_fromRawIn(prefix))
  return hmacSHA256(sharedKey, prefixHash)
}
