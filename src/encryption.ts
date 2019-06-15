import { TBinaryIn, TRawStringIn, TBytes, AESMode } from './interface'
import { randomBytes } from 'crypto'
import { _fromRawIn, _fromIn, _toWords, _fromWords } from './conversions/param'
import { hmacSHA256, sha256 } from './hashing'
import { concat, split } from './concat-split'
import axlsign from './libs/axlsign'
import { base64Decode, base64Encode } from './conversions/base-xx'
import CryptoJS = require('crypto-js')
import { bytesToString } from './conversions/string-bytes'


const aesModeMap: Record<AESMode, CryptoJS.Mode> = {
  'CBC': CryptoJS.mode.CBC,
  'CFB': CryptoJS.mode.CFB,
  'CTR': CryptoJS.mode.CTR,
  'OFB': CryptoJS.mode.OFB,
  'ECB': CryptoJS.mode.ECB,
}

export const aesEncrypt = (data: TRawStringIn, secret: TRawStringIn, mode: AESMode = 'CBC', iv?: TBinaryIn): TBytes =>
  base64Decode(
    CryptoJS.AES.encrypt(_toWords(_fromRawIn(data)), bytesToString(_fromRawIn(secret)),
      {
        iv: iv ? _toWords(_fromIn(iv)) : undefined,
        mode: aesModeMap[mode],
      })
      .toString()
  )

export const aesDecrypt = (encryptedData: TBinaryIn, secret: TRawStringIn, mode: AESMode = 'CBC', iv?: TBinaryIn): TBytes =>
  _fromWords(
    CryptoJS.AES.decrypt(base64Encode(encryptedData), bytesToString(_fromRawIn(secret)),
      {
        iv: iv ? _toWords(_fromIn(iv)) : undefined,
        mode: aesModeMap[mode],
      })
  )

export const messageEncrypt = (sharedKey: TBinaryIn, message: TRawStringIn): TBytes => {
  const CEK = randomBytes(32)
  const IV = randomBytes(16)
  const m = _fromRawIn(message)

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
  ] = split(encryptedMessage, 64, 32, 32, 16)

  const CEK = aesDecrypt(Ccek, sharedKey, 'ECB')

  const CEKhmac = _fromIn(hmacSHA256(concat(CEK, iv), _fromIn(sharedKey)))

  const isValidKey = CEKhmac.every((v, i) => v === _CEKhmac[i])
  if (!isValidKey)
    throw new Error('Invalid key')

  const M = aesDecrypt(Cc, CEK, 'CTR', iv)
  const Mhmac = _fromIn(hmacSHA256(M, CEK))

  const isValidMessage = Mhmac.every((v, i) => v === _Mhmac[i])
  if (!isValidMessage)
    throw new Error('Invalid message')

  return String.fromCharCode.apply(null, Array.from(M))
}

export const sharedKey = (privateKeyFrom: TBinaryIn, publicKeyTo: TBinaryIn, prefix: TRawStringIn): TBytes => {
  const sharedKey = axlsign.sharedKey(_fromIn(privateKeyFrom), _fromIn(publicKeyTo))
  const prefixHash = sha256(_fromRawIn(prefix))
  return hmacSHA256(sharedKey, prefixHash)
}
