import { pki, md } from 'node-forge'
import { RSADigestAlgorithm, TBytes, TRSAKeyPair } from './interface'
import { base64Decode, base64Encode } from '../conversions/base-xx'
import { stringToBytes, bytesToString } from '../conversions/string-bytes'

export const pemToBytes = (pem: string) => base64Decode(
  pem.trim()
    .split(/\r\n|\n/)
    .slice(1, -1).join('')
    .trim()
)

const pemTypeMap = {
  rsaPrivateNonEncrypted: 'RSA PRIVATE KEY',
  rsaPublic: 'PUBLIC KEY',
}
export const bytesToPem = (bytes: Uint8Array, type: keyof typeof pemTypeMap) => {
  const header = `-----BEGIN ${pemTypeMap[type]}-----\n`
  const footer = `-----END ${pemTypeMap[type]}-----\n`

  let b64characters = base64Encode(bytes)
  if (b64characters.length % 64 !== 0) {
    b64characters += ' '.repeat(64 - b64characters.length % 64)
  }

  let result = header
  for (let i = 0; i < (b64characters.length / 64); i++) {
    result += b64characters.slice(i * 64, (i + 1) * 64) + '\n'
  }
  result += footer

  return result
}

export const rsaKeyPairSync = (bits?: number, e?: number): TRSAKeyPair => {
  const kp = pki.rsa.generateKeyPair(bits, e)
  return {
    rsaPrivate: pemToBytes(pki.privateKeyToPem(kp.privateKey)),
    rsaPublic: pemToBytes(pki.publicKeyToPem(kp.publicKey)),
  }
}

export const rsaKeyPair = async (bits?: number, e?: number): Promise<TRSAKeyPair> => {
  return new Promise<TRSAKeyPair>((resolve, reject) => {
    pki.rsa.generateKeyPair(bits, e, function (err, kp) {
      if (err) reject(err)
      resolve({
        rsaPrivate: pemToBytes(pki.privateKeyToPem(kp.privateKey)),
        rsaPublic: pemToBytes(pki.publicKeyToPem(kp.publicKey)),
      })
    })
  })
}

const digestCreatorPlaceHolder: any = (type: string) => () => {
  throw new Error(`Digest ${type} is unsupported`)
}
const digestMap: Record<RSADigestAlgorithm, { create(): md.MessageDigest }> = {
  'MD5': md.md5,
  'SHA1': md.sha1,
  'SHA224': digestCreatorPlaceHolder('SHA224'),
  'SHA256': md.sha256,
  'SHA384': md.sha384,
  'SHA512': md.sha512,
  'SHA3-224': digestCreatorPlaceHolder('SHA3-224'),
  'SHA3-256': digestCreatorPlaceHolder('SHA3-256'),
  'SHA3-384': digestCreatorPlaceHolder('SHA3-384'),
  'SHA3-512': digestCreatorPlaceHolder('SHA3-512'),
}

export const rsaSign = (rsaPrivateKey: TBytes, message: TBytes, digest: RSADigestAlgorithm = 'SHA256'): TBytes => {
  const s = bytesToPem(rsaPrivateKey, 'rsaPrivateNonEncrypted')
  const sk = pki.privateKeyFromPem(s) as pki.rsa.PrivateKey
  const _digest = digestMap[digest].create()
  _digest.update(bytesToString(message, 'raw'))
  return stringToBytes(sk.sign(_digest), 'raw')
}

export const rsaVerify = (rsaPublicKey: TBytes, message: TBytes, signature: TBytes, digest: RSADigestAlgorithm = 'SHA256'): boolean => {
  const pk = pki.publicKeyFromPem(bytesToPem(rsaPublicKey, 'rsaPublic')) as pki.rsa.PublicKey
  const _digest = digestMap[digest].create()
  _digest.update(bytesToString(message), 'raw')
  return pk.verify(_digest.digest().getBytes(), bytesToString(signature, 'raw'))
}
