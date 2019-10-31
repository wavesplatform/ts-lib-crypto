// @ts-ignore
import * as pki from 'node-forge/lib/pki'
// @ts-ignore
import * as md from 'node-forge/lib/md'
// @ts-ignore
import * as md5 from 'node-forge/lib/md5'
// @ts-ignore
import * as util from 'node-forge/lib/util'
import { RSADigestAlgorithm, TBytes, TRSAKeyPair } from './interface'
import { base64Decode, base64Encode } from '../conversions/base-xx'
import { stringToBytes, bytesToString } from '../conversions/string-bytes'
import * as sha3 from 'js-sha3'

// HACK. Monkey patch node-forge library to provide oids for missing hash algorithms
pki.oids['sha224'] = '2.16.840.1.101.3.4.2.4'
pki.oids['2.16.840.1.101.3.4.2.4'] = 'sha224'

pki.oids['sha3-224'] = '2.16.840.1.101.3.4.2.7'
pki.oids['2.16.840.1.101.3.4.2.7'] = 'sha3-224'

pki.oids['sha3-256'] = '2.16.840.1.101.3.4.2.8'
pki.oids['2.16.840.1.101.3.4.2.8'] = 'sha3-256'

pki.oids['sha3-384'] = '2.16.840.1.101.3.4.2.9'
pki.oids['2.16.840.1.101.3.4.2.9'] = 'sha3-384'

pki.oids['sha3-512'] = '2.16.840.1.101.3.4.2.10'
pki.oids['2.16.840.1.101.3.4.2.10'] = 'sha3-512'


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

export const rsaKeyPair = async (bits?: number, e?: number): Promise<TRSAKeyPair> =>
  new Promise<TRSAKeyPair>((resolve, reject) => {
    pki.rsa.generateKeyPair(bits, e, function (err: any, kp: any) {
      if (err) reject(err)
      resolve({
        rsaPrivate: pemToBytes(pki.privateKeyToPem(kp.privateKey)),
        rsaPublic: pemToBytes(pki.publicKeyToPem(kp.publicKey)),
      })
    })
  })

const digestCreatorPlaceHolder: any = (type: string) => () => {
  throw new Error(`Digest ${type} is unsupported`)
}

class MessageDigestAdapter implements md.MessageDigest {
  constructor(private sha3Digest: sha3.Hasher, private algorithm: string){}

  static makeCreator(sha3Hash: sha3.Hash, algorithmName: string): { create(): md.MessageDigest } {
    return {create: () => new MessageDigestAdapter(sha3Hash.create(), algorithmName)}
  }

  public update(msg: string, encoding?: 'raw' | 'utf8'): md.MessageDigest {
    this.sha3Digest.update(stringToBytes(msg, encoding == null ? 'raw' : encoding))
    return this
  }

  public digest(): util.ByteStringBuffer{
    const bytes = Uint8Array.from(this.sha3Digest.digest())
    return util.createBuffer(bytesToString(bytes, 'raw'))
  }
}

const digestMap: Record<RSADigestAlgorithm, { create(): md.MessageDigest }> = {
  'MD5': md5,
  'SHA1': md.algorithms.sha1,
  'SHA224': digestCreatorPlaceHolder('SHA224'),
  'SHA256': md.algorithms.sha256,
  'SHA384': md.algorithms.sha384,
  'SHA512': md.algorithms.sha512,
  'SHA3-224': MessageDigestAdapter.makeCreator(sha3.sha3_224, 'sha3-224'),
  'SHA3-256': MessageDigestAdapter.makeCreator(sha3.sha3_256, 'sha3-256'),
  'SHA3-384': MessageDigestAdapter.makeCreator(sha3.sha3_384, 'sha3-384'),
  'SHA3-512': MessageDigestAdapter.makeCreator(sha3.sha3_512, 'sha3-512'),
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



