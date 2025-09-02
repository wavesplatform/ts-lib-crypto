import * as forge from 'node-forge'
import { RSADigestAlgorithm, TBytes, TRSAKeyPair } from './interface'
import { base64Decode, base64Encode } from '../conversions/base-xx'
import * as sha3 from 'js-sha3'
import { sha224 } from 'js-sha256'

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
  const kp = forge.pki.rsa.generateKeyPair(bits, e)
  return {
    rsaPrivate: pemToBytes(forge.pki.privateKeyToPem(kp.privateKey)),
    rsaPublic: pemToBytes(forge.pki.publicKeyToPem(kp.publicKey)),
  }
}

export const rsaKeyPair = async (bits?: number, e?: number): Promise<TRSAKeyPair> =>
  new Promise<TRSAKeyPair>((resolve, reject) => {
    forge.pki.rsa.generateKeyPair(bits, e, function (err: any, kp: any) {
      if (err) reject(err)
      resolve({
        rsaPrivate: pemToBytes(forge.pki.privateKeyToPem(kp.privateKey)),
        rsaPublic: pemToBytes(forge.pki.publicKeyToPem(kp.publicKey)),
      })
    })
  })

interface DigestInfo {
  oid: string
  prefix: string // ASN.1 DER prefix
  hash: (bytes: string) => string
}

const DIGEST_INFOS: Record<RSADigestAlgorithm, DigestInfo> = {
  MD5: {
    oid: '1.2.840.113549.2.5',
    prefix: '3020300c06082a864886f70d020505000410',
    hash: (bytes) => forge.md.md5.create().update(bytes).digest().getBytes(),
  },
  SHA1: {
    oid: '1.3.14.3.2.26',
    prefix: '3021300906052b0e03021a05000414',
    hash: (bytes) => forge.md.sha1.create().update(bytes).digest().getBytes(),
  },
  SHA224: {
    oid: '2.16.840.1.101.3.4.2.4',
    prefix: '303d300d06096086480165030402040500041c',
    hash: (bytes) => forge.util.hexToBytes(sha224(bytes)),
  },
  SHA256: {
    oid: '2.16.840.1.101.3.4.2.1',
    prefix: '3031300d060960864801650304020105000420',
    hash: (bytes) => forge.md.sha256.create().update(bytes).digest().getBytes(),
  },
  SHA384: {
    oid: '2.16.840.1.101.3.4.2.2',
    prefix: '3041300d060960864801650304020205000430',
    hash: (bytes) => forge.md.sha384.create().update(bytes).digest().getBytes(),
  },
  SHA512: {
    oid: '2.16.840.1.101.3.4.2.3',
    prefix: '3051300d060960864801650304020305000440',
    hash: (bytes) => forge.md.sha512.create().update(bytes).digest().getBytes(),
  },
  'SHA3-224': {
    oid: '2.16.840.1.101.3.4.2.7',
    prefix: '302d300d06096086480165030402070500041c',
    hash: (bytes) => forge.util.hexToBytes(sha3.sha3_224(bytes)),
  },
  'SHA3-256': {
    oid: '2.16.840.1.101.3.4.2.8',
    prefix: '3031300d060960864801650304020805000420',
    hash: (bytes) => forge.util.hexToBytes(sha3.sha3_256(bytes)),
  },
  'SHA3-384': {
    oid: '2.16.840.1.101.3.4.2.9',
    prefix: '3041300d060960864801650304020905000430',
    hash: (bytes) => forge.util.hexToBytes(sha3.sha3_384(bytes)),
  },
  'SHA3-512': {
    oid: '2.16.840.1.101.3.4.2.10',
    prefix: '3051300d060960864801650304020a05000440',
    hash: (bytes) => forge.util.hexToBytes(sha3.sha3_512(bytes)),
  },
}

export const rsaVerify = (rsaPublicKey: TBytes, message: TBytes, signature: TBytes, digest: RSADigestAlgorithm = 'SHA256'): boolean => {
  const algo = DIGEST_INFOS[digest]
  if (!algo) throw new Error(`Unsupported digest: ${digest}`)

  const msgBytes = forge.util.binary.raw.encode(message)
  const sigBytes = forge.util.binary.raw.encode(signature)
  const pubDer = forge.util.binary.raw.encode(rsaPublicKey)

  const hash = algo.hash(msgBytes)
  const digestInfo = forge.util.hexToBytes(algo.prefix) + hash

  const asn1 = forge.asn1.fromDer(pubDer)
  const publicKey = forge.pki.publicKeyFromAsn1(asn1)

  const k = Math.ceil(publicKey.n.bitLength() / 8)
  const emBuf = forge.util.createBuffer(publicKey.encrypt(sigBytes, 'RAW'))
  if (emBuf.length() !== k) return false
  const em = emBuf.getBytes()

  // PKCS#1 v1.5 padding check: 0x00 0x01 FF..FF 0x00 DigestInfo
  if (em.charCodeAt(0) !== 0x00 || em.charCodeAt(1) !== 0x01) return false
  const psEnd = em.indexOf('\x00', 2)
  if (psEnd < 0) return false
  for (let i = 2; i < psEnd; i++) {
    if (em.charCodeAt(i) !== 0xff) return false
  }

  const recovered = em.substring(psEnd + 1)
  return recovered === digestInfo
}

export const rsaSign = (rsaPrivateKey: TBytes, message: TBytes, digest: RSADigestAlgorithm = 'SHA256'): TBytes => {
  const algo = DIGEST_INFOS[digest]
  if (!algo) throw new Error(`Unsupported digest: ${digest}`)

  const msgBytes = forge.util.binary.raw.encode(message)

  // Compute hash
  const hashBytes = algo.hash(msgBytes)

  // DigestInfo = prefix + hash
  const digestInfo = algo.prefix ? forge.util.hexToBytes(algo.prefix) + hashBytes : hashBytes

  // Load private key
  const derStr = forge.util.binary.raw.encode(rsaPrivateKey)
  const asn1 = forge.asn1.fromDer(derStr)
  const privateKey = forge.pki.privateKeyFromAsn1(asn1)

  // PKCS#1 v1.5 padding
  const k = Math.ceil(privateKey.n.bitLength() / 8)
  const tLen = digestInfo.length
  if (tLen > k - 11) throw new Error('Message too long for RSA key size')

  const PS = String.fromCharCode(...Array(k - tLen - 3).fill(0xff))
  const EM = '\x00\x01' + PS + '\x00' + digestInfo

  // RSA encrypt with private key
  const sigBytes = privateKey.decrypt(EM, 'RAW')
  return new Uint8Array(forge.util.binary.raw.decode(sigBytes))
}


