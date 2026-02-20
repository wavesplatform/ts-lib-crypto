// bls.ts
import {bls12_381} from '@noble/curves/bls12-381'
import {hkdf} from '@noble/hashes/hkdf'
import {sha256} from '@noble/hashes/sha2'
import {bytesToNumberBE} from '@noble/curves/utils'
import {TBinaryIn, TBLSKeyPair, TBytes} from './interface'
import {_fromIn} from '../conversions/param'

const DST = new TextEncoder().encode('BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_')
const BLS_KEYGEN_SALT_BASE = new TextEncoder().encode('BLS-SIG-KEYGEN-SALT-')
const CURVE_ORDER = BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001')
const bls = bls12_381.longSignatures

export function mkBlsSecretKey(seed: Uint8Array): Uint8Array {
    const ikm = new Uint8Array([...seed, 0])
    const info = new Uint8Array([0x00, 0x30]) // 48

    const okm = hkdf(sha256, ikm, BLS_KEYGEN_SALT_BASE, info, 48)
    const sk = bytesToNumberBE(okm) % CURVE_ORDER

    if (sk === 0n) throw new Error('Invalid zero private key')

    const out = new Uint8Array(32)
    let tmp = sk
    for (let i = 31; i >= 0; i--) {
        out[i] = Number(tmp & 0xffn)
        tmp >>= 8n
    }
    return out
}

function hashToPoint(message: Uint8Array) {
    return bls12_381.G2.hashToCurve(message, { DST })
}

export const blsPublicKey = (secretKey: TBinaryIn): TBytes => {
    return bls.getPublicKey(_fromIn(secretKey)).toBytes(true)
}

export const blsKeyPair = (seed: TBinaryIn): TBLSKeyPair => {
    const secretKey = mkBlsSecretKey(_fromIn(seed))
    const publicKey = blsPublicKey(secretKey)
    return { blsSecret: secretKey, blsPublic: publicKey }
}



export const blsSign = (
    secretKey: TBinaryIn,
    message: TBinaryIn
): TBytes => {
    const msgPoint = hashToPoint(_fromIn(message))

    return bls.sign(msgPoint, _fromIn(secretKey) ).toBytes(true)
}

export const blsVerify = (
    publicKey: TBinaryIn,
    message: TBinaryIn,
    signature: TBinaryIn
): boolean => {
    const msgPoint = hashToPoint(_fromIn(message))

    return bls.verify(
        _fromIn(signature),
        msgPoint,
        _fromIn(publicKey)
    )
}
