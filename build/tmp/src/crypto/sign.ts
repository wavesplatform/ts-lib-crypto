import { TSeed, TPrivateKey, TBinaryIn, TBytes } from './interface'
import axlsign from '../libs/axlsign'
import { _fromIn } from '../conversions/param'
import { isPrivateKey } from './util'
import { privateKey } from './address-keys-seed'
import { randomBytes } from './random'

export const signBytes = (seedOrPrivateKey: TSeed | TPrivateKey<TBinaryIn>, bytes: TBinaryIn, random?: TBinaryIn): TBytes =>
  axlsign.sign(_fromIn(isPrivateKey(seedOrPrivateKey)
    ? seedOrPrivateKey.privateKey
    : privateKey(seedOrPrivateKey)),
    _fromIn(bytes), _fromIn(random || randomBytes(64)))
