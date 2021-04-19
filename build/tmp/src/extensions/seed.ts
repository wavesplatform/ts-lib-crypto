import { TSeed, INonceSeed } from '../crypto/interface'
import { _fromRawIn } from '../conversions/param'
import { bytesToString } from '../conversions/string-bytes'

export const Seed = {
  isSeedWithNonce: (val: TSeed): val is INonceSeed =>
    (<INonceSeed>val).nonce !== undefined,
  toBinary: (seed: TSeed): INonceSeed =>
    Seed.isSeedWithNonce(seed) ?
      { seed: Seed.toBinary(seed.seed).seed, nonce: seed.nonce } :
      { seed: _fromRawIn(seed), nonce: undefined },
  toString: (seed: TSeed): string =>
    bytesToString(Seed.toBinary(seed).seed),
}