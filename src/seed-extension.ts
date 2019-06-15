import { TSeed, IBinarySeed } from './interface'
import { _fromRawIn } from './conversions/param'
import { bytesToString } from './conversions/string-bytes'

export const Seed = {
  isSeedWithNonce: (val: TSeed): val is IBinarySeed =>
    (<IBinarySeed>val).nonce !== undefined,
  toBinary: (seed: TSeed): IBinarySeed =>
    Seed.isSeedWithNonce(seed) ?
      { seed: Seed.toBinary(seed.seed).seed, nonce: seed.nonce } :
      { seed: _fromRawIn(seed), nonce: undefined },
  toString: (seed: TSeed): string =>
    bytesToString(Seed.toBinary(seed).seed),
}