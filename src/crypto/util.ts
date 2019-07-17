import { TBinaryIn, TPublicKey, TPrivateKey } from './interface'

export const isPublicKey = <T extends TBinaryIn>(val: any): val is TPublicKey<T> =>
  val.publicKey !== undefined

export const isPrivateKey = <T extends TBinaryIn>(val: any): val is TPrivateKey<T> =>
  val.privateKey !== undefined

