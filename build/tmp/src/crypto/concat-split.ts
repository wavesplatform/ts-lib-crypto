import { TBinaryIn, TBytes } from './interface'
import { _fromIn } from '../conversions/param'

export const concat = (...arrays: TBinaryIn[]): TBytes =>
  arrays.reduce<Uint8Array>((a, b) => Uint8Array.from([...a, ..._fromIn(b)]), new Uint8Array(0))

export const split = (binary: TBinaryIn, ...sizes: number[]): TBytes[] => {
  const { r, arr } = sizes.reduce<{ arr: TBytes, r: TBytes[] }>((a, s) => ({ arr: a.arr.slice(s), r: [...a.r, a.arr.slice(0, s)] }), { arr: _fromIn(binary), r: [] })
  return [...r, arr]
}