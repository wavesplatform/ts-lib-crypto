import { TBytes } from './interface'

import { seedWordsList } from './seed-words-list'

type TTypesMap = {
  Array8: number[]
  Array16: number[]
  Array32: number[]
  Buffer: Buffer
  Uint8Array: Uint8Array
  Uint16Array: Uint16Array
  Uint32Array: Uint32Array
}

const random = (count: number) => {
  if (isBrowser) {
    const arr = new Uint8Array(count)
    const crypto = ((global as any).crypto || (global as any).msCrypto)
    crypto.getRandomValues(arr)
    return arr
  }

  const crypto = require('crypto')
  return Uint8Array.from(crypto.randomBytes(count))
}

const ensureBuffer = () => {
  try { const b = new Buffer(1) } catch (e) {
    throw new Error('Buffer not supported in this environment. Use Node.js or Browserify for browser support.')
  }
}

const isBrowser = typeof window !== 'undefined' && ({}).toString.call(window) === '[object Window]'

export const secureRandom = <T extends keyof TTypesMap>(count: number, type: T): TTypesMap[T] => {
  switch (type) {
    case 'Array8':
      return Array.from(random(count)) as TTypesMap[T]
    case 'Array16':
      return Array.from(secureRandom(count, 'Uint16Array')) as TTypesMap[T]
    case 'Array32':
      return Array.from(secureRandom(count, 'Uint32Array')) as TTypesMap[T]
    case 'Buffer':
      ensureBuffer()
      return Buffer.from(random(count)) as TTypesMap[T]
    case 'Uint8Array':
      return random(count) as TTypesMap[T]
    case 'Uint16Array':
      return new Uint16Array(count)
        .map(_ => random(2).reduce((a, b, i) => a | b << 8 * (1 - i), 0)) as TTypesMap[T]
    case 'Uint32Array':
      return new Uint32Array(count)
        .map(_ => random(4).reduce((a, b, i) => a | b << 8 * (1 - i), 0)) as TTypesMap[T]
    default:
      throw new Error(type + ' is unsupported.')
  }
}

export const randomBytes = (length: number): TBytes =>
  secureRandom(length, 'Uint8Array')

export const randomSeed = (wordsCount: number = 15): string =>
  secureRandom(wordsCount, 'Array32')
    .map(x => seedWordsList[x % seedWordsList.length])
    .join(' ')

