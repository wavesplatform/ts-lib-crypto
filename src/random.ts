
type RArray8 = 'Array8'
type RArray16 = 'Array16'
type RArray32 = 'Array32'
type RBuffer = 'Buffer'
type RUint8Array = 'Uint8Array'
type RUint16Array = 'Uint16Array'
type RUint32Array = 'Uint32Array'
type RandomOutput = RArray8 | RArray16 | RArray32 | RUint8Array | RUint16Array | RUint32Array | RBuffer
type _if<T, E, A, B> = T extends E ? A : B
type _switch<T, A1, B1, A2, B2, A3, B3, A4, B4, C> = _if<T, A1, B1, _if<T, A2, B2, _if<T, A3, B3, _if<T, A4, B4, C>>>>
type R<T> = _switch<T, RBuffer, Buffer, RUint8Array, Uint8Array, RUint16Array, Uint16Array, RUint32Array, Uint32Array, number[]>


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

export const secureRandom = <T extends RandomOutput>(count: number, type: T): R<T> => {
  switch (type) {
    case 'Array8':
      return Array.from(random(count)) as R<T>
    case 'Array16':
      return Array.from(secureRandom(count, 'Uint16Array')) as R<T>
    case 'Array32':
      return Array.from(secureRandom(count, 'Uint32Array')) as R<T>
    case 'Buffer':
      ensureBuffer()
      return Buffer.from(random(count)) as R<T>
    case 'Uint8Array':
      return random(count) as R<T>
    case 'Uint16Array':
      return new Uint16Array(count)
        .map(_ => random(2).reduce((a, b, i) => a | b << 8 * (1 - i), 0)) as R<T>
    case 'Uint32Array':
      return new Uint32Array(count)
        .map(_ => random(4).reduce((a, b, i) => a | b << 8 * (1 - i), 0)) as R<T>
    default:
      throw new Error(type + ' is unsupported.')
  }
}
