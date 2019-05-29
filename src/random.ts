
function nodeRandom(count: any, options: any) {
  const crypto = require('crypto')
  const buf = crypto.randomBytes(count)

  switch (options.type) {
    case 'Array':
      return [].slice.call(buf)
    case 'Buffer':
      return buf
    case 'Uint8Array':
      return Uint8Array.from(buf)
    default:
      throw new Error(options.type + ' is unsupported.')
  }
}

function browserRandom(count: any, options: any) {
  const nativeArr = new Uint8Array(count)
  const crypto = (global as any).crypto || (global as any).msCrypto
  crypto.getRandomValues(nativeArr)

  switch (options.type) {
    case 'Array':
      return [].slice.call(nativeArr)
    case 'Buffer':
      try {
        const b = new Buffer(1)
      } catch (e) {
        throw new Error('Buffer not supported in this environment. Use Node.js or Browserify for browser support.')
      }
      return new Buffer(nativeArr)
    case 'Uint8Array':
      return nativeArr
    default:
      throw new Error(options.type + ' is unsupported.')
  }
}

const isBrowser = typeof window !== 'undefined' && ({}).toString.call(window) === '[object Window]'
const isNode = typeof global !== 'undefined' && ({}).toString.call(global) === '[object global]'
const isJest = process.env.JEST_WORKER_ID !== undefined

export function secureRandom(count: any, options: any) {
  options = options || { type: 'Array' }

  if (isBrowser) {
    return browserRandom(count, options)
  } else if (isNode) {
    return nodeRandom(count, options)
  } else if (isJest) {
    return nodeRandom(count, options)
  } else {
    throw new Error('Your environment is not defined')
  }
}