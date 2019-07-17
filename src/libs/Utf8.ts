let Utf8ArrayToStr = (function () {
  let charCache = new Array(128)  // Preallocate the cache for the common single byte chars
  let charFromCodePt = String.fromCodePoint || String.fromCharCode
  let result: any = []

  return function (array: number[] | Uint8Array) {
    let codePt, byte1
    let buffLen = array.length

    result.length = 0

    for (let i = 0; i < buffLen;) {
      byte1 = array[i++]

      if (byte1 <= 0x7F) {
        codePt = byte1
      } else if (byte1 <= 0xDF) {
        codePt = ((byte1 & 0x1F) << 6) | (array[i++] & 0x3F)
      } else if (byte1 <= 0xEF) {
        codePt = ((byte1 & 0x0F) << 12) | ((array[i++] & 0x3F) << 6) | (array[i++] & 0x3F)
      } else if (String.fromCodePoint) {
        codePt = ((byte1 & 0x07) << 18) | ((array[i++] & 0x3F) << 12) | ((array[i++] & 0x3F) << 6) | (array[i++] & 0x3F)
      } else {
        codePt = 63    // Cannot convertLongFields four byte code points, so use "?" instead
        i += 3
      }

      result.push(charCache[codePt] || (charCache[codePt] = charFromCodePt(codePt)))
    }

    return result.join('')
  }
})

export const utf8ArrayToStr = Utf8ArrayToStr()

export function strToUtf8Array(str: string) {
  let utf8 = []
  for (let i = 0; i < str.length; i++) {
    let charcode = str.charCodeAt(i)
    if (charcode < 0x80) utf8.push(charcode)
    else if (charcode < 0x800) {
      utf8.push(0xc0 | (charcode >> 6),
        0x80 | (charcode & 0x3f))
    }
    else if (charcode < 0xd800 || charcode >= 0xe000) {
      utf8.push(0xe0 | (charcode >> 12),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f))
    }
    // surrogate pair
    else {
      i++
      // UTF-16 encodes 0x10000-0x10FFFF by
      // subtracting 0x10000 and splitting the
      // 20 bits of 0x0-0xFFFFF into two halves
      charcode = 0x10000 + (((charcode & 0x3ff) << 10)
        | (str.charCodeAt(i) & 0x3ff))
      utf8.push(0xf0 | (charcode >> 18),
        0x80 | ((charcode >> 12) & 0x3f),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f))
    }
  }
  return Uint8Array.from(utf8)
}
