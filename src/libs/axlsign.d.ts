declare const axlsign: {
  generateKeyPair: (seed: Uint8Array) => { public: Uint8Array, private: Uint8Array }
  verify: (publicKey: Uint8Array, bytes: Uint8Array, signature: Uint8Array) => boolean
  sign: (privateKey: Uint8Array, bytes: Uint8Array, random?: Uint8Array) => Uint8Array
  sharedKey: (keyA: Uint8Array, keyB: Uint8Array) => Uint8Array
}
export default axlsign
