type Message = string | number[] | ArrayBuffer | Uint8Array

interface Hasher {
  /**
   * Update hash
   *
   * @param message The message you want to hash.
   */
  update(message: Message): Hasher

  /**
   * Return hash in hex string.
   */
  hex(): string

  /**
   * Return hash in hex string.
   */
  toString(): string

  /**
   * Return hash in ArrayBuffer.
   */
  arrayBuffer(): ArrayBuffer

  /**
   * Return hash in integer array.
   */
  digest(): number[]

  /**
   * Return hash in integer array.
   */
  array(): number[]
}

interface Hash {
  /**
   * Hash and return hex string.
   *
   * @param message The message you want to hash.
   */
  (message: Message): string

  /**
   * Hash and return hex string.
   *
   * @param message The message you want to hash.
   */
  hex(message: Message): string

  /**
   * Hash and return ArrayBuffer.
   *
   * @param message The message you want to hash.
   */
  arrayBuffer(message: Message): ArrayBuffer

  /**
   * Hash and return integer array.
   *
   * @param message The message you want to hash.
   */
  digest(message: Message): number[]

  /**
   * Hash and return integer array.
   *
   * @param message The message you want to hash.
   */
  array(message: Message): number[]

  /**
   * Create a hash object.
   */
  create(): Hasher

  /**
   * Create a hash object and hash message.
   *
   * @param message The message you want to hash.
   */
  update(message: Message): Hasher
}

interface ShakeHash {
  /**
   * Hash and return hex string.
   *
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   */
  (message: Message, outputBits: number): string

  /**
   * Hash and return hex string.
   *
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   */
  hex(message: Message, outputBits: number): string

  /**
   * Hash and return ArrayBuffer.
   *
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   */
  arrayBuffer(message: Message, outputBits: number): ArrayBuffer

  /**
   * Hash and return integer array.
   *
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   */
  digest(message: Message, outputBits: number): number[]

  /**
   * Hash and return integer array.
   *
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   */
  array(message: Message, outputBits: number): number[]

  /**
   * Create a hash object.
   *
   * @param outputBits The length of output.
   * @param outputBits The length of output.
   */
  create(outputBits: number): Hasher

  /**
   * Create a hash object and hash message.
   *
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   */
  update(message: Message, outputBits: number): Hasher
}

interface CshakeHash {
  /**
   * Hash and return hex string.
   *
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   * @param functionName The function name string.
   * @param customization The customization string.
   */
  (message: Message, outputBits: number, functionName: Message, customization: Message): string

  /**
   * Hash and return hex string.
   *
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   * @param functionName The function name string.
   * @param customization The customization string.
   */
  hex(message: Message, outputBits: number, functionName: Message, customization: Message): string

  /**
   * Hash and return ArrayBuffer.
   *
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   * @param functionName The function name string.
   * @param customization The customization string.
   */
  arrayBuffer(message: Message, outputBits: number, functionName: Message, customization: Message): ArrayBuffer

  /**
   * Hash and return integer array.
   *
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   * @param functionName The function name string.
   * @param customization The customization string.
   */
  digest(message: Message, outputBits: number, functionName: Message, customization: Message): number[]

  /**
   * Hash and return integer array.
   *
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   * @param functionName The function name string.
   * @param customization The customization string.
   */
  array(message: Message, outputBits: number, functionName: Message, customization: Message): number[]

  /**
   * Create a hash object.
   *
   * @param outputBits The length of output.
   * @param outputBits The length of output.
   */
  create(outputBits: number): Hasher

  /**
   * Create a hash object.
   *
   * @param outputBits The length of output.
   * @param functionName The function name string.
   * @param customization The customization string.
   */
  create(outputBits: number, functionName: Message, customization: Message): Hasher

  /**
   * Create a hash object and hash message.
   *
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   * @param functionName The function name string.
   * @param customization The customization string.
   */
  update(message: Message, outputBits: number, functionName: Message, customization: Message): Hasher
}

interface KmacHash {
  /**
   * Hash and return hex string.
   *
   * @param key The key string.
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   * @param customization The customization string.
   */
  (key: Message, message: Message, outputBits: number, customization: Message): string

  /**
   * Hash and return hex string.
   *
   * @param key The key string.
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   * @param customization The customization string.
   */
  hex(key: Message, message: Message, outputBits: number, customization: Message): string

  /**
   * Hash and return ArrayBuffer.
   *
   * @param key The key string.
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   * @param customization The customization string.
   */
  arrayBuffer(key: Message, message: Message, outputBits: number, customization: Message): ArrayBuffer

  /**
   * Hash and return integer array.
   *
   * @param key The key string.
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   * @param customization The customization string.
   */
  digest(key: Message, message: Message, outputBits: number, customization: Message): number[]

  /**
   * Hash and return integer array.
   *
   * @param key The key string.
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   * @param customization The customization string.
   */
  array(key: Message, message: Message, outputBits: number, customization: Message): number[]

  /**
   * Create a hash object.
   *
   * @param key The key string.
   * @param outputBits The length of output.
   * @param customization The customization string.
   */
  create(key: Message, outputBits: number, customization: Message): Hasher

  /**
   * Create a hash object and hash message.
   *
   * @param key The key string.
   * @param message The message you want to hash.
   * @param outputBits The length of output.
   * @param customization The customization string.
   */
  update(key: Message, message: Message, outputBits: number, customization: Message): Hasher
}

export const sha3_512: Hash
export const sha3_384: Hash
export const sha3_256: Hash
export const sha3_224: Hash
export const keccak_512: Hash
export const keccak_384: Hash
export const keccak_256: Hash
export const keccak_224: Hash
export const keccak512: Hash
export const keccak384: Hash
export const keccak256: Hash
export const keccak224: Hash
export const shake_128: ShakeHash
export const shake_256: ShakeHash
export const shake128: ShakeHash
export const shake256: ShakeHash
export const cshake_128: CshakeHash
export const cshake_256: CshakeHash
export const cshake128: CshakeHash
export const cshake256: CshakeHash
export const kmac_128: KmacHash
export const kmac_256: KmacHash
export const kmac128: KmacHash
export const kmac256: KmacHash