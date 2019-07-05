import { blake2b } from '@waves/ts-lib-crypto'

const bytesArray = [117, 110, 99, 108, 101]
const bytesUint = Uint8Array.from([117, 110, 99, 108, 101])
const bytesBase58 = 'EFRr9cp'

blake2b(bytesArray)  // 9DqBU9wZAR85PyrUSJpwaU9DggM8veyMxRMvFe1q6atu
blake2b(bytesUint)   // 9DqBU9wZAR85PyrUSJpwaU9DggM8veyMxRMvFe1q6atu
blake2b(bytesBase58) // 9DqBU9wZAR85PyrUSJpwaU9DggM8veyMxRMvFe1q6atu
