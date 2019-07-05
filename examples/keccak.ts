import { keccak } from '@waves/ts-lib-crypto'

const bytesArray = [117, 110, 99, 108, 101]
const bytesUint = Uint8Array.from([117, 110, 99, 108, 101])
const bytesBase58 = 'EFRr9cp'

keccak(bytesArray) // 5cqz9N2PPjDkSBSwga8AttKzQEHfn8aQ95rcZZmabLA7
keccak(bytesUint) // 5cqz9N2PPjDkSBSwga8AttKzQEHfn8aQ95rcZZmabLA7
keccak(bytesBase58) // 5cqz9N2PPjDkSBSwga8AttKzQEHfn8aQ95rcZZmabLA7
