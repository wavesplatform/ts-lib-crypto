import { sha256 } from '@waves/ts-lib-crypto'

const bytesArray = [117, 110, 99, 108, 101]
const bytesUint = Uint8Array.from([117, 110, 99, 108, 101])
const bytesBase58 = 'EFRr9cp'

sha256(bytesArray) // 4JPydqbhxhZF7kpuGA2tJWkXDmevJYfig45gqdV1UF9E
sha256(bytesUint) // 4JPydqbhxhZF7kpuGA2tJWkXDmevJYfig45gqdV1UF9E
sha256(bytesBase58) // 4JPydqbhxhZF7kpuGA2tJWkXDmevJYfig45gqdV1UF9E
