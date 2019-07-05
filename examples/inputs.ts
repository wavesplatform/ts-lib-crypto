import { address } from '@waves/ts-lib-crypto'
const seedString = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
const seedBytesAsArray = [117, 110, 99, 108, 101, 32, 112, 117, 115, 104, 32, 104, 117, 109, 97, 110, 32, 98, 117, 115, 32, 101, 99, 104, 111, 32, 100, 114, 97, 115, 116, 105, 99, 32, 103, 97, 114, 100, 101, 110, 32, 106, 111, 107, 101, 32, 115, 97, 110, 100, 32, 119, 97, 114, 102, 97, 114, 101, 32, 115, 101, 110, 116, 101, 110, 99, 101, 32, 102, 111, 115, 115, 105, 108, 32, 116, 105, 116, 108, 101, 32, 99, 111, 108, 111, 114, 32, 99, 111, 109, 98, 105, 110, 101]
const seedBytesAsUintArray = Uint8Array.from(seedBytesAsArray)
address(seedString) // 3P9KR33QyXwfTXv8kKtNGZYtgKk3RXSUk36
address(seedBytesAsArray) // 3P9KR33QyXwfTXv8kKtNGZYtgKk3RXSUk36
address(seedBytesAsUintArray) // 3P9KR33QyXwfTXv8kKtNGZYtgKk3RXSUk36