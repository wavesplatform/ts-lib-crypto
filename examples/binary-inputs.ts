import { address, randomSeed, sha256 } from '@waves/ts-lib-crypto'

const seed = randomSeed() // uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine
const addressBase58 = address(seed) // 3P9KR33QyXwfTXv8kKtNGZYtgKk3RXSUk36
sha256(addressBase58) // DMPenguwWdLdZ7tesiZY6grw7mjKU2Dob1cn9Uq9TKfp
