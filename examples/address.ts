import { address, TEST_NET_CHAIN_ID } from '@waves/ts-lib-crypto'

const seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
address(seed) // 3P9KR33QyXwfTXv8kKtNGZYtgKk3RXSUk36
address(seed, 'T') // 3MwJc5iX7QQGq5ciVFdNK7B5KSEGbUCVxDw
address(seed, TEST_NET_CHAIN_ID) // 3MwJc5iX7QQGq5ciVFdNK7B5KSEGbUCVxDw
