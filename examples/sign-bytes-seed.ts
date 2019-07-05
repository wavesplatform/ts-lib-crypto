import { signBytes } from '@waves/ts-lib-crypto'

const bytes = [117, 110, 99, 108, 101]
const seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'

signBytes(seed, bytes) // 4qbwzQw7drkq4QiBwVuCscnDBooogsv69ZRr8RJF8CPmQVbKivgGQRr3dPjwWjHV9M98JRohaeG6RmyVH7d2u5de