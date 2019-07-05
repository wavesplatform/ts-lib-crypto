import { signBytes, privateKey } from '@waves/ts-lib-crypto'

const bytes = 'Fk1sjwdPSwZ4bPwvpCGPH6'
const seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'
const key = privateKey(seed)

signBytes({ privateKey: key }, bytes)