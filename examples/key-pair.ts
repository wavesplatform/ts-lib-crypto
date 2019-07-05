
import { keyPair } from '@waves/ts-lib-crypto'

const seed = 'uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine'

keyPair(seed)
// => {
//      publicKey:  '4KxUVD9NtyRJjU3BCvPgJSttoJX7cb3DMdDTNucLN121',
//      privateKey: '6zFSymZAoaua3gtJPbAUwM584tRETdKYdEG9BeEnZaGW'
//    }
