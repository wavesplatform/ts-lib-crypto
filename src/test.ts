import { crypto, output } from './index'


const c = crypto({ output: output.Bytes })

const r = c.base58Decode('waves')

console.log(r)