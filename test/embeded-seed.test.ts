import { crypto, output, MAIN_NET_CHAIN_ID } from '../src/index'


const seed = 'vast local exotic manage click stone boil analyst various truth swift decade cherry cram innocent'

const { address } = crypto({ seed, output: output.Base58 })

test('address from embeded seed', () => {
  expect(address()).toBe('3PPb7ZubjmRprx7772hWuRReMB5dwAz8Q26')
})
