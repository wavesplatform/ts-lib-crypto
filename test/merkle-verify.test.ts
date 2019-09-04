import { base64Decode } from '../src/conversions/base-xx'
import { merkleVerify } from '../src/crypto/merkle-verify'

test('Verify merkle proof', () => {
  let rootHash = base64Decode('eh9fm3HeHZ3XA/UfMpC9HSwLVMyBLgkAJL0MIVBIoYk=')
  let leafData = base64Decode('AAAm+w==')
  let merkleProof = base64Decode('ACBSs2di6rY+9N3mrpQVRNZLGAdRX2WBD6XkrOXuhh42XwEgKhB3Aiij6jqLRuQhrwqv6e05kr89tyxkuFYwUuMCQB8AIKLhp/AFQkokTe/NMQnKFL5eTMvDlFejApmJxPY6Rp8XACAWrdgB8DwvPA8D04E9HgUjhKghAn5aqtZnuKcmpLHztQAgd2OG15WYz90r1WipgXwjdq9WhvMIAtvGlm6E3WYY12oAIJXPPVIdbwOTdUJvCgMI4iape2gvR55vsrO2OmJJtZUNASAya23YyBl+EpKytL9+7cPdkeMMWSjk0Bc0GNnqIisofQ==')

  let valid = merkleVerify(rootHash, merkleProof, leafData)

  expect(valid).toBe(true)
})



