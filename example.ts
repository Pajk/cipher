import { parseEncryptionKeys, createDecrypter, createEncrypter } from '.'
import secret from './secret'

const keys = parseEncryptionKeys(secret)

async function run() {
  // Set the 4th param to `keys.iv` (Initialization Vector) if you need 
  // the encrypted data to be always the same.
  const encrypt = await createEncrypter(keys.key, keys.salt, keys.rounds)
  const decrypt = createDecrypter(keys.key)
  const plain = "Secret data that I need to decrypt later, nothing like passwords."

  const encrypted1 = encrypt(plain)
  const encrypted2 = encrypt(plain)
  const decrypted1 = await decrypt(encrypted1)
  const decrypted2 = await decrypt(encrypted2)

  console.log('Plain:', plain)
  console.log('Encrypted #1:', encrypted1)
  console.log('Encrypted #2:', encrypted2)
  console.log('Decrypted #2:', decrypted1)
  console.log('Decrypted #2:', decrypted2)
}

run()
  .catch(err => console.error(`Error: ${err.message}`))
