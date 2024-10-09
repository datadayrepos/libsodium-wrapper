// argon2id.ts

import {
  crypto_pwhash,
  crypto_pwhash_ALG_ARGON2ID13,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  sodiumReady,
  to_base64,
} from './lib'

export type Argon2IDOptions = {
  memoryLimit?: number // Memory usage in bytes
  opsLimit?: number // Number of passes over the data
  salt?: Uint8Array // Optional salt
  outputLength?: number // Output length in bytes
}

/**
 * This module provides a utility function for creating Argon2ID hashes using the
 * `libsodium` library. Argon2ID is a secure password hashing algorithm that combines
 * the benefits of Argon2i and Argon2d, making it resistant to both side-channel and
 * GPU-based attacks. This implementation allows customization of hashing parameters,
 * including memory usage, the number of computational passes, salt, and output length.
 *
 * The function `createArgon2IDHash` returns a Base64-encoded hash of the input password,
 * using the specified options or default values. It is designed to be used in secure
 * password storage scenarios, where parameters are adjusted according to OWASP
 * recommendations for interactive applications.
 *
 * Parameters:
 * - `memoryLimit`: Maximum memory usage in bytes (default is `crypto_pwhash_MEMLIMIT_INTERACTIVE`).
 * - `opsLimit`: Number of computational passes over the password (default is `crypto_pwhash_OPSLIMIT_INTERACTIVE`).
 * - `salt`: Optional salt for the hashing process; if not provided, a random salt is generated.
 * - `outputLength`: Length of the generated hash in bytes (default is 32 bytes).
 *
 * Usage Example:
 *
 * ```typescript
 * import { createArgon2IDHash } from '@datadayrepos/libsodium-wrapper'
 *
 * const password = 'my-secure-password'
 * const options = {
 *   memoryLimit: 64 * 1024 * 1024, // 64 MB
 *   opsLimit: 1, // Number of passes
 * }
 * The p parameter (parallelism) is not directly available in the crypto_pwhash function.
 * Instead, crypto_pwhash implicitly handles the degree of parallelism with p set to 1.
 *
 * createArgon2IDHash(password, options)
 *   .then(({ error, result }) => {
 *     if (error) {
 *       console.error('Hashing failed:', error)
 *     } else {
 *       console.log('Generated hash:', result)
 *     }
 *   })
 * ```
 */
export async function createArgon2IDHash(password: string, options: Argon2IDOptions = {}): Promise<{ error: string | null, result: string | null }> {
  await sodiumReady

  const memoryLimit = options.memoryLimit || crypto_pwhash_MEMLIMIT_INTERACTIVE
  const opsLimit = options.opsLimit || crypto_pwhash_OPSLIMIT_INTERACTIVE
  const outputLength = options.outputLength || 32
  const salt = options?.salt || crypto.getRandomValues(new Uint8Array(16))

  try {
    const hash = crypto_pwhash(
      outputLength,
      password,
      salt,
      opsLimit,
      memoryLimit,
      crypto_pwhash_ALG_ARGON2ID13,
    )
    return { error: null, result: to_base64(hash) }
  }
  // eslint-disable-next-line unused-imports/no-unused-vars
  catch (e) {
    return { error: 'Failed to create Argon2ID hash', result: null }
  }
}
