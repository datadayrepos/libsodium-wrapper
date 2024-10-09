// These are just wrappers over Web Crypto API

// Encrypts text using AES-GCM
export async function encryptWithAESGCM(text: string, derivedKey: CryptoKey): Promise<string> {
  // Encode the text to a Uint8Array
  const encodedText = new TextEncoder().encode(text)

  // Create a random IV (Initialization Vector)
  const iv = window.crypto.getRandomValues(new Uint8Array(12)) // 12 bytes for AES-GCM

  // Encrypt the encoded text
  const encryptedData = await window.crypto.subtle.encrypt(
    {
      iv,
      name: 'AES-GCM',
    },
    derivedKey,
    encodedText,
  )

  // Convert the encrypted data to a base64-encoded string
  const uintArray = new Uint8Array(encryptedData)
  const base64Data = btoa(String.fromCharCode(...uintArray))

  // Return the encrypted data as a JSON string including the base64 data and the IV
  return JSON.stringify({
    base64Data,
    initializationVector: Array.from(iv),
  })
}

// Decrypts a message using AES-GCM
export async function decryptWithAESGCM(messageJSON: string, derivedKey: CryptoKey): Promise<string | null> {
  try {
    // Parse the JSON message
    const message = JSON.parse(messageJSON)
    const base64Data = message.base64Data
    const initializationVector = new Uint8Array(message.initializationVector)

    // Decode the base64 data to a Uint8Array
    const encryptedBytes = Uint8Array.from(atob(base64Data), char => char.charCodeAt(0))

    // Decrypt the data
    const decryptedData = await window.crypto.subtle.decrypt(
      {
        iv: initializationVector,
        name: 'AES-GCM',
      },
      derivedKey,
      encryptedBytes,
    )

    // Decode the decrypted data to a string
    return new TextDecoder().decode(decryptedData)
  }
  catch (e) {
    return `Error decrypting message: ${(e as Error).message}`
  }
}

/**
 * Generates a cryptographically secure random 32-byte value and returns it as a base64 encoded string.
 *
 * This method uses Web Crypto API in browsers or Node.js crypto module to provide robust security.
 * It is suitable for generating keys or tokens that require high levels of randomness and security.
 *
 * @returns {Promise<{ error: string | null, result: string | null }>} An object with an error message if any, and the base64 encoded random string.
 */
export async function generateSecureRandomBase64(): Promise<{ error: string | null, result: string | null }> {
  if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
    const randomBytes = new Uint8Array(32)
    window.crypto.getRandomValues(randomBytes)
    const base64String = btoa(String.fromCharCode(...randomBytes))
    return { error: null, result: base64String }
  }

  /*
    // Node.js crypto module for generating the base64-encoded random string
    else if (typeof require !== 'undefined') {
      const { randomBytes } = await import('crypto')
      const base64String = randomBytes(32).toString('base64')
      return { error: null, result: base64String }
    }
    */

  return { error: 'Secure random generation is not supported in this environment', result: null }
}
