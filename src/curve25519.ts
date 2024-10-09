// curve25519.ts

import {
  crypto_box_keypair,
  crypto_box_seal,
  crypto_box_seal_open,
  from_base64,
  sodiumReady,
  to_base64,
} from './lib'

export type KeyPairResult = {
  public: Uint8Array
  private: Uint8Array
}

// Generate a Curve25519 key pair
export async function createCurve25519(): Promise<{ error: string | null, result: KeyPairResult | null }> {
  await sodiumReady
  // 1. Generate ECC key pair
  const curve25519KeyPair = crypto_box_keypair()

  // 2. Generate JWKS
  if (curve25519KeyPair.publicKey && curve25519KeyPair.privateKey) {
    return {
      error: null,
      result: {
        private: curve25519KeyPair.privateKey,
        public: curve25519KeyPair.publicKey,
      },
    }
  }

  return { error: 'key pair undefined', result: null }
}

// Encrypt content using a public key
export async function encryptWithPublicKey(publicKey: Uint8Array, content: string): Promise<string> {
  await sodiumReady
  // Convert the content to Uint8Array
  const contentBytes = new TextEncoder().encode(content)

  // Encrypt the content using the recipient's public key
  const encryptedContent = crypto_box_seal(contentBytes, publicKey)

  // Return the encrypted content as a base64 string
  return to_base64(encryptedContent)
}

// Decrypt content using a private key
export async function decryptWithPrivateKey(privateKey: Uint8Array, publicKey: Uint8Array, encryptedContent: string): Promise<string | null> {
  await sodiumReady
  // Convert the encrypted content from base64 to Uint8Array
  const encryptedBytes = from_base64(encryptedContent)

  // Decrypt the content using the recipient's private key and the sender's public key
  const decryptedContent = crypto_box_seal_open(encryptedBytes, publicKey, privateKey)

  // Return the decrypted content as a string if decryption is successful, otherwise return null
  if (decryptedContent) {
    return new TextDecoder().decode(decryptedContent)
  }

  return null
}