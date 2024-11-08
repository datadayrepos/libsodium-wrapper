// curve25519.ts

import type { JWKSKeyPair } from './types'
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

/** Function to create curve25519 JWKS from the key pair */
function createCurve25519JWKS(publicKey: string, privateKey: string): JWKSKeyPair {
  const jwkPair: JWKSKeyPair = {
    privateKey: {
      alg: 'ECDH-ES', // Correct algorithm for X25519 encryption
      crv: 'X25519', // Correct curve for Curve25519 used in encryption
      d: privateKey,
      kty: 'OKP',
      use: 'enc', // Correct use for encryption
      x: publicKey,
    },
    publicKey: {
      alg: 'ECDH-ES', // Correct algorithm for X25519 encryption
      crv: 'X25519', // Correct curve for Curve25519 used in encryption
      kty: 'OKP',
      use: 'enc', // Correct use for encryption
      x: publicKey,
    },
  }

  return jwkPair
}

/**
 * Generates a Curve25519 key pair for encryption.
 * Uses libsodium to create the keys and returns them as base64.
 */
async function createCurve25519KeyPair(): Promise<{ publicKey: string, privateKey: string }> {
  // Ensure libsodium is ready
  await sodiumReady

  // Generate ECC key pair
  const curve25519KeyPair = crypto_box_keypair()

  // Return the key pair (public and private)
  return {
    privateKey: to_base64(curve25519KeyPair.privateKey),
    publicKey: to_base64(curve25519KeyPair.publicKey),
  }
}

/**
 * Generates a Curve 25519 key pair for encryption.
 * Returns it as a JWK (JSON Web Key Set) for both public and private keys.
 */
export async function createCurve25519JwkPair(): Promise<JWKSKeyPair> {
  // Generate Ed25519 key pair
  const keyPair = await createCurve25519KeyPair()

  // Generate JWKS from the key pair
  return createCurve25519JWKS(keyPair.publicKey, keyPair.privateKey)
}

/**
 * Encrypts string content using a Curve25519 public key. The content returned is base64 encoded, and the public key is passed as a JWK.
 */
export async function encryptWithCurve25519PublicKey(
  content: string,
  publicKeyJwk: JsonWebKey,
): Promise<string> {
  await sodiumReady

  // Ensure the public key (x) is defined
  if (!publicKeyJwk.x) {
    throw new Error('Public key (x) is undefined in the provided JWK')
  }

  // Convert the JWK public key to Uint8Array
  const publicKeyBase64 = publicKeyJwk.x // x is the public key in JWK format for Curve25519
  const publicKey = from_base64(publicKeyBase64)

  // Convert the content to Uint8Array
  const contentBytes = new TextEncoder().encode(content)

  // Encrypt the content using the recipient's public key
  const encryptedContent = crypto_box_seal(contentBytes, publicKey)

  // Return the encrypted content as a base64 string
  return to_base64(encryptedContent)
}

/**
 * Decrypts string base64 content using a Curve25519 private jwk key.
 * The input encryptedContent is presumed to be base64 encoded.
 */
export async function decryptWithCurve25519PrivateKey(
  encryptedContent: string,
  privateKeyJwk: JsonWebKey,
): Promise<string | null> {
  await sodiumReady

  // Ensure both the private key (d) and public key (x) are defined
  if (!privateKeyJwk.d) {
    throw new Error('Private key (d) is undefined in the provided JWK')
  }
  if (!privateKeyJwk.x) {
    throw new Error('Public key (x) is undefined in the provided JWK')
  }

  // Convert JWK keys to Uint8Array
  const privateKeyBase64 = privateKeyJwk.d // d is the private key in JWK format for Curve25519
  const publicKeyBase64 = privateKeyJwk.x // x is the public key in JWK format for Curve25519

  const privateKey = from_base64(privateKeyBase64)
  const publicKey = from_base64(publicKeyBase64)

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
