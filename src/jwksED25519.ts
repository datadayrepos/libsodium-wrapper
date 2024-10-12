// jwks.ts

import type {
  JWKSKey,
} from './lib'

import {
  crypto_sign_keypair,
  sodiumReady,
  to_base64,
} from './lib'

export type JWKSKeyPair = {
  public: JWKSKey
  private: JWKSKey
}

// Function to create ED25519 JWKS from the key pair
function createEd25519JWKS(publicKey: string, privateKey: string): JWKSKeyPair {
  const jwkPair: JWKSKeyPair = {
    private: {
      alg: 'EdDSA',
      crv: 'Ed25519',
      d: privateKey,
      kid: '', // add in caller
      kty: 'OKP',
      use: 'sig',
      x: publicKey,
    },
    public: {
      alg: 'EdDSA',
      crv: 'Ed25519',
      kid: '', // add in caller
      kty: 'OKP',
      use: 'sig',
      x: publicKey,
    },
  }

  return jwkPair
}

export async function createEd25519KeyPair(): Promise<{ publicKey: string, privateKey: string }> {
  // Ensure sodium is ready
  await sodiumReady

  // Generate Ed25519 key pair
  const keyPair = crypto_sign_keypair()

  // Return the public and private keys as base64
  return {
    privateKey: to_base64(keyPair.privateKey),
    publicKey: to_base64(keyPair.publicKey),
  }
}

export async function createEd25519JwkPair(): Promise<JWKSKeyPair> {
  // Generate Ed25519 key pair
  const keyPair = await createEd25519KeyPair()

  // Generate JWKS from the key pair
  return createEd25519JWKS(keyPair.publicKey, keyPair.privateKey)
}
