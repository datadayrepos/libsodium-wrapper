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

// Function to create an ED25519 key pair
async function createEd25519KeyPair(): Promise<{ error: string | null, publicKey: string | null, privateKey: string | null }> {
  await sodiumReady

  try {
    const keyPair = crypto_sign_keypair()
    return {
      error: null,
      privateKey: to_base64(keyPair.privateKey),
      publicKey: to_base64(keyPair.publicKey),
    }
  }
  // eslint-disable-next-line unused-imports/no-unused-vars
  catch (e) {
    return { error: 'Failed to create ED25519 key pair', privateKey: null, publicKey: null }
  }
}

export async function createEd25519JwkPair(): Promise<{ error: string | null, result: JWKSKeyPair | null }> {
  // 1. Generate ED25519 key pair
  const keyPair = await createEd25519KeyPair()
  if (keyPair.error)
    return { error: keyPair.error, result: null }
  // 3. Generate JWKS
  if (keyPair.publicKey && keyPair.privateKey) {
    const jwks = createEd25519JWKS(keyPair.publicKey, keyPair.privateKey)
    return { error: null, result: jwks }
  }

  return { error: 'key pir undefined', result: null }
}
