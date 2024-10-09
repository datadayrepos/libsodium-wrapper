// lib.ts

// Importing only the necessary functions and types from 'libsodium-wrappers'
export {
  crypto_box_keypair,
  crypto_box_seal,
  crypto_box_seal_open,
  crypto_pwhash,
  crypto_pwhash_ALG_ARGON2ID13,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  crypto_sign_detached,
  crypto_sign_keypair,
  from_base64,
  ready as sodiumReady,
  to_base64,
} from 'libsodium-wrappers'

// Type exports from 'libsodium-wrappers' for type safety and clarity
export type {
  KeyPair,
  StringOutputFormat,
  Uint8ArrayOutputFormat,
} from 'libsodium-wrappers'

export type JWKSKey = {
  kty: string
  crv: string
  x: string
  d?: string
  alg: string
  use: string
  kid: string
}

// Function to encode base64url (used in JWT)
export function base64UrlEncode(input: ArrayBuffer | Uint8Array): string {
  const str = typeof input === 'string' ? input : String.fromCharCode(...new Uint8Array(input))
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

// Helper function to convert base64url to base64
export function base64UrlToBase64(base64url: string): string {
  // Replace '-' with '+' and '_' with '/'
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')

  // Add padding if necessary
  switch (base64.length % 4) {
    case 2: base64 += '=='; break
    case 3: base64 += '='; break
  }

  return base64
}
