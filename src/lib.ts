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
  crypto_sign_verify_detached,
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

// Function to encode base64url (used in JWT)
export function base64UrlEncode(input: ArrayBuffer | Uint8Array): string {
  const uint8Array = input instanceof Uint8Array ? input : new Uint8Array(input)

  // Convert Uint8Array to binary string in chunks to avoid stack overflow
  const chunkSize = 0x8000 // 32KB
  let binaryString = ''
  for (let i = 0; i < uint8Array.length; i += chunkSize) {
    const chunk = uint8Array.subarray(i, i + chunkSize)
    binaryString += String.fromCharCode.apply(null, Array.from(chunk))
  }

  // Encode binary string to base64
  const base64String = btoa(binaryString)

  // Convert base64 to base64url by replacing characters and removing padding
  const base64UrlString = base64String
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

  return base64UrlString
}

// Function to decode base64url (used in JWT)
export function base64UrlDecode(base64UrlString: string): Uint8Array {
  // Replace URL-safe characters and add padding if necessary
  let base64String = base64UrlString.replace(/-/g, '+').replace(/_/g, '/')
  const padding = base64String.length % 4
  if (padding > 0) {
    base64String += '='.repeat(4 - padding)
  }

  // Decode base64 string to binary string
  const binaryString = atob(base64String)

  // Convert binary string to Uint8Array
  const len = binaryString.length
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i)
  }

  return bytes
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
