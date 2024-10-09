// signEdJwt.ts
import type {
  JWKSKey,
} from './lib'

import {
  base64UrlEncode,
  base64UrlToBase64,
  crypto_sign_detached,
  sodiumReady,
} from './lib'

// Function to validate the JWK structure
function validateEd25519Jwk(jwk: any): void {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.d || !jwk.x) {
    throw new Error('Invalid JWK format for ED25519 private key.')
  }
}

// Function to convert JWK to Ed25519 private key
function importEd25519PrivateKey(jwk: JWKSKey): Uint8Array {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.d || !jwk.x) {
    throw new Error('Invalid JWK format for ED25519 private key.')
  }

  // Convert the base64url-encoded 'd' and 'x' values to base64
  const base64PrivateKey = base64UrlToBase64(jwk.d)
  const base64PublicKey = base64UrlToBase64(jwk.x)

  // Decode the base64 strings into Uint8Arrays
  const privateScalar = Uint8Array.from(atob(base64PrivateKey), c => c.charCodeAt(0))
  const publicKey = Uint8Array.from(atob(base64PublicKey), c => c.charCodeAt(0))

  // Combine the private scalar (32 bytes) and public key (32 bytes) to form a 64-byte private key
  const fullPrivateKey = new Uint8Array(64)
  fullPrivateKey.set(privateScalar)
  fullPrivateKey.set(publicKey, 32) // append public key starting at byte 32

  return fullPrivateKey
}

// Function to sign a JWT using ED25519
async function signJwt(header: object, body: object, privateKey: Uint8Array): Promise< string | null > {
  await sodiumReady

  try {
    const encoder = new TextEncoder()
    // Step 1: Encode the JWT parts (header and payload)
    const encodedHeader = base64UrlEncode(encoder.encode(JSON.stringify(header)))
    const encodedPayload = base64UrlEncode(encoder.encode(JSON.stringify(body)))

    // Step 2: Create the signing input (header.payload)
    const signingInput = `${encodedHeader}.${encodedPayload}`

    const signature = crypto_sign_detached(signingInput, privateKey)

    return `${signingInput}.${base64UrlEncode(signature)}`
  }
  catch (e) {
    const err = e as unknown as Error
    throw new Error(err.message)
  }
}

//  function to process the JWK and create a signed JWT
export async function createSignedJwt(privateJwk: JWKSKey, header: Record<string, any> = {}, body: Record<string, any> = {}): Promise<{ error: string | null, result: string | null }> {
  try {
    // Step 1: Validate the JWK
    validateEd25519Jwk(privateJwk)

    // Step 2: Import the JWK as a CryptoKey
    const privateKey = importEd25519PrivateKey(privateJwk)

    // Step 4: Sign the JWT
    const jwt = await signJwt(header, body, privateKey)

    // Step 5: Return both the JWT and the expiration (exp) field
    return { error: null, result: jwt }
  }
  catch (e) {
    const err = e as unknown as Error
    return { error: `Failed to sign JWT ${err.message}`, result: null }
  }
}
