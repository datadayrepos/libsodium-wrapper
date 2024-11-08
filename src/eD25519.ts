// eD25519.ts

import type { JWKSKeyPair } from './types'

import {
  base64UrlDecode,
  base64UrlEncode,
  base64UrlToBase64,
  crypto_sign_detached,
  crypto_sign_keypair,
  crypto_sign_verify_detached,
  sodiumReady,
  to_base64,
} from './lib'

// --------------------------------------------------------
//              Create keys
// --------------------------------------------------------

/** Function to create ED25519 JWKS from the key pair */
function createEd25519JWKS(publicKey: string, privateKey: string): JWKSKeyPair {
  const jwkPair: JWKSKeyPair = {
    privateKey: {
      alg: 'EdDSA',
      crv: 'Ed25519',
      d: privateKey,
      kty: 'OKP',
      use: 'sig',
      x: publicKey,
    },
    publicKey: {
      alg: 'EdDSA',
      crv: 'Ed25519',
      kty: 'OKP',
      use: 'sig',
      x: publicKey,
    },
  }

  return jwkPair
}

/**
 * Generates a Ed25519 key pair for signature.
 * Uses libsodium to create the keys and returns them as base64.
 */
async function createEd25519KeyPair(): Promise<{ publicKey: string, privateKey: string }> {
  // Ensure sodium is ready
  await sodiumReady

  // Generate Ed25519 key pair
  const ed25519keyPair = crypto_sign_keypair()

  // Return the public and private keys as base64
  return {
    privateKey: to_base64(ed25519keyPair.privateKey),
    publicKey: to_base64(ed25519keyPair.publicKey),
  }
}

/**
 * Generates an Ed25519 key pair for signature.
 * Returns it as a JWK (JSON Web Key Set) for both public and private keys.
 */
export async function createEd25519JwkPair(): Promise<JWKSKeyPair> {
  // Generate Ed25519 key pair
  const keyPair = await createEd25519KeyPair()

  // Generate JWKS from the key pair
  return createEd25519JWKS(keyPair.publicKey, keyPair.privateKey)
}

// --------------------------------------------------------
//              Signature create jwt
// --------------------------------------------------------

// Function to validate the JWK structure
function validateEd25519Jwk(jwk: any): void {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.d || !jwk.x) {
    throw new Error('Invalid JWK format for ED25519 private key.')
  }
}

// Function to convert JWK to Ed25519 private key
function importEd25519PrivateKey(jwk: JsonWebKey): Uint8Array {
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
export async function createSignedJwt(privateJwk: JsonWebKey, header: Record<string, any> = {}, body: Record<string, any> = {}): Promise<{ error: string | null, result: string | null }> {
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

// --------------------------------------------------------
//              Signature verify jwt
// --------------------------------------------------------

// Function to convert JWK to Ed25519 public key
function importEd25519PublicKey(jwk: JsonWebKey): Uint8Array {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x) {
    throw new Error('Invalid JWK format for ED25519 public key.')
  }

  // Convert the base64url-encoded 'x' value to base64
  const base64PublicKey = base64UrlToBase64(jwk.x)

  // Decode the base64 string into Uint8Array
  return Uint8Array.from(atob(base64PublicKey), c => c.charCodeAt(0))
}

// Function to verify the JWT signature using ED25519
async function verifyJwt(jwt: string, publicKey: Uint8Array): Promise<boolean> {
  await sodiumReady

  try {
    // Step 1: Split the JWT into its parts (header, payload, signature)
    const [encodedHeader, encodedPayload, encodedSignature] = jwt.split('.')

    if (!encodedHeader || !encodedPayload || !encodedSignature) {
      throw new Error('Invalid JWT format')
    }

    // Step 2: Recreate the signing input (header.payload)
    const signingInput = `${encodedHeader}.${encodedPayload}`

    // Step 3: Decode the signature from base64url to Uint8Array
    const signature = base64UrlDecode(encodedSignature)

    // Step 4: Verify the signature using the public key
    const isValid = crypto_sign_verify_detached(signature, signingInput, publicKey)

    return isValid
  }
  catch (e) {
    const err = e as unknown as Error
    throw new Error(`Failed to verify JWT: ${err.message}`)
  }
}

// Function to process the JWK and verify the JWT
export async function verifySignedJwt(jwt: string, publicJwk: JsonWebKey): Promise<{ error: string | null, isValid: boolean }> {
  try {
    // Step 1: Import the JWK as a CryptoKey
    const publicKey = importEd25519PublicKey(publicJwk)

    // Step 2: Verify the JWT
    const isValid = await verifyJwt(jwt, publicKey)

    // Step 3: Return the result of verification
    return { error: null, isValid }
  }
  catch (e) {
    const err = e as unknown as Error
    return { error: `Failed to verify JWT: ${err.message}`, isValid: false }
  }
}

// --------------------------------------------------------
//              Signature verify any
// --------------------------------------------------------
