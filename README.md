# libsodium-wrapper
Typescript wrapper around a subset of libsodium.js and WASM crypto funcs

## Usage

### Argon2ID Password Hashing with @datadayrepos/libsodium-wrapper

This library provides an implementation for hashing passwords using the Argon2ID algorithm through the `libsodium` library. Argon2ID is the recommended choice for secure password storage, as it balances between security and performance. This implementation allows developers to specify parameters such as memory usage, the number of computational passes, salt, and output length.

To create an Argon2ID hash, import the `createArgon2IDHash` function and use it with your desired parameters.

#### Argon Example Code

```typescript
import { createArgon2IDHash as _createArgon2IDHash } from '@datadayrepos/libsodium-wrapper'

const password = 'my-secure-password'
const options = {
  memoryLimit: 46 * 1024 * 1024, // Memory limit in bytes (46 MiB)
  opsLimit: 1, // Number of computational passes
  //  outputLength: 32, // Optional - defaults to 32 -Output length of the hash in bytes
  // salt:... // Uint8Array // Optional salt - default to random 16 unint array

  // NOTE P - paralellism aprameter is fixed to 1
}

export async function createArgon2IDHash(password, options) {
  const res = await _createArgon2IDHash(password, options)
  if (res.error)
    throw new Error('Failed to generate hash')
  return res.result
}
```

#### Argon Configuration Options

The hashing function accepts the following optional configuration options:

- **memoryLimit**: The maximum memory usage during the hashing process, in bytes. The default is set to `crypto_pwhash_MEMLIMIT_INTERACTIVE`, which is suitable for interactive applications.
- **opsLimit**: The number of computational passes over the password. The default is `crypto_pwhash_OPSLIMIT_INTERACTIVE`, which is recommended for interactive scenarios.
- **salt**: A `Uint8Array` providing a custom salt for the hashing process. If not provided, a random 16-byte salt is generated.
- **outputLength**: The length of the resulting hash, in bytes. The default is 32 bytes.

#### OWASP Recommendations

The following settings are based on OWASP recommendations for password storage:

- **Memory Limit**: At 46 MB for interactive applications. Higher count emphasizes memory.
- **Ops Limit**: Minimum 1 iterations for interactive use. Higher count emphasizes CPU.
- **Paralism**: 1

---

### ED25519 Key Pair and JWKS Generation with @datadayrepos/libsodium-wrapper

This library provides functionality for generating ED25519 key pairs and creating JSON Web Key Sets (JWKS) using the `libsodium` library. ED25519 is a high-security public-key signature system suitable for cryptographic signing operations, and JWKS is a standard format for representing public keys, used in scenarios like verifying JSON Web Tokens (JWTs).

To create an ED25519 key pair and generate a corresponding JWKS representation, import the functions provided and use them as demonstrated in the examples below.

Here’s the updated documentation reflecting the new, streamlined approach that removes unnecessary error handling within the functions:

---

### Creating Curve25519 Key Pairs using @datadayrepos/libsodium-wrapper

This library provides a function for generating Curve25519 key pairs suitable for encryption and decryption operations using elliptic curve cryptography. The keys can be used for secure communication and other cryptographic purposes.

#### Example Code for Creating a Curve25519 Key Pair

This example demonstrates how to generate a Curve25519 key pair using the library.

```typescript
import { createCurve25519 } from '@datadayrepos/libsodium-wrapper'

async function generateCurve25519KeyPair() {
  const keyPair = await createCurve25519()
  return keyPair // keyPair will contain both public and private keys
}
```

---

### Creating ED25519 JWKS Key Pairs using @datadayrepos/libsodium-wrapper

This library also provides functions for generating ED25519 key pairs and converting them into a JSON Web Key Set (JWKS) format, which can be used for signing and verifying purposes in applications such as JWT (JSON Web Token).

#### Example Code for Creating a JWKS Key Pair

This example demonstrates how to generate an ED25519 key pair and convert it into a JWKS-compatible format:

```typescript
import { createEd25519JwkPair } from '@datadayrepos/libsodium-wrapper'

async function generateJWKS() {
  const jwkPair = await createEd25519JwkPair()
  return jwkPair // jwkPair contains both public and private keys in JWKS format
}
```

---

### Creating and Signing JWTs with ED25519 Keys using @datadayrepos/libsodium-wrapper

This library provides a function for creating and signing JSON Web Tokens (JWTs) using ED25519 keys in the JWKS format. It includes validating the JWK, importing the private key, and signing the JWT with the provided header and body.

Used for some admin tools.

#### Example Code for Creating a Signed JWT

This example demonstrates how to create and sign a JWT using an ED25519 private JWK.

```typescript
import { createSignedJwt } from '@datadayrepos/libsodium-wrapper'

async function generateSignedJwt(privateJwk, header = {}, body = {}) {
  const jwtResult = await createSignedJwt(privateJwk, header, body)
  if (jwtResult.error)
    throw new Error('Failed to sign JWT')
  return jwtResult.result
}
```

#### Function Details

1. **`createSignedJwt(privateJwk: JWKSKey, header: Record<string, any>, body: Record<string, any>): Promise<{ error: string | null, result: string | null }>`**
   - This function creates and signs a JWT using an ED25519 private JWK.
   - **Parameters**:
     - `privateJwk`: The ED25519 private key in JWKS format, used to sign the JWT.
     - `header`: An optional object containing additional JWT header fields (e.g., `alg`, `typ`).
     - `body`: An optional object containing the JWT payload.
   - **Returns**:
     An object with:
     - `error`: A string containing an error message if the signing fails, or `null` if successful.
     - `result`: The signed JWT string if successful, or `null` if an error occurred.

---

### Encrypting Content with a Public Key using @datadayrepos/libsodium-wrapper

This library provides a function for encrypting content using a recipient's public key based on the Curve25519 elliptic curve cryptography. The function securely encrypts data, ensuring that only the owner of the corresponding private key can decrypt the message.

#### Example Code for Encrypting Content with a Public Key

This example demonstrates how to encrypt content using a recipient's public key.

```typescript
import { encryptWithPublicKey } from '@datadayrepos/libsodium-wrapper'

async function encryptMessage(publicKey: Uint8Array, content: string): Promise<string> {
  const encryptedResult = await encryptWithPublicKey(publicKey, content)
  return encryptedResult
}
```

#### Function Details

1. **`encryptWithPublicKey(publicKey: Uint8Array, content: string): Promise<string>`**
   - This function encrypts a given string using the recipient's public key.
   - **Parameters**:
     - `publicKey`: A `Uint8Array` representing the recipient's public key.
     - `content`: The string content to be encrypted.
   - **Returns**:
     A promise that resolves to a base64-encoded string representing the encrypted content.

---

### Decrypting Content with a Private Key using @datadayrepos/libsodium-wrapper

This library provides a function for decrypting content that was encrypted using elliptic curve cryptography with a recipient's public key. The function allows decryption using the recipient's private key and the sender's public key, enabling secure communication.

#### Example Code for Decrypting Content with a Private Key

This example demonstrates how to decrypt encrypted content using the recipient's private key and the sender's public key.

```typescript
import { decryptWithPrivateKey } from '@datadayrepos/libsodium-wrapper'

async function decryptMessage(privateKey: Uint8Array, publicKey: Uint8Array, encryptedContent: string): Promise<string | null> {
  const decryptedResult = await decryptWithPrivateKey(privateKey, publicKey, encryptedContent)
  return decryptedResult
}
```

#### Function Details

1. **`decryptWithPrivateKey(privateKey: Uint8Array, publicKey: Uint8Array, encryptedContent: string): Promise<string | null>`**
   - This function decrypts content that was encrypted with a public key.
   - **Parameters**:
     - `privateKey`: A `Uint8Array` representing the recipient's private key.
     - `publicKey`: A `Uint8Array` representing the sender's public key.
     - `encryptedContent`: The encrypted content as a base64-encoded string.
   - **Returns**:
     A promise that resolves to the decrypted content as a string if decryption is successful, or `null` if it fails

---

## Copyright and License

This project is licensed by Ivar Strand under the MIT License. See the [LICENSE](LICENSE) file for details.
