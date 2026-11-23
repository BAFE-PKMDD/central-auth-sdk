import type { OAuthPkceParams } from './types'

const encoder = new TextEncoder()

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = ''
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Constant-time string comparison using UTF-8 byte comparison.
 * Length differences still return false immediately (never treats unequal strings as equal).
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const aBytes = encoder.encode(a)
  const bBytes = encoder.encode(b)
  if (aBytes.length !== bBytes.length) {
    return false
  }
  let diff = 0
  for (let i = 0; i < aBytes.length; i += 1) {
    diff |= aBytes[i] ^ bBytes[i]
  }
  return diff === 0
}

/**
 * Generate cryptographically random CSRF state and PKCE S256 verifier/challenge pair
 * using Web Crypto (safe in Node, Bun, and Edge runtimes).
 */
export async function generateOAuthPkceParams(): Promise<OAuthPkceParams> {
  const stateBytes = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const verifierBytes = globalThis.crypto.getRandomValues(new Uint8Array(32))

  const state = bytesToBase64Url(stateBytes)
  const codeVerifier = bytesToBase64Url(verifierBytes)

  const digestBuffer = await globalThis.crypto.subtle.digest(
    'SHA-256',
    encoder.encode(codeVerifier),
  )
  const codeChallenge = bytesToBase64Url(new Uint8Array(digestBuffer))

  return { state, codeVerifier, codeChallenge }
}

/**
 * Compare OAuth state parameter against the stored cookie value in constant time.
 */
export function verifyOAuthState(
  receivedState: string | null | undefined,
  expectedState: string | undefined,
): boolean {
  if (!receivedState || !expectedState) {
    return false
  }
  return constantTimeEqual(receivedState, expectedState)
}

/**
 * Compute lowercase hex-encoded SHA-256 hash using Web Crypto.
 */
export async function sha256Hex(input: string): Promise<string> {
  const digestBuffer = await globalThis.crypto.subtle.digest(
    'SHA-256',
    encoder.encode(input),
  )
  return bytesToHex(new Uint8Array(digestBuffer))
}

/**
 * Compute lowercase hex-encoded HMAC-SHA256 signature using Web Crypto.
 */
export async function hmacSha256Hex(
  secret: string,
  message: string,
): Promise<string> {
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sigBuffer = await globalThis.crypto.subtle.sign(
    'HMAC',
    cryptoKey,
    encoder.encode(message),
  )
  return bytesToHex(new Uint8Array(sigBuffer))
}

/**
 * Verify a hex-encoded HMAC-SHA256 signature in constant time (case-insensitive hex).
 */
export async function verifyHmacSha256Hex(
  secret: string,
  message: string,
  signatureHex: string,
): Promise<boolean> {
  const expected = await hmacSha256Hex(secret, message)
  return constantTimeEqual(signatureHex.toLowerCase(), expected)
}
