/**
 * Compute the SHA-256 hash of a refresh token using the Web Crypto API.
 *
 * This is used to match backchannel logout events — central auth sends
 * the stored hash, and the client computes it from its plaintext token
 * to determine if THIS session's token was revoked.
 *
 * @param token - The plaintext refresh token stored in localStorage
 * @returns Hex-encoded SHA-256 hash
 */
export async function hashRefreshToken(token: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(token)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}
