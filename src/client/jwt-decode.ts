import { DEFAULT_TTL_FALLBACK_SECONDS } from '../constants'

/**
 * Decode a JWT payload without cryptographic verification.
 *
 * **Client-side display only** — actual verification must happen
 * on the server via JWKS using `verifyAccessToken()`.
 *
 * @param token - Raw JWT string
 * @returns Decoded payload object, or `null` if decoding fails
 */
export function decodeToken(token: string): Record<string, unknown> | null {
  try {
    const payload = token.split('.')[1]
    return JSON.parse(atob(payload))
  } catch {
    return null
  }
}

/**
 * Get the remaining time-to-live (in seconds) for a JWT.
 *
 * @param token - Raw JWT string
 * @returns Seconds until expiry, or `DEFAULT_TTL_FALLBACK_SECONDS` if no `exp` claim
 */
export function getTokenTtl(token: string): number {
  const decoded = decodeToken(token)
  if (!decoded?.exp) return DEFAULT_TTL_FALLBACK_SECONDS
  const exp = decoded.exp as number
  return Math.max(0, exp - Math.floor(Date.now() / 1000))
}
