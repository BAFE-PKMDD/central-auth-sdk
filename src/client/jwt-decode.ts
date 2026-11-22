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
    const parts = token.split('.')
    if (parts.length !== 3 || !parts[1]) return null

    // Convert base64url to standard base64 with proper padding
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=')

    // Decode UTF-8 safely across browser and Node/Bun runtimes
    const binary = atob(padded)
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0))
    const json = new TextDecoder().decode(bytes)
    const parsed = JSON.parse(json)
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null
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
