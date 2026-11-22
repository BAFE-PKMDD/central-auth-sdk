import { createRemoteJWKSet, type RemoteJWKSetOptions } from 'jose'
import { JWKS_ENDPOINT_PATH } from '../constants'

const DEFAULT_JWKS_OPTIONS: RemoteJWKSetOptions = {
  cacheMaxAge: 10 * 60 * 1000, // 10 minutes
  cooldownDuration: 30 * 1000, // 30 seconds
  timeoutDuration: 5 * 1000, // 5 seconds
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>()

/**
 * Create a JWKS (JSON Web Key Set) remote key set for verifying
 * Central Auth JWTs.
 *
 * Under the hood this uses `jose.createRemoteJWKSet` and points
 * to `{centralAuthUrl}/api/auth/jwks`.
 */
export function createJWKS(
  centralAuthUrl: string,
  options?: RemoteJWKSetOptions,
) {
  const normalizedUrl = centralAuthUrl.replace(/\/+$/, '')
  return createRemoteJWKSet(
    new URL(`${normalizedUrl}${JWKS_ENDPOINT_PATH}`),
    { ...DEFAULT_JWKS_OPTIONS, ...options },
  )
}

/**
 * Return a cached JWKS remote key set for the given Central Auth URL.
 * Prevents a live HTTP round-trip to `/api/auth/jwks` on every verification call
 * and preserves cached keys during brief IdP outages.
 */
export function getCachedJWKS(centralAuthUrl: string) {
  const normalizedUrl = centralAuthUrl.replace(/\/+$/, '')
  let jwks = jwksCache.get(normalizedUrl)
  if (!jwks) {
    jwks = createJWKS(normalizedUrl)
    jwksCache.set(normalizedUrl, jwks)
  }
  return jwks
}

/** Clear the module-level JWKS cache (useful in tests). */
export function clearJWKSCache(): void {
  jwksCache.clear()
}
