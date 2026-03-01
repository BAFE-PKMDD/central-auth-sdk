import { createRemoteJWKSet } from 'jose'
import { JWKS_ENDPOINT_PATH } from '../constants'

/**
 * Create a JWKS (JSON Web Key Set) remote key set for verifying
 * Central Auth JWTs.
 *
 * Under the hood this uses `jose.createRemoteJWKSet` and points
 * to `{centralAuthUrl}/api/auth/jwks`.
 *
 * @param centralAuthUrl - Full URL of the Central Auth instance
 * @returns A JWKS key-fetching function usable with `jose.jwtVerify`
 *
 * @example
 * ```ts
 * import { createJWKS } from '@bafe-pkmdd/central-auth-sdk/server'
 * const jwks = createJWKS('https://auth.example.com')
 * ```
 */
export function createJWKS(centralAuthUrl: string) {
  return createRemoteJWKSet(
    new URL(`${centralAuthUrl}${JWKS_ENDPOINT_PATH}`),
  )
}
