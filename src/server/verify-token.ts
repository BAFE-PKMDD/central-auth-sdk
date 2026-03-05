import { jwtVerify } from 'jose'
import type { JWTPayload, VerifyTokenConfig, VerifyTokenResult } from '../types'
import { createJWKS } from './jwks'

/**
 * Extract the Bearer token from an Authorization header value.
 *
 * @param authHeader - The full `Authorization` header string
 * @returns The raw JWT string, or `null` if not a Bearer token
 *
 * @example
 * ```ts
 * const token = extractBearerToken(req.headers.authorization)
 * if (!token) return res.status(401).json({ error: 'Missing token' })
 * ```
 */
export function extractBearerToken(authHeader?: string | null): string | null {
  if (!authHeader?.startsWith('Bearer ')) return null
  return authHeader.slice(7)
}

/**
 * Verify a JWT access token against Central Auth's JWKS endpoint.
 *
 * Returns a discriminated union — check `result.success` to determine
 * whether verification succeeded or failed.
 *
 * @param token - Raw JWT string (without "Bearer " prefix)
 * @param config - Verification configuration
 * @returns `{ success: true, payload }` or `{ success: false, error, isExpired }`
 *
 * @example
 * ```ts
 * import { verifyAccessToken, extractBearerToken } from '@bafe-pkmdd/central-auth-sdk/server'
 *
 * const token = extractBearerToken(req.headers.authorization)
 * if (!token) return res.status(401).json({ error: 'Missing token' })
 *
 * const result = await verifyAccessToken(token, {
 *   centralAuthUrl: process.env.CENTRAL_AUTH_URL!,
 * })
 *
 * if (!result.success) {
 *   return res.status(401).json({ error: result.error })
 * }
 *
 * // result.payload is typed as JWTPayload
 * req.user = result.payload
 * ```
 */
export async function verifyAccessToken(
  token: string,
  config: VerifyTokenConfig,
): Promise<VerifyTokenResult> {
  const { centralAuthUrl } = config
  const jwks = config.jwks ?? createJWKS(centralAuthUrl)

  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: centralAuthUrl,
      audience: centralAuthUrl,
    })

    const user: JWTPayload = {
      sub: payload.sub as string,
      email: payload.email as string,
      name: payload.name as string,
      avatarUrl: payload.avatarUrl as string | undefined,
      role: payload.role as string | undefined,
      activeOrganizationId: payload.activeOrganizationId as string | undefined,
      appRole: payload.appRole as JWTPayload['appRole'],
      permissions: (payload.permissions as string[]) ?? [],
      customFields: (payload.customFields as Record<string, string>) ?? {},
      exp: payload.exp,
      iat: payload.iat,
    }

    return { success: true, payload: user }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid token'
    const isExpired =
      message.includes('exp') || message.includes('expired')

    return { success: false, error: message, isExpired }
  }
}
