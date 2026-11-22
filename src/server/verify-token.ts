import { jwtVerify, decodeJwt, type JWTPayload as JoseJWTPayload } from 'jose'
import type { JWTPayload, VerifyTokenConfig, VerifyTokenResult } from '../types'
import { getCachedJWKS } from './jwks'

const DEFAULT_ALGORITHMS = ['EdDSA']

function mapJwtPayload(payload: JoseJWTPayload): JWTPayload {
  return {
    sub: payload.sub as string,
    email: payload.email as string,
    name: payload.name as string,
    avatarUrl: payload.avatarUrl as string | undefined,
    phoneNumber: (payload.phoneNumber as string | null) ?? null,
    role: payload.role as string | undefined,
    activeOrganizationId: payload.activeOrganizationId as string | undefined,
    aiPermissions: payload.aiPermissions as JWTPayload['aiPermissions'],
    appRole: payload.appRole as JWTPayload['appRole'],
    permissions: (payload.permissions as string[]) ?? [],
    customFields: (payload.customFields as Record<string, string>) ?? {},
    dataScope: payload.dataScope as JWTPayload['dataScope'],
    impersonatedBy: (payload.impersonatedBy as string | undefined) || undefined,
    exp: payload.exp,
    iat: payload.iat,
  }
}

/**
 * Extract the Bearer token from an Authorization header value (case-insensitive).
 */
export function extractBearerToken(authHeader?: string | null): string | null {
  if (!authHeader) return null
  const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim())
  if (!match) return null
  const token = match[1].trim()
  return token.length > 0 ? token : null
}

/**
 * Verify a JWT access token against Central Auth's JWKS endpoint.
 */
export async function verifyAccessToken(
  token: string,
  config: VerifyTokenConfig,
): Promise<VerifyTokenResult> {
  const { centralAuthUrl, audience, algorithms, clockTolerance } = config
  const normalizedUrl = centralAuthUrl.replace(/\/+$/, '')
  const jwks = config.jwks ?? getCachedJWKS(normalizedUrl)

  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: normalizedUrl,
      audience: audience ?? normalizedUrl,
      algorithms: algorithms ?? DEFAULT_ALGORITHMS,
      ...(clockTolerance !== undefined ? { clockTolerance } : {}),
    })

    return { success: true, payload: mapJwtPayload(payload) }
  } catch (err: unknown) {
    const joseErr = err as { code?: string; message?: string }
    const isExpired = joseErr?.code === 'ERR_JWT_EXPIRED'
    const message = joseErr?.message || 'Invalid token'

    // If allowExpired is true and verification failed ONLY due to expiration
    // (jose validates the cryptographic signature before checking exp),
    // return the decoded payload as a valid stale session.
    if (isExpired && config.allowExpired) {
      try {
        const payload = decodeJwt(token)
        return { success: true, payload: mapJwtPayload(payload) }
      } catch {
        return {
          success: false,
          error: 'Failed to decode expired token',
          isExpired: true,
        }
      }
    }

    return { success: false, error: message, isExpired }
  }
}
