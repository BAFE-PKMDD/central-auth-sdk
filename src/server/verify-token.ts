import { jwtVerify, decodeJwt, type JWTPayload as JoseJWTPayload } from 'jose'
import type { JWTPayload, VerifyTokenConfig, VerifyTokenResult } from '../types'
import { getCachedJWKS } from './jwks'

const DEFAULT_ALGORITHMS = ['EdDSA']

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function mapCustomFields(raw: unknown): Record<string, string> {
  if (!isPlainObject(raw)) return {}
  const result: Record<string, string> = {}
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value === 'string') {
      result[key] = value
    }
  }
  return result
}

function mapAppRole(raw: unknown): JWTPayload['appRole'] {
  if (!isPlainObject(raw)) return null
  if (typeof raw.id !== 'string' || typeof raw.name !== 'string') return null
  return {
    id: raw.id,
    name: raw.name,
    color: typeof raw.color === 'string' ? raw.color : null,
  }
}

function mapAiPermissions(raw: unknown): JWTPayload['aiPermissions'] {
  if (!isPlainObject(raw) || typeof raw.enabled !== 'boolean') return undefined
  return {
    enabled: raw.enabled,
    dailyLimit:
      typeof raw.dailyLimit === 'number' && Number.isFinite(raw.dailyLimit)
        ? raw.dailyLimit
        : 0,
  }
}

function mapDataScope(raw: unknown): JWTPayload['dataScope'] {
  if (!isPlainObject(raw) || typeof raw.unrestricted !== 'boolean') {
    return undefined
  }
  return {
    unrestricted: raw.unrestricted,
    ...(typeof raw.restricted === 'boolean'
      ? { restricted: raw.restricted }
      : {}),
    ...(isPlainObject(raw.scope) ? { scope: mapCustomFields(raw.scope) } : {}),
  }
}

function mapJwtPayload(payload: JoseJWTPayload): JWTPayload | null {
  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    return null
  }

  return {
    sub: payload.sub,
    email: typeof payload.email === 'string' ? payload.email : '',
    name: typeof payload.name === 'string' ? payload.name : '',
    avatarUrl: typeof payload.avatarUrl === 'string' ? payload.avatarUrl : null,
    phoneNumber:
      typeof payload.phoneNumber === 'string' ? payload.phoneNumber : null,
    role: typeof payload.role === 'string' ? payload.role : undefined,
    activeOrganizationId:
      typeof payload.activeOrganizationId === 'string'
        ? payload.activeOrganizationId
        : undefined,
    aiPermissions: mapAiPermissions(payload.aiPermissions),
    appRole: mapAppRole(payload.appRole),
    permissions: Array.isArray(payload.permissions)
      ? payload.permissions.filter((p): p is string => typeof p === 'string')
      : [],
    customFields: mapCustomFields(payload.customFields),
    dataScope: mapDataScope(payload.dataScope),
    impersonatedBy:
      typeof payload.impersonatedBy === 'string' &&
      payload.impersonatedBy.length > 0
        ? payload.impersonatedBy
        : undefined,
    exp:
      typeof payload.exp === 'number' && Number.isFinite(payload.exp)
        ? payload.exp
        : undefined,
    iat:
      typeof payload.iat === 'number' && Number.isFinite(payload.iat)
        ? payload.iat
        : undefined,
  }
}

/**
 * Extract the Bearer token from an Authorization header value (case-insensitive).
 * Rejects malformed tokens containing internal whitespace.
 */
export function extractBearerToken(
  authHeader?: string | string[] | null,
): string | null {
  const rawHeader = Array.isArray(authHeader) ? authHeader[0] : authHeader
  if (typeof rawHeader !== 'string' || rawHeader.length === 0) return null
  const match = /^Bearer\s+(\S+)$/i.exec(rawHeader.trim())
  if (!match) return null
  return match[1] || null
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

    const mapped = mapJwtPayload(payload)
    if (!mapped) {
      return {
        success: false,
        error: 'Missing subject claim (sub)',
        isExpired: false,
      }
    }

    return { success: true, payload: mapped }
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
        const mapped = mapJwtPayload(payload)
        if (!mapped) {
          return {
            success: false,
            error: 'Missing subject claim (sub)',
            isExpired: true,
          }
        }
        return { success: true, payload: mapped, isExpired: true }
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
