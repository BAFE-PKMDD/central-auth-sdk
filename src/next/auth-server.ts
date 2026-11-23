import {
  DEFAULT_COOKIE_MAX_AGE_SECONDS,
  DEFAULT_REFRESH_GRACE_MS,
} from '../constants'
import { getCachedJWKS } from '../server/jwks'
import { verifyAccessToken } from '../server/verify-token'
import { createRefreshManager, isNetworkError } from './refresh-manager'
import type {
  CookieOptions,
  NextAuthServer,
  NextAuthServerConfig,
  ResolvedUserResult,
} from './types'

const DEFAULT_PROACTIVE_BUFFER_MS = 15_000

/**
 * Decode ONLY the numeric finite `exp` claim from a JWT string to decide
 * whether a proactive server-side refresh should happen before calling a backend.
 * NEVER use this function for authentication or authorization decisions.
 */
export function readTokenExp(token: string): number | undefined {
  try {
    const parts = token.split('.')
    if (parts.length !== 3 || !parts[1]) return undefined
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=')
    const binary = atob(padded)
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0))
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes))
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return undefined
    }
    const exp = (parsed as Record<string, unknown>).exp
    return typeof exp === 'number' && Number.isFinite(exp) ? exp : undefined
  } catch {
    return undefined
  }
}

function isReadOnlyCookieError(err: unknown): boolean {
  return (
    err instanceof Error &&
    err.message.includes('Cookies can only be modified')
  )
}

/**
 * Create a server-side Next.js authentication helper bundle for reading/writing
 * HTTP-only cookies, performing single-flight token refreshes, and resolving
 * the authenticated user with Stale-While-Revalidate (SWR) JWKS verification.
 */
export function createNextAuthServer(
  config: NextAuthServerConfig,
): NextAuthServer {
  const {
    centralAuthUrl,
    clientId,
    clientSecret,
    tokenCookieName,
    refreshTokenCookieName,
    getCookies,
    cookieMaxAgeSeconds = DEFAULT_COOKIE_MAX_AGE_SECONDS,
    proactiveRefreshBufferMs = DEFAULT_PROACTIVE_BUFFER_MS,
    refreshGraceMs = DEFAULT_REFRESH_GRACE_MS,
    refreshTimeoutMs,
    isProduction = false,
  } = config

  const normalizedUrl = centralAuthUrl.replace(/\/+$/, '')

  const cookieOptions: CookieOptions = {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    maxAge: cookieMaxAgeSeconds,
    ...config.cookieOptions,
  }

  const refreshManager = createRefreshManager({
    centralAuthUrl: normalizedUrl,
    clientId,
    clientSecret,
    graceMs: refreshGraceMs,
    ...(refreshTimeoutMs !== undefined ? { timeoutMs: refreshTimeoutMs } : {}),
  })

  function getAppJwks() {
    if (!normalizedUrl) return undefined
    return getCachedJWKS(normalizedUrl)
  }

  async function getCookieToken(): Promise<string | undefined> {
    const store = await getCookies()
    return store.get(tokenCookieName)?.value
  }

  async function getCookieRefreshToken(): Promise<string | undefined> {
    const store = await getCookies()
    return store.get(refreshTokenCookieName)?.value
  }

  async function setCookieToken(
    token: string,
    _expiresIn?: number,
  ): Promise<boolean> {
    void _expiresIn
    try {
      const store = await getCookies()
      store.set(tokenCookieName, token, {
        ...cookieOptions,
        maxAge: cookieMaxAgeSeconds,
      })
      return true
    } catch (err) {
      if (isReadOnlyCookieError(err)) return false
      throw err
    }
  }

  async function setCookieRefreshToken(refreshToken: string): Promise<boolean> {
    try {
      const store = await getCookies()
      store.set(refreshTokenCookieName, refreshToken, {
        ...cookieOptions,
        maxAge: cookieMaxAgeSeconds,
      })
      return true
    } catch (err) {
      if (isReadOnlyCookieError(err)) return false
      throw err
    }
  }

  async function clearCookies(): Promise<boolean> {
    try {
      const store = await getCookies()
      const refreshToken = store.get(refreshTokenCookieName)?.value
      if (refreshToken) {
        refreshManager.clearRefreshCache(refreshToken)
      }
      store.delete(tokenCookieName)
      store.delete(refreshTokenCookieName)
      return true
    } catch (err) {
      if (isReadOnlyCookieError(err)) return false
      throw err
    }
  }

  async function persistRefreshedTokens(
    accessToken: string,
    refreshToken?: string,
    expiresIn?: number,
  ): Promise<{ setTokenSuccess: boolean; setRefreshSuccess: boolean }> {
    const setTokenSuccess = await setCookieToken(accessToken, expiresIn)
    const setRefreshSuccess = refreshToken
      ? await setCookieRefreshToken(refreshToken)
      : true
    return { setTokenSuccess, setRefreshSuccess }
  }

  async function getValidAccessToken(): Promise<string | null> {
    const token = await getCookieToken()
    if (token) {
      const exp = readTokenExp(token)
      if (exp && exp * 1000 > Date.now() + proactiveRefreshBufferMs) {
        return token
      }
    }

    const refreshToken = await getCookieRefreshToken()
    if (!refreshToken) {
      return token ?? null
    }

    try {
      const result = await refreshManager.performRefresh(refreshToken)
      if (result?.access_token) {
        await persistRefreshedTokens(
          result.access_token,
          result.refresh_token,
          result.expires_in,
        )
        return result.access_token
      }
    } catch (err) {
      if (!isProduction) {
        console.warn('[Auth] getValidAccessToken proactive refresh failed:', err)
      }
    }

    return token ?? null
  }

  async function verifyToken(token: string, allowExpired: boolean) {
    return await verifyAccessToken(token, {
      centralAuthUrl: normalizedUrl,
      audience: clientId,
      jwks: getAppJwks(),
      allowExpired,
    })
  }

  async function recoverWithRefresh(
    existingToken: string,
  ): Promise<ResolvedUserResult | null> {
    const refreshToken = await getCookieRefreshToken()
    if (!refreshToken) return null

    try {
      const refreshResult = await refreshManager.performRefresh(refreshToken)
      if (refreshResult?.access_token) {
        const { setTokenSuccess, setRefreshSuccess } =
          await persistRefreshedTokens(
            refreshResult.access_token,
            refreshResult.refresh_token,
            refreshResult.expires_in,
          )
        const verifyResult = await verifyToken(refreshResult.access_token, false)
        if (verifyResult.success) {
          return {
            user: verifyResult.payload,
            isStale: !setTokenSuccess || !setRefreshSuccess,
          }
        }
      }
      return null
    } catch (err) {
      if (isNetworkError(err)) {
        const staleResult = await verifyToken(existingToken, true)
        if (staleResult.success) {
          return { user: staleResult.payload, isStale: true }
        }
        return { user: null, isStale: false }
      }
      await clearCookies()
      return { user: null, isStale: false }
    }
  }

  async function resolveCurrentUser(): Promise<ResolvedUserResult> {
    let token = await getCookieToken()
    let isStale = false

    // 1. If access token cookie is missing, attempt refresh via refresh token
    if (!token) {
      const refreshToken = await getCookieRefreshToken()
      if (refreshToken) {
        try {
          const result = await refreshManager.performRefresh(refreshToken)
          if (result?.access_token) {
            token = result.access_token
            const { setTokenSuccess, setRefreshSuccess } =
              await persistRefreshedTokens(
                result.access_token,
                result.refresh_token,
                result.expires_in,
              )
            if (!setTokenSuccess || !setRefreshSuccess) {
              isStale = true
            }
          }
        } catch (err) {
          const msg = err instanceof Error ? err.message : ''
          console.error('[Auth] Silent refresh failed in getCurrentUser:', msg)

          if (isNetworkError(err)) {
            isStale = true
          } else {
            await clearCookies()
            return { user: null, isStale: false }
          }
        }
      }
    }

    if (!token) {
      await clearCookies()
      return { user: null, isStale: false }
    }

    // 2. Verify token signature cryptographically against cached JWKS
    const result = await verifyToken(token, isStale)
    if (result.success) {
      return { user: result.payload, isStale }
    }

    const isNetError = isNetworkError(result.error)

    // 3. Expired JWT recovery via refresh (or SWR stale verification on outage)
    if (result.isExpired && !isStale) {
      const recovered = await recoverWithRefresh(token)
      if (recovered) return recovered
    }

    // 4. Network error during initial JWKS check — attempt refresh or cached-JWKS SWR
    if (isNetError && !isStale) {
      const recovered = await recoverWithRefresh(token)
      if (recovered) return recovered

      const staleResult = await verifyToken(token, true)
      if (staleResult.success) {
        return { user: staleResult.payload, isStale: true }
      }
    }

    await clearCookies()
    return { user: null, isStale: false }
  }

  return {
    cookieOptions,
    getCachedJwks: getAppJwks,
    getCookieToken,
    getCookieRefreshToken,
    setCookieToken,
    setCookieRefreshToken,
    clearCookies,
    performRefresh: refreshManager.performRefresh,
    clearRefreshCache: refreshManager.clearRefreshCache,
    getValidAccessToken,
    resolveCurrentUser,
  }
}
