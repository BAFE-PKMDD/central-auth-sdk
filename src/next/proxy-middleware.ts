import { DEFAULT_COOKIE_MAX_AGE_SECONDS } from '../constants'
import { isNetworkError } from './refresh-manager'
import { sanitizeRedirectPath, tryParseOrigin } from './redirect'
import type {
  NextAuthProxyConfig,
  NextRequestLike,
  NextResponseLike,
} from './types'

/**
 * Merge updated cookie key/value pairs into a raw `Cookie` request header string.
 */
export function upsertRequestCookies(
  existingCookieHeader: string | null,
  updates: Record<string, string>,
): string {
  const cookieMap = new Map<string, string>()
  if (existingCookieHeader) {
    for (const part of existingCookieHeader.split(';')) {
      const idx = part.indexOf('=')
      if (idx > 0) {
        cookieMap.set(part.slice(0, idx).trim(), part.slice(idx + 1).trim())
      }
    }
  }
  for (const [key, value] of Object.entries(updates)) {
    cookieMap.set(key, value)
  }
  return Array.from(cookieMap.entries())
    .map(([key, value]) => `${key}=${value}`)
    .join('; ')
}

/**
 * Apply baseline security response headers (`X-Content-Type-Options`, `Referrer-Policy`,
 * and `Strict-Transport-Security` in production) while clearing legacy `X-Frame-Options`.
 */
export function applyDefaultSecurityHeaders(
  headers: Headers,
  isProduction: boolean,
): void {
  headers.delete('X-Frame-Options')
  headers.set('X-Content-Type-Options', 'nosniff')
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  if (isProduction) {
    headers.set(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains; preload',
    )
  }
}

/**
 * Create a Next.js middleware/proxy handler that:
 * 1. Protects configured pages with silent refresh + request cookie forwarding + SWR passthrough
 * 2. Protects configured API routes (401 when unauthenticated)
 * 3. Rejects cross-origin non-GET requests to `/api/*` (CSRF protection)
 */
export function createNextAuthProxy<
  TResponse extends NextResponseLike = NextResponseLike,
>(
  config: NextAuthProxyConfig<TResponse>,
): (request: NextRequestLike) => Promise<TResponse> {
  const {
    nextResponse,
    protectedPages,
    publicApi,
    protectedApi = /^\/api\//,
    tokenCookieName,
    refreshTokenCookieName,
    cookieMaxAgeSeconds = DEFAULT_COOKIE_MAX_AGE_SECONDS,
    isProduction = false,
    performRefresh,
    applySecurityHeaders: shouldApplyHeaders = false,
    onResponse,
    loginPath = '/login',
  } = config

  function finalize(response: TResponse): TResponse {
    if (shouldApplyHeaders) {
      applyDefaultSecurityHeaders(response.headers, isProduction)
    }
    return onResponse ? onResponse(response) : response
  }

  return async function nextAuthProxy(
    request: NextRequestLike,
  ): Promise<TResponse> {
    const { pathname } = request.nextUrl
    const token = request.cookies.get(tokenCookieName)?.value

    // 1. Protected Pages: verify token or perform silent refresh
    if (protectedPages.test(pathname) && !token) {
      const refreshToken = request.cookies.get(refreshTokenCookieName)?.value
      if (refreshToken) {
        try {
          const result = await performRefresh(refreshToken)
          if (result?.access_token) {
            const requestHeaders = new Headers(request.headers)
            const updatedCookies: Record<string, string> = {
              [tokenCookieName]: result.access_token,
            }
            if (result.refresh_token) {
              updatedCookies[refreshTokenCookieName] = result.refresh_token
            }
            requestHeaders.set(
              'cookie',
              upsertRequestCookies(
                request.headers.get('cookie'),
                updatedCookies,
              ),
            )

            const response = nextResponse.next({
              request: { headers: requestHeaders },
            })
            const cookieOpts = {
              httpOnly: true,
              secure: isProduction,
              sameSite: 'lax' as const,
              path: '/',
              maxAge: cookieMaxAgeSeconds,
            }
            response.cookies.set(tokenCookieName, result.access_token, cookieOpts)
            if (result.refresh_token) {
              response.cookies.set(
                refreshTokenCookieName,
                result.refresh_token,
                cookieOpts,
              )
            }
            return finalize(response)
          }
        } catch (err) {
          console.error('[Middleware] Silent refresh failed:', err)
          if (isNetworkError(err)) {
            return finalize(nextResponse.next())
          }
        }
      }

      const loginUrl = new URL(loginPath, request.url)
      loginUrl.searchParams.set('clear_session', 'true')
      const safeRedirect = sanitizeRedirectPath(pathname, '')
      if (safeRedirect) {
        loginUrl.searchParams.set('redirect', safeRedirect)
      }
      return finalize(nextResponse.redirect(loginUrl))
    }

    // 2. Protected API: 401 when missing access token
    if (protectedApi.test(pathname) && !publicApi.test(pathname) && !token) {
      return finalize(
        nextResponse.json({ error: 'Unauthorized' }, { status: 401 }),
      )
    }

    // 3. CSRF check on non-GET /api/* mutations
    if (request.method !== 'GET' && pathname.startsWith('/api/')) {
      const origin = request.headers.get('origin')
      const host = request.headers.get('host')

      if (origin && host) {
        try {
          const originHost = new URL(origin).host
          if (originHost !== host) {
            return finalize(
              nextResponse.json({ error: 'Forbidden' }, { status: 403 }),
            )
          }
        } catch {
          return finalize(
            nextResponse.json({ error: 'Forbidden' }, { status: 403 }),
          )
        }
      }
    }

    return finalize(nextResponse.next())
  }
}

export { tryParseOrigin }
