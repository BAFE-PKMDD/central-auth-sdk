import {
  AUTH_LOGIN_PATH,
  DEFAULT_BACKCHANNEL_MAX_DRIFT_MS,
  DEFAULT_OAUTH_TEMP_COOKIE_MAX_AGE_SECONDS,
} from '../constants'
import { proxyTokenExchange } from '../server/exchange-token'
import { proxyTokenRevoke } from '../server/revoke-token'
import { verifyAccessToken } from '../server/verify-token'
import { CentralAuthError } from '../types'
import {
  generateOAuthPkceParams,
  sha256Hex,
  verifyHmacSha256Hex,
  verifyOAuthState,
} from './pkce'
import {
  getRequestOrigin,
  sanitizeRedirectPath,
} from './redirect'
import { isNetworkError } from './refresh-manager'
import { createSseStreamResponse } from './session-events'
import type {
  AuthRouteHandlersConfig,
  NextRequestLike,
  NextResponseLike,
} from './types'

const SHA256_HEX_RE = /^[0-9a-f]{64}$/i

type CallbackRequestBody = {
  code?: unknown
  state?: unknown
}

type BackchannelRequestBody = {
  user_id?: unknown
  client_id?: unknown
  token_hash?: unknown
  timestamp?: unknown
  signature?: unknown
}

/**
 * Create Next.js App Router handlers for all `/api/auth/*` routes:
 * `login`, `callback`, `refresh`, `logout`, `session`, `backchannelLogout`, and `sessionEvents`.
 */
export function createAuthRouteHandlers<
  TResponse extends NextResponseLike = NextResponseLike,
>(config: AuthRouteHandlersConfig<TResponse>) {
  const {
    nextResponse,
    centralAuthUrl,
    clientId,
    clientSecret,
    authServer,
    stateCookieName,
    verifierCookieName,
    tempCookieMaxAgeSeconds = DEFAULT_OAUTH_TEMP_COOKIE_MAX_AGE_SECONDS,
    configuredAppUrl,
    allowedAppOrigins = [],
    fallbackOrigin = 'http://localhost:3000',
    isProduction = false,
    backchannelSecret = '',
    backchannelMaxDriftMs = DEFAULT_BACKCHANNEL_MAX_DRIFT_MS,
    revokeTimeoutMs = 3_000,
    sessionEventStore,
    getCurrentUser = () => authServer.resolveCurrentUser(),
    heartbeatIntervalMs = 30_000,
  } = config

  const normalizedUrl = centralAuthUrl.replace(/\/+$/, '')

  function clearOAuthTempCookies(response: TResponse): TResponse {
    const expiredOptions = { ...authServer.cookieOptions, maxAge: 0 }
    response.cookies.set(stateCookieName, '', expiredOptions)
    response.cookies.set(verifierCookieName, '', expiredOptions)
    return response
  }

  async function login(request: NextRequestLike): Promise<TResponse> {
    const origin = getRequestOrigin({
      request,
      configuredAppUrl,
      allowedOrigins: allowedAppOrigins,
      isProduction,
      fallbackOrigin,
    })

    const rawRedirect = request.nextUrl.searchParams.get('redirect')
    const redirectPath = sanitizeRedirectPath(rawRedirect, '')

    let callbackUrl = `${origin}/callback`
    if (redirectPath) {
      callbackUrl += `?redirect=${encodeURIComponent(redirectPath)}`
    }

    const { state, codeVerifier, codeChallenge } =
      await generateOAuthPkceParams()

    const authUrl = new URL(AUTH_LOGIN_PATH, normalizedUrl || 'http://localhost:3000')
    authUrl.searchParams.set('client_id', clientId)
    authUrl.searchParams.set('redirect_to', callbackUrl)
    authUrl.searchParams.set('state', state)
    authUrl.searchParams.set('code_challenge', codeChallenge)
    authUrl.searchParams.set('code_challenge_method', 'S256')

    const response = nextResponse.redirect(authUrl)
    const tempOptions = {
      ...authServer.cookieOptions,
      maxAge: tempCookieMaxAgeSeconds,
    }
    response.cookies.set(stateCookieName, state, tempOptions)
    response.cookies.set(verifierCookieName, codeVerifier, tempOptions)

    return response
  }

  async function callback(request: NextRequestLike): Promise<TResponse> {
    try {
      const body = (await request.json()) as CallbackRequestBody
      const code = body?.code
      const state = typeof body?.state === 'string' || body?.state === null ? body.state : undefined

      if (!code || typeof code !== 'string') {
        return clearOAuthTempCookies(
          nextResponse.json(
            { error: 'Missing or invalid authorization code.' },
            { status: 400 },
          ),
        )
      }

      const expectedState = request.cookies.get(stateCookieName)?.value
      const codeVerifier = request.cookies.get(verifierCookieName)?.value

      if ((expectedState || state) && !verifyOAuthState(state, expectedState)) {
        return clearOAuthTempCookies(
          nextResponse.json({ error: 'invalid_state' }, { status: 400 }),
        )
      }

      if (!clientId || !clientSecret) {
        console.error('[Auth/Callback] CLIENT_ID or CLIENT_SECRET not configured')
        return clearOAuthTempCookies(
          nextResponse.json(
            { error: 'Server misconfiguration.' },
            { status: 500 },
          ),
        )
      }

      const data = await proxyTokenExchange({
        centralAuthUrl: normalizedUrl,
        clientId,
        clientSecret,
        code,
        ...(codeVerifier ? { codeVerifier } : {}),
      })

      await authServer.setCookieToken(data.access_token, data.expires_in)
      if (data.refresh_token) {
        await authServer.setCookieRefreshToken(data.refresh_token)
      }

      return clearOAuthTempCookies(nextResponse.json({ success: true }))
    } catch (err) {
      if (err instanceof CentralAuthError && err.code === 'API_ERROR') {
        const detail = err.message.replace(/^API_ERROR:\s*/, '')
        console.error('[Auth/Callback] Token exchange failed:', detail)
        return clearOAuthTempCookies(
          nextResponse.json({ error: detail || 'Authentication failed.' }, { status: 401 }),
        )
      }
      if (err instanceof CentralAuthError && (err.code === 'NETWORK_ERROR' || err.code === 'PARSE_ERROR')) {
        console.error('[Auth/Callback] Exchange request failed:', err.message)
        return clearOAuthTempCookies(
          nextResponse.json({ error: 'Authentication failed.' }, { status: 401 }),
        )
      }
      console.error('[Auth/Callback] Unexpected error:', err)
      return clearOAuthTempCookies(
        nextResponse.json(
          { error: 'Internal server error.' },
          { status: 500 },
        ),
      )
    }
  }

  async function refresh(_request?: NextRequestLike): Promise<TResponse> {
    try {
      const refreshToken = await authServer.getCookieRefreshToken()
      if (!refreshToken) {
        await authServer.clearCookies()
        return nextResponse.json(
          { error: 'Missing refresh token' },
          { status: 400 },
        )
      }

      const result = await authServer.performRefresh(refreshToken)

      if (result.access_token) {
        await authServer.setCookieToken(result.access_token, result.expires_in)
      }
      if (result.refresh_token) {
        await authServer.setCookieRefreshToken(result.refresh_token)
      }

      const verifyResult = await verifyAccessToken(result.access_token, {
        centralAuthUrl: normalizedUrl,
        audience: clientId,
        jwks: authServer.getCachedJwks(),
      })

      if (!verifyResult.success) {
        console.error(
          '[API/Refresh] Verification of refreshed token failed:',
          verifyResult.error,
        )
        await authServer.clearCookies()
        return nextResponse.json(
          { error: 'Verification failed' },
          { status: 401 },
        )
      }

      return nextResponse.json({
        success: true,
        user: verifyResult.payload,
      })
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err)
      console.error('[API/Refresh] Refresh failed:', err)

      if (
        (err instanceof CentralAuthError && err.status === 429) ||
        errorMsg.includes('Too many requests') ||
        errorMsg.includes('429')
      ) {
        return nextResponse.json(
          { error: 'Too many requests. Please try again later.' },
          { status: 429 },
        )
      }

      if (isNetworkError(err)) {
        return nextResponse.json(
          { error: 'Service temporarily unavailable' },
          { status: 503 },
        )
      }

      await authServer.clearCookies()
      return nextResponse.json(
        { error: 'Authentication failed' },
        { status: 401 },
      )
    }
  }

  async function logout(): Promise<TResponse> {
    const refreshToken = await authServer.getCookieRefreshToken()

    if (refreshToken) {
      try {
        await proxyTokenRevoke({
          centralAuthUrl: normalizedUrl,
          clientId,
          clientSecret,
          refreshToken,
          timeoutMs: revokeTimeoutMs,
        })
      } catch (err) {
        console.warn('[API/Logout] Token revoke failed (non-fatal):', err)
      }
    }

    await authServer.clearCookies()
    return nextResponse.json({ success: true })
  }

  async function session(): Promise<TResponse> {
    const { user, isStale } = await getCurrentUser()
    if (!user) {
      return nextResponse.json({ authenticated: false }, { status: 401 })
    }
    return nextResponse.json({
      authenticated: true,
      user,
      is_stale: isStale,
    })
  }

  async function backchannelLogout(
    request: NextRequestLike,
  ): Promise<TResponse> {
    if (!sessionEventStore) {
      return nextResponse.json(
        { error: 'Session event store not configured' },
        { status: 500 },
      )
    }

    try {
      const body = (await request.json()) as BackchannelRequestBody
      const userId = body?.user_id
      const reqClientId = body?.client_id
      const tokenHash =
        typeof body?.token_hash === 'string' && body.token_hash.length > 0
          ? body.token_hash
          : undefined
      const timestamp = body?.timestamp
      const signature = body?.signature

      if (!userId || typeof userId !== 'string' || !reqClientId || !timestamp || !signature) {
        return nextResponse.json(
          { error: 'Missing required fields' },
          { status: 400 },
        )
      }

      if (!backchannelSecret) {
        console.error('[BackchannelLogout] BACKCHANNEL_LOGOUT_SECRET not set')
        return nextResponse.json(
          { error: 'Server misconfiguration' },
          { status: 500 },
        )
      }

      if (!clientId || reqClientId !== clientId) {
        return nextResponse.json(
          { error: 'Invalid client_id' },
          { status: 403 },
        )
      }

      if (typeof signature !== 'string' || !SHA256_HEX_RE.test(signature)) {
        return nextResponse.json(
          { error: 'Invalid signature' },
          { status: 403 },
        )
      }

      if (typeof timestamp !== 'number' || !Number.isFinite(timestamp)) {
        return nextResponse.json(
          { error: 'Invalid timestamp' },
          { status: 400 },
        )
      }

      if (Math.abs(Date.now() - timestamp) > backchannelMaxDriftMs) {
        return nextResponse.json(
          { error: 'Request expired' },
          { status: 403 },
        )
      }

      const payload = tokenHash
        ? { user_id: userId, client_id: reqClientId, token_hash: tokenHash, timestamp }
        : { user_id: userId, client_id: reqClientId, timestamp }

      const isValid = await verifyHmacSha256Hex(
        backchannelSecret,
        JSON.stringify(payload),
        signature,
      )
      if (!isValid) {
        return nextResponse.json(
          { error: 'Invalid signature' },
          { status: 403 },
        )
      }

      const notified = tokenHash
        ? sessionEventStore.pushTokenLogout(userId, tokenHash)
        : sessionEventStore.pushLogout(userId)

      return nextResponse.json({ success: true, notified })
    } catch {
      return nextResponse.json(
        { error: 'Internal server error' },
        { status: 500 },
      )
    }
  }

  async function sessionEvents(request: NextRequestLike): Promise<Response> {
    if (!sessionEventStore) {
      return new Response('Session event store not configured', { status: 500 })
    }

    await sessionEventStore.init()
    const { user } = await getCurrentUser()
    if (!user) {
      return new Response('Unauthorized', { status: 401 })
    }

    const refreshToken = await authServer.getCookieRefreshToken()
    const tokenHash = refreshToken ? await sha256Hex(refreshToken) : null

    return createSseStreamResponse({
      store: sessionEventStore,
      userId: user.sub,
      tokenHash,
      signal: request.signal,
      heartbeatIntervalMs,
    })
  }

  return {
    login,
    callback,
    refresh,
    logout,
    session,
    backchannelLogout,
    sessionEvents,
  }
}
