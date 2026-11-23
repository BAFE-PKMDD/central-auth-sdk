import { afterEach, describe, expect, it } from 'bun:test'
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose'
import {
  applyDefaultSecurityHeaders,
  createAuthRouteHandlers,
  createNextAuthProxy,
  createNextAuthServer,
  createRefreshManager,
  createSessionEventStore,
  createSseStreamResponse,
  generateOAuthPkceParams,
  getRequestOrigin,
  hmacSha256Hex,
  isNetworkError,
  readTokenExp,
  sanitizeProxySegments,
  sanitizeRedirectPath,
  sha256Hex,
  upsertRequestCookies,
  verifyHmacSha256Hex,
  verifyOAuthState,
} from '../src/next/index'
import type {
  CookieOptions,
  CookieStoreLike,
  NextRequestLike,
  NextResponseFactory,
  NextResponseLike,
  RedisPubSubClientLike,
} from '../src/next/types'

const originalFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = originalFetch
})

type MockResponse = NextResponseLike & {
  kind: 'next' | 'redirect' | 'json'
  status: number
  body?: unknown
  redirectUrl?: string
  forwardedHeaders?: Headers
  setCookies: Map<string, { value: string; options?: CookieOptions }>
}

function createMockNextResponseFactory(): NextResponseFactory<MockResponse> {
  function makeBase(kind: 'next' | 'redirect' | 'json', status = 200): MockResponse {
    const setCookies = new Map<string, { value: string; options?: CookieOptions }>()
    return {
      kind,
      status,
      headers: new Headers(),
      setCookies,
      cookies: {
        set(name: string, value: string, options?: CookieOptions) {
          setCookies.set(name, { value, options })
        },
      },
    }
  }

  return {
    next(init) {
      const res = makeBase('next', 200)
      res.forwardedHeaders = init?.request?.headers
      return res
    },
    redirect(url) {
      const res = makeBase('redirect', 307)
      res.redirectUrl = typeof url === 'string' ? url : url.toString()
      return res
    },
    json(body, init) {
      const res = makeBase('json', init?.status ?? 200)
      res.body = body
      if (init?.headers) {
        for (const [k, v] of Object.entries(init.headers)) {
          res.headers.set(k, v)
        }
      }
      return res
    },
  }
}

function createMockRequest(options: {
  url: string
  method?: string
  headers?: Record<string, string>
  cookies?: Record<string, string>
  jsonBody?: unknown
}): NextRequestLike {
  const parsed = new URL(options.url)
  const headers = new Headers(options.headers)
  const cookieMap = new Map(Object.entries(options.cookies ?? {}))
  return {
    method: options.method ?? 'GET',
    url: options.url,
    nextUrl: {
      pathname: parsed.pathname,
      searchParams: parsed.searchParams,
      origin: parsed.origin,
    },
    headers,
    cookies: {
      get(name: string) {
        const val = cookieMap.get(name)
        return val !== undefined ? { value: val } : undefined
      },
      getAll() {
        return Array.from(cookieMap.entries()).map(([name, value]) => ({
          name,
          value,
        }))
      },
    },
    async json() {
      return options.jsonBody
    },
  }
}

function createMemoryCookieStore(
  initial: Record<string, string> = {},
): CookieStoreLike & { raw: Map<string, string> } {
  const raw = new Map(Object.entries(initial))
  return {
    raw,
    get(name: string) {
      const val = raw.get(name)
      return val !== undefined ? { value: val } : undefined
    },
    set(name: string, value: string, options?: CookieOptions) {
      if (options?.maxAge === 0) {
        raw.delete(name)
      } else {
        raw.set(name, value)
      }
    },
    delete(name: string) {
      raw.delete(name)
    },
  }
}

describe('redirect & segment sanitization', () => {
  it('allows safe single-leading-slash paths and blocks open redirects / XSS', () => {
    expect(sanitizeRedirectPath('/dashboard?tab=overview')).toBe('/dashboard?tab=overview')
    expect(sanitizeRedirectPath('https://evil.com')).toBe('/dashboard')
    expect(sanitizeRedirectPath('//evil.com')).toBe('/dashboard')
    expect(sanitizeRedirectPath('javascript:alert(1)')).toBe('/dashboard')
    expect(sanitizeRedirectPath('/path\\evil')).toBe('/dashboard')
    expect(sanitizeRedirectPath('/bad\npath', '/fallback')).toBe('/fallback')
  })

  it('rejects traversal and encoded slashes in catch-all proxy segments', () => {
    expect(sanitizeProxySegments(['projects', '123'])).toEqual(['projects', '123'])
    expect(sanitizeProxySegments(['a b'])).toEqual(['a%20b'])
    expect(sanitizeProxySegments([])).toBeNull()
    expect(sanitizeProxySegments(['..', 'secret'])).toBeNull()
    expect(sanitizeProxySegments(['%2e%2e'])).toBeNull()
    expect(sanitizeProxySegments(['foo/bar'])).toBeNull()
    expect(sanitizeProxySegments(['user@host'])).toBeNull()
  })

  it('resolves request origin safely with configured URL or allowlisted Host', () => {
    expect(
      getRequestOrigin({
        configuredAppUrl: 'https://abemis3.bafe.gov.ph/dashboard',
        host: 'attacker.example',
      }),
    ).toBe('https://abemis3.bafe.gov.ph')

    expect(
      getRequestOrigin({
        host: 'attacker.example',
        allowedOrigins: ['https://abemis3.bafe.gov.ph'],
        isProduction: true,
        fallbackOrigin: 'https://abemis3.bafe.gov.ph',
      }),
    ).toBe('https://abemis3.bafe.gov.ph')
  })
})

describe('PKCE, constant-time state & HMAC helpers', () => {
  it('generates S256 PKCE pairs and validates state + HMAC in constant time', async () => {
    const pkce = await generateOAuthPkceParams()
    expect(pkce.state.length).toBeGreaterThan(20)
    expect(pkce.codeVerifier.length).toBeGreaterThan(20)

    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(pkce.codeVerifier),
    )
    const expectedChallenge = Buffer.from(digest).toString('base64url')
    expect(pkce.codeChallenge).toBe(expectedChallenge)

    expect(verifyOAuthState(pkce.state, pkce.state)).toBe(true)
    expect(verifyOAuthState('wrong', pkce.state)).toBe(false)
    expect(verifyOAuthState(undefined, pkce.state)).toBe(false)

    const sig = await hmacSha256Hex('super-secret', '{"a":1}')
    expect(await verifyHmacSha256Hex('super-secret', '{"a":1}', sig.toUpperCase())).toBe(true)
    expect(await verifyHmacSha256Hex('super-secret', '{"a":2}', sig)).toBe(false)
  })
})

describe('refresh manager & single-user eviction', () => {
  it('deduplicates concurrent refreshes and only evicts the target user token', async () => {
    let calls = 0
    globalThis.fetch = (async () => {
      calls += 1
      return new Response(
        JSON.stringify({
          access_token: `at-${calls}`,
          refresh_token: `rt-next-${calls}`,
          token_type: 'Bearer',
          expires_in: 300,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      )
    }) as typeof fetch

    const manager = createRefreshManager({
      centralAuthUrl: 'https://auth.example.com',
      clientId: 'abemis3-frontend',
      clientSecret: 'secret',
    })

    const [a, b] = await Promise.all([
      manager.performRefresh('rt-user-1'),
      manager.performRefresh('rt-user-1'),
    ])
    expect(calls).toBe(1)
    expect(a.access_token).toBe('at-1')
    expect(b.access_token).toBe('at-1')

    await manager.performRefresh('rt-user-2')
    expect(calls).toBe(2)

    // Evicting user-1 must not evict user-2 from grace cache
    manager.clearRefreshCache('rt-user-1')
    const cachedUser2 = await manager.performRefresh('rt-user-2')
    expect(cachedUser2.access_token).toBe('at-2')
    expect(calls).toBe(2)

    const refetchedUser1 = await manager.performRefresh('rt-user-1')
    expect(refetchedUser1.access_token).toBe('at-3')
    expect(calls).toBe(3)
    expect(isNetworkError(new Error('ECONNREFUSED 127.0.0.1:3000'))).toBe(true)
  })
})

describe('next auth server (readTokenExp & resolveCurrentUser)', () => {
  it('resolves active session and falls back to SWR only during network errors', async () => {
    const cookieStore = createMemoryCookieStore({
      app_token: '',
    })
    cookieStore.raw.delete('app_token')

    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' })
    const jwk = await exportJWK(publicKey)
    jwk.kid = 'k-next'
    jwk.alg = 'EdDSA'
    const jwksUrl = new URL('https://auth.example.com/api/auth/jwks')

    const expiredJwt = await new SignJWT({ email: 'u@bafe.gov.ph', name: 'Test User' })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'k-next' })
      .setSubject('user-swr')
      .setIssuer('https://auth.example.com')
      .setAudience('abemis3-frontend')
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(privateKey)

    expect(typeof readTokenExp(expiredJwt)).toBe('number')
    expect(readTokenExp('bad')).toBeUndefined()

    cookieStore.raw.set('app_token', expiredJwt)
    cookieStore.raw.set('app_rt', 'rt-swr')

    const localJwks = createLocalJWKSet({ keys: [jwk] })
    expect(localJwks).toBeDefined()

    globalThis.fetch = (async (input: string | URL | Request) => {
      const target = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      if (target === jwksUrl.toString()) {
        return new Response(JSON.stringify({ keys: [jwk] }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      throw new Error('fetch failed ECONNREFUSED')
    }) as typeof fetch

    const authServer = createNextAuthServer({
      centralAuthUrl: 'https://auth.example.com',
      clientId: 'abemis3-frontend',
      clientSecret: 'sec',
      tokenCookieName: 'app_token',
      refreshTokenCookieName: 'app_rt',
      getCookies: async () => cookieStore,
    })

    const res = await authServer.resolveCurrentUser()
    expect(res.isStale).toBe(true)
    expect(res.user?.sub).toBe('user-swr')
  })
})

describe('next proxy middleware', () => {
  it('silently refreshes cookies, guards APIs with 401, and rejects CSRF cross-origin mutations', async () => {
    const nextResponse = createMockNextResponseFactory()
    const proxy = createNextAuthProxy({
      nextResponse,
      protectedPages: /^\/dashboard(?:\/|$)/,
      publicApi: /^\/api\/auth(\/|$)/,
      tokenCookieName: 'app_token',
      refreshTokenCookieName: 'app_rt',
      applySecurityHeaders: true,
      performRefresh: async () => ({
        access_token: 'fresh-jwt',
        refresh_token: 'fresh-rt',
        token_type: 'Bearer',
        expires_in: 300,
      }),
    })

    const pageRes = await proxy(
      createMockRequest({
        url: 'http://localhost:3001/dashboard',
        cookies: { app_rt: 'old-rt', theme: 'light' },
      }),
    )
    expect(pageRes.kind).toBe('next')
    expect(pageRes.forwardedHeaders?.get('cookie')).toContain('app_token=fresh-jwt')
    expect(pageRes.setCookies.get('app_token')?.value).toBe('fresh-jwt')
    expect(pageRes.headers.get('X-Content-Type-Options')).toBe('nosniff')

    const api401 = await proxy(
      createMockRequest({ url: 'http://localhost:3001/api/projects' }),
    )
    expect(api401.status).toBe(401)

    const csrf403 = await proxy(
      createMockRequest({
        url: 'http://localhost:3001/api/projects',
        method: 'POST',
        cookies: { app_token: 'tok' },
        headers: { origin: 'https://evil.com', host: 'localhost:3001' },
      }),
    )
    expect(csrf403.status).toBe(403)

    expect(upsertRequestCookies('a=1; b=2', { b: '9', c: '3' })).toBe('a=1; b=9; c=3')
    const hdr = new Headers({ 'X-Frame-Options': 'SAMEORIGIN' })
    applyDefaultSecurityHeaders(hdr, true)
    expect(hdr.get('X-Frame-Options')).toBeNull()
    expect(hdr.get('Strict-Transport-Security')).toContain('max-age=31536000')
  })
})

describe('session event store & auth route handlers', () => {
  it('relays Redis session events over SSE and enforces backchannel HMAC + PKCE callback', async () => {
    const handlers = new Map<string, (...args: string[]) => void>()
    const published: Array<{ channel: string; message: string }> = []

    const mockPubSub: RedisPubSubClientLike = {
      status: 'ready',
      async subscribe() {
        return 1
      },
      publish(channel, message) {
        published.push({ channel, message })
        return 1
      },
      on(event: string, listener: (...args: string[]) => void) {
        handlers.set(event, listener)
      },
    }

    const store = createSessionEventStore({
      redisPub: mockPubSub,
      redisSub: mockPubSub,
    })
    await store.init()

    const cookieStore = createMemoryCookieStore({ app_rt: 'rt-123' })
    const authServer = createNextAuthServer({
      centralAuthUrl: 'https://auth.example.com',
      clientId: 'abemis3-frontend',
      clientSecret: 'client-secret',
      tokenCookieName: 'app_token',
      refreshTokenCookieName: 'app_rt',
      getCookies: async () => cookieStore,
    })

    const nextResponse = createMockNextResponseFactory()
    const routeHandlers = createAuthRouteHandlers({
      nextResponse,
      centralAuthUrl: 'https://auth.example.com',
      clientId: 'abemis3-frontend',
      clientSecret: 'client-secret',
      authServer,
      stateCookieName: 'oauth_state',
      verifierCookieName: 'oauth_verifier',
      backchannelSecret: 'bc-secret',
      sessionEventStore: store,
      getCurrentUser: async () => ({
        user: { sub: 'u-1', email: 'u@bafe.gov.ph', name: 'User' },
        isStale: false,
      }),
    })

    const loginRes = await routeHandlers.login(
      createMockRequest({ url: 'http://localhost:3001/api/auth/login?redirect=/projects' }),
    )
    expect(loginRes.kind).toBe('redirect')
    expect(loginRes.redirectUrl).toContain('code_challenge_method=S256')
    const issuedState = loginRes.setCookies.get('oauth_state')?.value
    expect(issuedState).toBeTruthy()

    const badStateRes = await routeHandlers.callback(
      createMockRequest({
        url: 'http://localhost:3001/api/auth/callback',
        method: 'POST',
        cookies: { oauth_state: issuedState! },
        jsonBody: { code: 'auth-code-1', state: 'tampered' },
      }),
    )
    expect(badStateRes.status).toBe(400)

    const tokenHash = await sha256Hex('rt-123')
    const controller = new AbortController()
    const sseRes = createSseStreamResponse({
      store,
      userId: 'u-1',
      tokenHash,
      signal: controller.signal,
    })
    const reader = sseRes.body!.getReader()
    const initialChunk = await reader.read()
    expect(new TextDecoder().decode(initialChunk.value)).toContain('event: connected')

    const ts = Date.now()
    const bcBody = { user_id: 'u-1', client_id: 'abemis3-frontend', token_hash: tokenHash, timestamp: ts }
    const sig = await hmacSha256Hex('bc-secret', JSON.stringify(bcBody))
    const bcRes = await routeHandlers.backchannelLogout(
      createMockRequest({
        url: 'http://localhost:3001/api/auth/backchannel-logout',
        method: 'POST',
        jsonBody: { ...bcBody, signature: sig },
      }),
    )
    expect(bcRes.status).toBe(200)
    expect(published.length).toBe(1)

    // Simulate Redis delivering message back to local SSE subscriber
    handlers.get('message')?.('session_events', published[0].message)
    const logoutChunk = await reader.read()
    expect(new TextDecoder().decode(logoutChunk.value)).toContain('event: token_logout')

    controller.abort()
    await reader.cancel()
  })
})
