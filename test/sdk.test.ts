import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { generateKeyPair, exportJWK, SignJWT, createLocalJWKSet } from 'jose'
import { extractBearerToken, verifyAccessToken } from '../src/server/verify-token'
import { getCachedJWKS, clearJWKSCache } from '../src/server/jwks'
import { proxyTokenExchange } from '../src/server/exchange-token'
import { proxyTokenRefresh } from '../src/server/refresh-token'
import { proxyTokenRevoke } from '../src/server/revoke-token'
import { CentralAuthError } from '../src/types'
import { decodeToken, getTokenTtl } from '../src/client/jwt-decode'
import { createRefreshFlow } from '../src/client/refresh-flow'
import {
  configureStorage,
  getToken,
  getTokenExpiry,
  isAuthenticated,
  removeTokens,
  setToken,
  setTokenExpiry,
} from '../src/client/token-storage'
import { DEFAULT_TTL_FALLBACK_SECONDS } from '../src/constants'

const originalFetch = globalThis.fetch
const originalWindow = globalThis.window
const originalLocalStorage = globalThis.localStorage

afterEach(() => {
  globalThis.fetch = originalFetch
  Object.defineProperty(globalThis, 'window', {
    value: originalWindow,
    configurable: true,
    writable: true,
  })
  Object.defineProperty(globalThis, 'localStorage', {
    value: originalLocalStorage,
    configurable: true,
    writable: true,
  })
})

describe('extractBearerToken', () => {
  it('extracts case-insensitive bearer tokens and trims whitespace', () => {
    expect(extractBearerToken('Bearer abc.def.ghi')).toBe('abc.def.ghi')
    expect(extractBearerToken('bearer   abc.def.ghi  ')).toBe('abc.def.ghi')
    expect(extractBearerToken('BEARER tok123')).toBe('tok123')
  })

  it('returns null for missing, empty, non-bearer, or malformed multi-token headers', () => {
    expect(extractBearerToken(undefined)).toBeNull()
    expect(extractBearerToken(null)).toBeNull()
    expect(extractBearerToken('Bearer ')).toBeNull()
    expect(extractBearerToken('Bearer tok1 tok2')).toBeNull()
    expect(extractBearerToken('Basic dXNlcjpwYXNz')).toBeNull()
    expect(extractBearerToken(['Bearer first-tok', 'Bearer second-tok'])).toBe('first-tok')
  })
})

describe('getCachedJWKS', () => {
  beforeEach(() => clearJWKSCache())

  it('returns the same cached JWKS instance for normalized URLs', () => {
    const a = getCachedJWKS('https://auth.example.com')
    const b = getCachedJWKS('https://auth.example.com///')
    expect(a).toBe(b)
  })
})

describe('verifyAccessToken', () => {
  it('verifies EdDSA tokens with multi-audience allowlist and rejects wrong audience', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' })
    const jwk = await exportJWK(publicKey)
    jwk.kid = 'k1'
    jwk.alg = 'EdDSA'
    const jwks = createLocalJWKSet({ keys: [jwk] })

    const token = await new SignJWT({
      email: 'user@example.com',
      name: 'Juan Dela Cruz',
      permissions: ['project:read'],
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'k1' })
      .setSubject('user-1')
      .setIssuer('https://auth.example.com')
      .setAudience('abemis3-frontend')
      .setExpirationTime('5m')
      .sign(privateKey)

    const ok = await verifyAccessToken(token, {
      centralAuthUrl: 'https://auth.example.com',
      audience: ['abemis3-frontend', 'geoagri2-frontend'],
      jwks,
    })
    expect(ok.success).toBe(true)
    if (ok.success) {
      expect(ok.payload.sub).toBe('user-1')
      expect(ok.payload.permissions).toEqual(['project:read'])
    }

    const wrongAud = await verifyAccessToken(token, {
      centralAuthUrl: 'https://auth.example.com',
      audience: 'other-app',
      jwks,
    })
    expect(wrongAud.success).toBe(false)
  })

  it('rejects non-EdDSA algorithms by default', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256')
    const jwk = await exportJWK(publicKey)
    jwk.kid = 'es1'
    const jwks = createLocalJWKSet({ keys: [jwk] })

    const token = await new SignJWT({ email: 'a@b.c', name: 'Test' })
      .setProtectedHeader({ alg: 'ES256', kid: 'es1' })
      .setSubject('u1')
      .setIssuer('https://auth.example.com')
      .setAudience('abemis3-frontend')
      .setExpirationTime('5m')
      .sign(privateKey)

    const res = await verifyAccessToken(token, {
      centralAuthUrl: 'https://auth.example.com',
      audience: 'abemis3-frontend',
      jwks,
    })
    expect(res.success).toBe(false)
  })

  it('rejects missing sub claim and marks expired allowExpired tokens with isExpired: true', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' })
    const jwk = await exportJWK(publicKey)
    jwk.kid = 'k-exp'
    jwk.alg = 'EdDSA'
    const jwks = createLocalJWKSet({ keys: [jwk] })

    const noSubToken = await new SignJWT({ email: 'a@b.c' })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'k-exp' })
      .setIssuer('https://auth.example.com')
      .setAudience('abemis3-frontend')
      .setExpirationTime('5m')
      .sign(privateKey)

    const noSubRes = await verifyAccessToken(noSubToken, {
      centralAuthUrl: 'https://auth.example.com',
      audience: 'abemis3-frontend',
      jwks,
    })
    expect(noSubRes.success).toBe(false)

    const expiredToken = await new SignJWT({ email: 'a@b.c', name: 'Expired' })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'k-exp' })
      .setSubject('user-exp')
      .setIssuer('https://auth.example.com')
      .setAudience('abemis3-frontend')
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(privateKey)

    const allowed = await verifyAccessToken(expiredToken, {
      centralAuthUrl: 'https://auth.example.com',
      audience: 'abemis3-frontend',
      allowExpired: true,
      jwks,
    })
    expect(allowed.success).toBe(true)
    if (allowed.success) {
      expect(allowed.payload.sub).toBe('user-exp')
      expect(allowed.isExpired).toBe(true)
    }
  })
})

describe('server token proxy helpers', () => {
  it('propagates HTTP status and Origin on exchange/refresh and respects revoke data.success', async () => {
    const capturedHeaders: Array<HeadersInit | undefined> = []

    globalThis.fetch = (async (_input: string | URL | Request, init?: RequestInit) => {
      capturedHeaders.push(init?.headers)
      return new Response(JSON.stringify({ success: false }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }) as typeof fetch

    const revokeResult = await proxyTokenRevoke({
      centralAuthUrl: 'https://auth.example.com/',
      clientId: 'app-1',
      clientSecret: 'sec-1',
      refreshToken: 'rt-1',
      origin: 'https://app.example.com',
    })
    expect(revokeResult).toEqual({ success: false })
    expect(capturedHeaders[0]).toEqual({
      'Content-Type': 'application/json',
      Origin: 'https://app.example.com',
    })

    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ error: 'rate_limited' }), {
        status: 429,
        headers: { 'Content-Type': 'application/json' },
      })) as typeof fetch

    let caught: unknown
    try {
      await proxyTokenRefresh({
        centralAuthUrl: 'https://auth.example.com',
        clientId: 'app-1',
        clientSecret: 'sec-1',
        refreshToken: 'rt-1',
      })
    } catch (err) {
      caught = err
    }
    expect(caught).toBeInstanceOf(CentralAuthError)
    expect((caught as CentralAuthError).code).toBe('API_ERROR')
    expect((caught as CentralAuthError).status).toBe(429)

    globalThis.fetch = (async (_input: string | URL | Request, init?: RequestInit) => {
      const parsed = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>
      expect(parsed.code_verifier).toBe('ver-123')
      return new Response(
        JSON.stringify({
          access_token: 'at-new',
          refresh_token: 'rt-new',
          token_type: 'Bearer',
          expires_in: 300,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      )
    }) as typeof fetch

    const exchanged = await proxyTokenExchange({
      centralAuthUrl: 'https://auth.example.com',
      clientId: 'app-1',
      clientSecret: 'sec-1',
      code: 'code-1',
      codeVerifier: 'ver-123',
    })
    expect(exchanged.access_token).toBe('at-new')
  })
})

describe('decodeToken (base64url + UTF-8) and getTokenTtl', () => {
  it('decodes UTF-8 multibyte claims and rejects arrays or malformed tokens', () => {
    const payload = Buffer.from(
      JSON.stringify({ sub: '1', name: 'Niño Peña', exp: 9999999999 }),
      'utf8',
    ).toString('base64url')
    const decoded = decodeToken(`eyJhbGciOiJFZERTQSJ9.${payload}.sig`)
    expect(decoded?.name).toBe('Niño Peña')

    const arrayPayload = Buffer.from(JSON.stringify(['a', 'b']), 'utf8').toString('base64url')
    expect(decodeToken(`eyJhbGciOiJFZERTQSJ9.${arrayPayload}.sig`)).toBeNull()
    expect(decodeToken('not-a-jwt')).toBeNull()
    expect(decodeToken('a.b')).toBeNull()
  })

  it('handles exp === 0 and non-numeric exp safely in getTokenTtl', () => {
    const zeroExp = Buffer.from(JSON.stringify({ sub: '1', exp: 0 }), 'utf8').toString('base64url')
    const badExp = Buffer.from(JSON.stringify({ sub: '1', exp: 'later' }), 'utf8').toString('base64url')
    expect(getTokenTtl(`h.${zeroExp}.s`)).toBe(0)
    expect(getTokenTtl(`h.${badExp}.s`)).toBe(DEFAULT_TTL_FALLBACK_SECONDS)
  })
})

describe('token-storage & refresh-flow safety', () => {
  it('does not throw when window/localStorage is unavailable', () => {
    expect(getToken()).toBeNull()
    expect(() => setToken('abc')).not.toThrow()
    expect(() => removeTokens()).not.toThrow()
    expect(isAuthenticated()).toBe(false)
  })

  it('guards invalid expiry values and rejects expired tokens in isAuthenticated', () => {
    const store = new Map<string, string>()
    const mockStorage = {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => {
        store.set(k, v)
      },
      removeItem: (k: string) => {
        store.delete(k)
      },
    }
    Object.defineProperty(globalThis, 'window', {
      value: { localStorage: mockStorage, location: { origin: 'http://localhost', href: '/' } },
      configurable: true,
      writable: true,
    })
    Object.defineProperty(globalThis, 'localStorage', {
      value: mockStorage,
      configurable: true,
      writable: true,
    })

    configureStorage('test_auth')
    setTokenExpiry(Number.NaN)
    expect(getTokenExpiry()).toBe(0)

    store.set('test_auth_token_expiry', 'not-a-number')
    expect(getTokenExpiry()).toBe(0)

    const expiredPayload = Buffer.from(
      JSON.stringify({ sub: 'u1', exp: Math.floor(Date.now() / 1000) - 30 }),
      'utf8',
    ).toString('base64url')
    setToken(`h.${expiredPayload}.s`)
    expect(isAuthenticated()).toBe(false)

    const futurePayload = Buffer.from(
      JSON.stringify({ sub: 'u1', exp: Math.floor(Date.now() / 1000) + 300 }),
      'utf8',
    ).toString('base64url')
    setToken(`h.${futurePayload}.s`)
    expect(isAuthenticated()).toBe(true)

    removeTokens()
  })

  it('does not overwrite tokens when stop() is called while refresh is in flight', async () => {
    const store = new Map<string, string>([['stop_test_refresh_token', 'rt-old']])
    const mockStorage = {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => {
        store.set(k, v)
      },
      removeItem: (k: string) => {
        store.delete(k)
      },
    }
    Object.defineProperty(globalThis, 'window', {
      value: { localStorage: mockStorage, location: { origin: 'http://localhost', href: '/' } },
      configurable: true,
      writable: true,
    })
    Object.defineProperty(globalThis, 'localStorage', {
      value: mockStorage,
      configurable: true,
      writable: true,
    })
    configureStorage('stop_test')

    let resolveFetch!: (value: Response) => void
    globalThis.fetch = (() =>
      new Promise<Response>((resolve) => {
        resolveFetch = resolve
      })) as unknown as typeof fetch

    const flow = createRefreshFlow({
      refreshEndpoint: '/api/auth/refresh',
      centralAuthUrl: 'https://auth.example.com',
      clientId: 'app-1',
    })

    const refreshPromise = flow.refresh()
    flow.stop()
    resolveFetch(
      new Response(
        JSON.stringify({
          access_token: 'at-should-not-write',
          refresh_token: 'rt-new',
          expires_in: 300,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )

    expect(await refreshPromise).toBe(false)
    expect(getToken()).toBeNull()
  })
})
