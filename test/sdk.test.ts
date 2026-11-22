import { describe, expect, it, beforeEach } from 'bun:test'
import { generateKeyPair, exportJWK, SignJWT, createLocalJWKSet } from 'jose'
import { extractBearerToken, verifyAccessToken } from '../src/server/verify-token'
import { getCachedJWKS, clearJWKSCache } from '../src/server/jwks'
import { decodeToken } from '../src/client/jwt-decode'
import { getToken, setToken, removeTokens } from '../src/client/token-storage'

describe('extractBearerToken', () => {
  it('extracts case-insensitive bearer tokens and trims whitespace', () => {
    expect(extractBearerToken('Bearer abc.def.ghi')).toBe('abc.def.ghi')
    expect(extractBearerToken('bearer   abc.def.ghi  ')).toBe('abc.def.ghi')
    expect(extractBearerToken('BEARER tok123')).toBe('tok123')
  })

  it('returns null for missing, empty, or non-bearer headers', () => {
    expect(extractBearerToken(undefined)).toBeNull()
    expect(extractBearerToken(null)).toBeNull()
    expect(extractBearerToken('Bearer ')).toBeNull()
    expect(extractBearerToken('Basic dXNlcjpwYXNz')).toBeNull()
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
})

describe('decodeToken (base64url + UTF-8)', () => {
  it('decodes UTF-8 multibyte claims and rejects malformed tokens', () => {
    const payload = Buffer.from(
      JSON.stringify({ sub: '1', name: 'Niño Peña', exp: 9999999999 }),
      'utf8',
    ).toString('base64url')
    const decoded = decodeToken(`eyJhbGciOiJFZERTQSJ9.${payload}.sig`)
    expect(decoded?.name).toBe('Niño Peña')
    expect(decodeToken('not-a-jwt')).toBeNull()
    expect(decodeToken('a.b')).toBeNull()
  })
})

describe('token-storage SSR safety', () => {
  it('does not throw when window/localStorage is unavailable', () => {
    expect(getToken()).toBeNull()
    expect(() => setToken('abc')).not.toThrow()
    expect(() => removeTokens()).not.toThrow()
  })
})
