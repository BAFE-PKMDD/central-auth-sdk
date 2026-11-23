import type { JWTVerifyGetKey } from 'jose'
import type { JWTPayload, TokenRefreshResponse } from '../types'

/** HTTP cookie serialization options compatible with Next.js cookies(). */
export type CookieOptions = {
  httpOnly?: boolean
  secure?: boolean
  sameSite?: 'lax' | 'strict' | 'none'
  path?: string
  maxAge?: number
}

/** Structural interface for Next.js `cookies()` store. */
export type CookieStoreLike = {
  get(name: string): { value: string } | undefined
  set(name: string, value: string, options?: CookieOptions): unknown
  delete(name: string): unknown
}

/** Structural interface matching `NextRequest`. */
export type NextRequestLike = {
  method: string
  url: string
  nextUrl: {
    pathname: string
    searchParams: URLSearchParams
    origin?: string
  }
  headers: Headers
  cookies: {
    get(name: string): { value: string } | undefined
    getAll(): Array<{ name: string; value: string }>
  }
  signal?: AbortSignal
  json(): Promise<unknown>
}

/** Structural interface for `NextResponse` cookie mutation. */
export type NextResponseCookieSetter = {
  set(name: string, value: string, options?: CookieOptions): unknown
}

/** Structural interface matching `NextResponse`. */
export type NextResponseLike = {
  headers: Headers
  cookies: NextResponseCookieSetter
}

/** Structural interface matching the static `NextResponse` class in `next/server`. */
export type NextResponseFactory<
  TResponse extends NextResponseLike = NextResponseLike,
> = {
  next(init?: { request?: { headers?: Headers } }): TResponse
  redirect(url: string | URL): TResponse
  json(
    body: unknown,
    init?: { status?: number; headers?: Record<string, string> },
  ): TResponse
}

/** Structural interface matching `ioredis` pub/sub clients. */
export type RedisPubSubClientLike = {
  status?: string
  connect?(): Promise<unknown>
  subscribe(...args: string[]): Promise<unknown>
  publish(channel: string, message: string): Promise<unknown> | unknown
  on(event: 'ready', listener: () => void): unknown
  on(
    event: 'message',
    listener: (channel: string, message: string) => void,
  ): unknown
}

/** OAuth2 CSRF state and PKCE S256 parameter tuple. */
export type OAuthPkceParams = {
  state: string
  codeVerifier: string
  codeChallenge: string
}

/** Resolved server-side session result returned by `resolveCurrentUser`. */
export type ResolvedUserResult = {
  user: JWTPayload | null
  isStale: boolean
}

/** Configuration for `createRefreshManager`. */
export type RefreshManagerConfig = {
  centralAuthUrl: string
  clientId: string
  clientSecret: string
  graceMs?: number
  timeoutMs?: number
}

/** Deduplicated server-side refresh manager with grace cache. */
export type RefreshManager = {
  performRefresh(refreshToken: string): Promise<TokenRefreshResponse>
  clearRefreshCache(refreshToken?: string): void
}

/** Configuration for `createNextAuthServer`. */
export type NextAuthServerConfig = {
  centralAuthUrl: string
  clientId: string
  clientSecret: string
  tokenCookieName: string
  refreshTokenCookieName: string
  getCookies: () => Promise<CookieStoreLike>
  cookieOptions?: CookieOptions
  cookieMaxAgeSeconds?: number
  proactiveRefreshBufferMs?: number
  refreshGraceMs?: number
  refreshTimeoutMs?: number
  isProduction?: boolean
}

/** Server-side Next.js authentication helper bundle. */
export type NextAuthServer = {
  cookieOptions: CookieOptions
  getCachedJwks(): JWTVerifyGetKey | undefined
  getCookieToken(): Promise<string | undefined>
  getCookieRefreshToken(): Promise<string | undefined>
  setCookieToken(token: string, expiresIn?: number): Promise<boolean>
  setCookieRefreshToken(refreshToken: string): Promise<boolean>
  clearCookies(): Promise<boolean>
  performRefresh(refreshToken: string): Promise<TokenRefreshResponse>
  clearRefreshCache(refreshToken?: string): void
  getValidAccessToken(): Promise<string | null>
  resolveCurrentUser(): Promise<ResolvedUserResult>
}

/** Real-time session logout event payload relayed over Redis Pub/Sub and SSE. */
export type SessionEventPayload = {
  type: 'logout' | 'token_logout'
  userId: string
  tokenHash?: string
}

/** Configuration for `createSessionEventStore`. */
export type SessionEventStoreConfig = {
  redisPub: RedisPubSubClientLike
  redisSub: RedisPubSubClientLike
  channel?: string
  isProduction?: boolean
}

/** In-memory SSE socket registry backed by Redis Pub/Sub. */
export type SessionEventStore = {
  init(): Promise<void>
  addConnection(
    userId: string,
    controller: ReadableStreamDefaultController<Uint8Array>,
  ): void
  removeConnection(
    userId: string,
    controller: ReadableStreamDefaultController<Uint8Array>,
  ): void
  pushLogout(userId: string): number
  pushTokenLogout(userId: string, tokenHash: string): number
}

/** Configuration for `createNextAuthProxy`. */
export type NextAuthProxyConfig<
  TResponse extends NextResponseLike = NextResponseLike,
> = {
  nextResponse: NextResponseFactory<TResponse>
  protectedPages: RegExp
  publicApi: RegExp
  protectedApi?: RegExp
  tokenCookieName: string
  refreshTokenCookieName: string
  cookieMaxAgeSeconds?: number
  isProduction?: boolean
  performRefresh: (refreshToken: string) => Promise<TokenRefreshResponse>
  applySecurityHeaders?: boolean
  onResponse?: (response: TResponse) => TResponse
  loginPath?: string
}

/** Configuration for `createAuthRouteHandlers`. */
export type AuthRouteHandlersConfig<
  TResponse extends NextResponseLike = NextResponseLike,
> = {
  nextResponse: NextResponseFactory<TResponse>
  centralAuthUrl: string
  clientId: string
  clientSecret: string
  authServer: NextAuthServer
  stateCookieName: string
  verifierCookieName: string
  tempCookieMaxAgeSeconds?: number
  configuredAppUrl?: string
  allowedAppOrigins?: string[]
  fallbackOrigin?: string
  isProduction?: boolean
  backchannelSecret?: string
  backchannelMaxDriftMs?: number
  revokeTimeoutMs?: number
  sessionEventStore?: SessionEventStore
  getCurrentUser?: () => Promise<ResolvedUserResult>
  heartbeatIntervalMs?: number
}
