// Next.js App Router & Middleware utilities for Central Auth consumers
export type {
  AuthRouteHandlersConfig,
  CookieOptions,
  CookieStoreLike,
  NextAuthProxyConfig,
  NextAuthServer,
  NextAuthServerConfig,
  NextRequestLike,
  NextResponseCookieSetter,
  NextResponseFactory,
  NextResponseLike,
  OAuthPkceParams,
  RedisPubSubClientLike,
  RefreshManager,
  RefreshManagerConfig,
  ResolvedUserResult,
  SessionEventPayload,
  SessionEventStore,
  SessionEventStoreConfig,
} from './types'

export {
  getRequestOrigin,
  sanitizeProxySegments,
  sanitizeRedirectPath,
  tryParseOrigin,
} from './redirect'
export type { GetRequestOriginOptions } from './redirect'

export {
  constantTimeEqual,
  generateOAuthPkceParams,
  hmacSha256Hex,
  sha256Hex,
  verifyHmacSha256Hex,
  verifyOAuthState,
} from './pkce'

export { createRefreshManager, isNetworkError } from './refresh-manager'

export { createNextAuthServer, readTokenExp } from './auth-server'

export {
  createSessionEventStore,
  createSseStreamResponse,
} from './session-events'
export type { CreateSseStreamResponseOptions } from './session-events'

export {
  applyDefaultSecurityHeaders,
  createNextAuthProxy,
  upsertRequestCookies,
} from './proxy-middleware'

export { createAuthRouteHandlers } from './route-handlers'
