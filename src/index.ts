// @bafe-pkmdd/central-auth-sdk
// Framework-agnostic JavaScript SDK for Central Auth consumers.

// ─── Types ───────────────────────────────────────────────
export { CentralAuthError } from './types'
export type {
  CentralAuthErrorCode,
  DataScopeClaim,
  JWTPayload,
  RefreshFlowConfig,
  VerifyTokenConfig,
  TokenExchangeProxyConfig,
  TokenRefreshProxyConfig,
  TokenRevokeProxyConfig,
  TokenExchangeResponse,
  TokenRefreshResponse,
  VerifyTokenResult,
} from './types'

// ─── Constants ───────────────────────────────────────────
export {
  DEFAULT_STORAGE_PREFIX,
  DEFAULT_REFRESH_BUFFER_SECONDS,
  MIN_REFRESH_INTERVAL_SECONDS,
  DEFAULT_TTL_FALLBACK_SECONDS,
  JWKS_ENDPOINT_PATH,
  TOKEN_EXCHANGE_ENDPOINT_PATH,
  TOKEN_REFRESH_ENDPOINT_PATH,
  TOKEN_REVOKE_ENDPOINT_PATH,
  TOKEN_INTROSPECT_ENDPOINT_PATH,
  AUTH_LOGIN_PATH,
  LOGOUT_PATH,
  DEFAULT_COOKIE_MAX_AGE_SECONDS,
  DEFAULT_OAUTH_TEMP_COOKIE_MAX_AGE_SECONDS,
  DEFAULT_REFRESH_GRACE_MS,
  DEFAULT_BACKCHANNEL_MAX_DRIFT_MS,
} from './constants'

// ─── Client SDK ──────────────────────────────────────────
export {
  configureStorage,
  getToken,
  setToken,
  getRefreshToken,
  setRefreshToken,
  setTokenExpiry,
  getTokenExpiry,
  removeTokens,
  isAuthenticated,
  decodeToken,
  getTokenTtl,
  createRefreshFlow,
  hashRefreshToken,
  sanitizeRedirectPath,
} from './client/index'

// ─── Server SDK ──────────────────────────────────────────
export {
  createJWKS,
  getCachedJWKS,
  clearJWKSCache,
  verifyAccessToken,
  extractBearerToken,
  proxyTokenExchange,
  proxyTokenRefresh,
  proxyTokenRevoke,
} from './server/index'
