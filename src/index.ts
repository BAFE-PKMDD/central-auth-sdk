// @bafe-pkmdd/central-auth-sdk
// Framework-agnostic JavaScript SDK for Central Auth consumers.

// ─── Types ───────────────────────────────────────────────
export type {
  JWTPayload,
  RefreshFlowConfig,
  VerifyTokenConfig,
  TokenRefreshProxyConfig,
  TokenRevokeProxyConfig,
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
  TOKEN_REFRESH_ENDPOINT_PATH,
  TOKEN_REVOKE_ENDPOINT_PATH,
  LOGOUT_PATH,
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
} from './client/index'

// ─── Server SDK ──────────────────────────────────────────
export {
  createJWKS,
  verifyAccessToken,
  extractBearerToken,
  proxyTokenRefresh,
  proxyTokenRevoke,
} from './server/index'
