/** Default prefix for localStorage keys used by the client SDK. */
export const DEFAULT_STORAGE_PREFIX = 'central_auth'

/** How many seconds before JWT expiry to trigger a proactive refresh. */
export const DEFAULT_REFRESH_BUFFER_SECONDS = 30

/** Minimum seconds to wait before refreshing (prevents tight loop). */
export const MIN_REFRESH_INTERVAL_SECONDS = 10

/** Fallback TTL (seconds) when a JWT has no `exp` claim. */
export const DEFAULT_TTL_FALLBACK_SECONDS = 300

/** Central Auth JWKS endpoint path. */
export const JWKS_ENDPOINT_PATH = '/api/auth/jwks'

/** Central Auth token refresh endpoint path. */
export const TOKEN_REFRESH_ENDPOINT_PATH = '/api/token/refresh'
