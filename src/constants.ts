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

/** Central Auth token exchange endpoint path. */
export const TOKEN_EXCHANGE_ENDPOINT_PATH = '/api/token/exchange'

/** Central Auth token refresh endpoint path. */
export const TOKEN_REFRESH_ENDPOINT_PATH = '/api/token/refresh'

/** Central Auth token revoke endpoint path. */
export const TOKEN_REVOKE_ENDPOINT_PATH = '/api/token/revoke'

/** Central Auth token introspect endpoint path. */
export const TOKEN_INTROSPECT_ENDPOINT_PATH = '/api/token/introspect'

/** Central Auth login redirect path. */
export const AUTH_LOGIN_PATH = '/auth/login'

/** Central Auth logout redirect path. */
export const LOGOUT_PATH = '/auth/logout'

/** Default HTTP-only auth cookie lifetime in seconds (7 days). */
export const DEFAULT_COOKIE_MAX_AGE_SECONDS = 7 * 24 * 60 * 60

/** Default short-lived OAuth PKCE/state cookie lifetime in seconds (5 minutes). */
export const DEFAULT_OAUTH_TEMP_COOKIE_MAX_AGE_SECONDS = 300

/** Default grace window (ms) for server-side token refresh deduplication. */
export const DEFAULT_REFRESH_GRACE_MS = 45_000

/** Default max timestamp drift (ms) for back-channel logout webhook verification. */
export const DEFAULT_BACKCHANNEL_MAX_DRIFT_MS = 30_000
