// ─── JWT Payload ─────────────────────────────────────────

/** Standard claims embedded in Central Auth JWTs. */
export type JWTPayload = {
  /** User ID (subject) */
  sub: string
  /** User email address */
  email: string
  /** User display name */
  name: string
  /** Global user role (e.g. "admin", "user") */
  role?: string
  /** Active organization ID from the JWT context */
  activeOrganizationId?: string
  /** Application-specific role assigned via Central Auth RBAC */
  appRole?: { name: string; color: string | null } | null
  /** Flat list of permission strings (e.g. "project:read") */
  permissions?: string[]
  /** URL to the user's avatar image (e.g. Google profile picture) */
  avatarUrl?: string | null
  /** Token expiry (Unix timestamp, seconds) */
  exp?: number
  /** Token issued-at (Unix timestamp, seconds) */
  iat?: number
}

// ─── Client Config ───────────────────────────────────────

/** Configuration for the client-side refresh flow. */
export type RefreshFlowConfig = {
  /**
   * URL of the consumer backend's token refresh proxy endpoint.
   * This endpoint should forward the refresh token to Central Auth
   * and attach `client_id` + `client_secret` server-side.
   *
   * @example "http://localhost:4000/auth/refresh"
   * @example "/auth/refresh" (relative path)
   */
  refreshEndpoint: string

  /**
   * Full URL of the Central Auth instance.
   * Used for the logout redirect to clear the session cookie.
   *
   * @example "https://auth.example.com"
   */
  centralAuthUrl: string

  /**
   * OAuth client ID registered in Central Auth.
   * Passed to the logout redirect so central-auth can build
   * a fallback redirect URL.
   */
  clientId: string

  /**
   * How many seconds before JWT expiry to trigger a proactive refresh.
   * @default 30
   */
  refreshBufferSeconds?: number

  /**
   * Called when auto-refresh fails (e.g. refresh token revoked).
   * Use this to redirect the user to the login page.
   *
   * @example () => { window.location.href = '/login' }
   */
  onLogout?: () => void
}

// ─── Server Config ───────────────────────────────────────

/** Configuration for server-side JWT verification. */
export type VerifyTokenConfig = {
  /** Full URL of the Central Auth instance (e.g. "https://auth.example.com") */
  centralAuthUrl: string

  /**
   * Optional pre-created JWKS key set.
   * If omitted, one is created automatically from `centralAuthUrl`.
   */
  jwks?: ReturnType<typeof import('jose').createRemoteJWKSet>
}

/** Configuration for the server-side token refresh proxy. */
export type TokenRefreshProxyConfig = {
  /** Full URL of the Central Auth instance */
  centralAuthUrl: string
  /** OAuth client ID registered in Central Auth */
  clientId: string
  /** OAuth client secret (keep this server-side only!) */
  clientSecret: string
  /** The refresh token received from the client */
  refreshToken: string
}

/** Configuration for the server-side token revoke proxy. */
export type TokenRevokeProxyConfig = {
  /** Full URL of the Central Auth instance */
  centralAuthUrl: string
  /** OAuth client ID registered in Central Auth */
  clientId: string
  /** OAuth client secret (keep this server-side only!) */
  clientSecret: string
  /** The refresh token to revoke */
  refreshToken: string
}

// ─── Response Types ──────────────────────────────────────

/** Successful token refresh response from Central Auth. */
export type TokenRefreshResponse = {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

/** Discriminated union for JWT verification results. */
export type VerifyTokenResult =
  | {
    success: true
    payload: JWTPayload
  }
  | {
    success: false
    error: string
    isExpired: boolean
  }
