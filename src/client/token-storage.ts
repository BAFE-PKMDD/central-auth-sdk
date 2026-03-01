import { DEFAULT_STORAGE_PREFIX } from '../constants'

// ─── Storage Key Management ─────────────────────────────

let storagePrefix = DEFAULT_STORAGE_PREFIX

/**
 * Configure the storage key prefix used for all localStorage operations.
 * Call this once at app startup if you need a custom prefix.
 *
 * @param prefix - Storage key prefix (default: "central_auth")
 */
export function configureStorage(prefix: string): void {
  storagePrefix = prefix
}

function key(name: string): string {
  return `${storagePrefix}_${name}`
}

// ─── Access Token ────────────────────────────────────────

/** Retrieve the stored access token. */
export function getToken(): string | null {
  return localStorage.getItem(key('token'))
}

/** Store the access token in localStorage. */
export function setToken(token: string): void {
  localStorage.setItem(key('token'), token)
}

// ─── Refresh Token ───────────────────────────────────────

/** Retrieve the stored refresh token. */
export function getRefreshToken(): string | null {
  return localStorage.getItem(key('refresh_token'))
}

/** Store the refresh token in localStorage. */
export function setRefreshToken(token: string): void {
  localStorage.setItem(key('refresh_token'), token)
}

// ─── Token Expiry ────────────────────────────────────────

/**
 * Store the token expiry time based on `expires_in` (seconds from now).
 * Internally stores an absolute Unix-ms timestamp.
 */
export function setTokenExpiry(expiresIn: number): void {
  const expiresAt = Date.now() + expiresIn * 1000
  localStorage.setItem(key('token_expiry'), expiresAt.toString())
}

/** Get the stored token expiry as an absolute Unix-ms timestamp. */
export function getTokenExpiry(): number {
  const expiry = localStorage.getItem(key('token_expiry'))
  return expiry ? parseInt(expiry, 10) : 0
}

// ─── Cleanup ─────────────────────────────────────────────

/** Remove all stored auth tokens and expiry data. */
export function removeTokens(): void {
  localStorage.removeItem(key('token'))
  localStorage.removeItem(key('refresh_token'))
  localStorage.removeItem(key('token_expiry'))
}

// ─── Quick Check ─────────────────────────────────────────

/** Returns `true` if an access token is currently stored. */
export function isAuthenticated(): boolean {
  return !!getToken()
}
