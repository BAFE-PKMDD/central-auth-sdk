import { DEFAULT_STORAGE_PREFIX } from '../constants'
import { decodeToken } from './jwt-decode'

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

function hasStorage(): boolean {
  return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined'
}

// ─── Access Token ────────────────────────────────────────

/** Retrieve the stored access token. */
export function getToken(): string | null {
  if (!hasStorage()) return null
  return localStorage.getItem(key('token'))
}

/** Store the access token in localStorage. */
export function setToken(token: string): void {
  if (!hasStorage()) return
  localStorage.setItem(key('token'), token)
}

// ─── Refresh Token ───────────────────────────────────────

/** Retrieve the stored refresh token. */
export function getRefreshToken(): string | null {
  if (!hasStorage()) return null
  return localStorage.getItem(key('refresh_token'))
}

/** Store the refresh token in localStorage. */
export function setRefreshToken(token: string): void {
  if (!hasStorage()) return
  localStorage.setItem(key('refresh_token'), token)
}

// ─── Token Expiry ────────────────────────────────────────

/**
 * Store the token expiry time based on `expires_in` (seconds from now).
 * Internally stores an absolute Unix-ms timestamp.
 */
export function setTokenExpiry(expiresIn: number): void {
  if (!hasStorage() || !Number.isFinite(expiresIn)) return
  const expiresAt = Date.now() + expiresIn * 1000
  localStorage.setItem(key('token_expiry'), expiresAt.toString())
}

/** Get the stored token expiry as an absolute Unix-ms timestamp. */
export function getTokenExpiry(): number {
  if (!hasStorage()) return 0
  const expiry = localStorage.getItem(key('token_expiry'))
  if (!expiry) return 0
  const parsed = parseInt(expiry, 10)
  return Number.isFinite(parsed) ? parsed : 0
}

// ─── Cleanup ─────────────────────────────────────────────

/** Remove all stored auth tokens and expiry data. */
export function removeTokens(): void {
  if (!hasStorage()) return
  localStorage.removeItem(key('token'))
  localStorage.removeItem(key('refresh_token'))
  localStorage.removeItem(key('token_expiry'))
}

// ─── Quick Check ─────────────────────────────────────────

/** Returns `true` if a non-expired access token is currently stored. */
export function isAuthenticated(): boolean {
  const token = getToken()
  if (!token) return false

  const decoded = decodeToken(token)
  if (decoded && typeof decoded.exp === 'number' && Number.isFinite(decoded.exp)) {
    return decoded.exp * 1000 > Date.now()
  }

  const storedExpiry = getTokenExpiry()
  if (storedExpiry > 0) {
    return storedExpiry > Date.now()
  }

  return true
}
