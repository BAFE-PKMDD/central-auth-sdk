import {
  DEFAULT_REFRESH_BUFFER_SECONDS,
  LOGOUT_PATH,
  MIN_REFRESH_INTERVAL_SECONDS,
} from '../constants'
import type { RefreshFlowConfig, TokenRefreshResponse } from '../types'
import {
  getRefreshToken,
  getToken,
  removeTokens,
  setRefreshToken,
  setToken,
  setTokenExpiry,
} from './token-storage'
import { getTokenTtl } from './jwt-decode'

/**
 * Create a fully managed token refresh flow.
 *
 * Returns an object with methods to manually refresh, schedule
 * auto-refresh, initialize the flow on page load, stop the timer,
 * and perform a full logout (including central-auth session).
 *
 * @example
 * ```ts
 * import { createRefreshFlow } from '@bafe-pkmdd/central-auth-sdk/client'
 *
 * const auth = createRefreshFlow({
 *   refreshEndpoint: '/auth/refresh',
 *   centralAuthUrl: 'https://auth.example.com',
 *   clientId: 'my-app-client-id',
 *   onLogout: () => { window.location.href = '/login' },
 * })
 *
 * // On page load:
 * auth.init()
 *
 * // On logout:
 * auth.logout()
 * ```
 */
export function createRefreshFlow(config: RefreshFlowConfig) {
  const {
    refreshEndpoint,
    centralAuthUrl,
    clientId,
    refreshBufferSeconds = DEFAULT_REFRESH_BUFFER_SECONDS,
    onLogout = () => {
      window.location.href = '/'
    },
  } = config

  let refreshTimer: ReturnType<typeof setTimeout> | null = null

  /**
   * Call the consumer backend's refresh proxy to get a new access token.
   * Automatically stores the new tokens and rotated refresh token.
   *
   * @returns `true` if refresh succeeded, `false` otherwise
   */
  async function refresh(): Promise<boolean> {
    const rt = getRefreshToken()
    if (!rt) return false

    try {
      const res = await fetch(refreshEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: rt }),
      })

      if (!res.ok) {
        console.error('[CentralAuth] Refresh failed:', res.status)
        return false
      }

      const data = (await res.json()) as TokenRefreshResponse

      setToken(data.access_token)
      setTokenExpiry(data.expires_in)

      // Save the rotated refresh token — the old one is now revoked
      if (data.refresh_token) {
        setRefreshToken(data.refresh_token)
      }

      schedule(data.expires_in)
      return true
    } catch (err) {
      console.error('[CentralAuth] Refresh error:', err)
      return false
    }
  }

  /**
   * Schedule the next proactive token refresh.
   *
   * @param expiresIn - Seconds until the current token expires
   */
  function schedule(expiresIn: number): void {
    if (refreshTimer) clearTimeout(refreshTimer)

    const refreshIn =
      Math.max(MIN_REFRESH_INTERVAL_SECONDS, expiresIn - refreshBufferSeconds) *
      1000

    console.log(
      `[CentralAuth] Next refresh in ${Math.round(refreshIn / 1000)}s`,
    )

    refreshTimer = setTimeout(async () => {
      const success = await refresh()
      if (!success) {
        console.warn('[CentralAuth] Auto-refresh failed — logging out')
        removeTokens()
        onLogout()
      }
    }, refreshIn)
  }

  /**
   * Initialize the refresh flow on app startup.
   * If the token is expired, attempts an immediate refresh.
   * If valid, schedules the next refresh based on remaining TTL.
   */
  function init(): void {
    const token = getToken()
    if (!token) return

    const ttl = getTokenTtl(token)
    if (ttl <= 0) {
      // Token already expired, try immediate refresh
      refresh().then((success) => {
        if (!success) {
          removeTokens()
          onLogout()
        }
      })
    } else {
      schedule(ttl)
    }
  }

  /** Stop the auto-refresh timer. Call this on logout. */
  function stop(): void {
    if (refreshTimer) {
      clearTimeout(refreshTimer)
      refreshTimer = null
    }
  }

  /**
   * Perform a full logout: stop refresh timer, clear local tokens,
   * and redirect to Central Auth to sign out the session.
   *
   * After sign-out, central-auth redirects the user back to `redirectTo`.
   *
   * @param redirectTo - URL to redirect after logout (defaults to current origin + '/auth/login')
   */
  function logout(redirectTo?: string): void {
    stop()

    const rt = getRefreshToken()
    removeTokens()

    // Build the central-auth logout URL
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_to: redirectTo ?? `${window.location.origin}/auth/login`,
    })
    if (rt) params.set('refresh_token', rt)

    // Redirect to central-auth to clear the session cookie
    window.location.href = `${centralAuthUrl}${LOGOUT_PATH}?${params.toString()}`
  }

  return { refresh, schedule, init, stop, logout }
}
