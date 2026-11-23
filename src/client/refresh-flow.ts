import {
  DEFAULT_REFRESH_BUFFER_SECONDS,
  DEFAULT_TTL_FALLBACK_SECONDS,
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

type RefreshOutcome = 'ok' | 'permanent_failure' | 'transient_failure'

const MAX_TRANSIENT_RETRIES = 5
const BASE_RETRY_SECONDS = 5
const MAX_RETRY_SECONDS = 60

function defaultLogoutRedirect(): void {
  if (typeof window !== 'undefined') {
    window.location.href = '/'
  }
}

/**
 * Create a fully managed token refresh flow.
 *
 * Returns an object with methods to manually refresh, schedule
 * auto-refresh, initialize the flow on page load, stop the timer,
 * and perform a full logout (including central-auth session).
 */
export function createRefreshFlow(config: RefreshFlowConfig) {
  const {
    refreshEndpoint,
    centralAuthUrl,
    clientId,
    refreshBufferSeconds = DEFAULT_REFRESH_BUFFER_SECONDS,
    onLogout = defaultLogoutRedirect,
  } = config

  let refreshTimer: ReturnType<typeof setTimeout> | null = null
  let inFlightRefresh: Promise<RefreshOutcome> | null = null
  let stopped = false
  let transientFailures = 0
  const normalizedAuthUrl = centralAuthUrl.replace(/\/+$/, '')

  async function executeRefresh(): Promise<RefreshOutcome> {
    if (stopped) return 'transient_failure'
    if (inFlightRefresh) return inFlightRefresh

    inFlightRefresh = (async (): Promise<RefreshOutcome> => {
      const rt = getRefreshToken()
      if (!rt) return 'permanent_failure'

      try {
        const res = await fetch(refreshEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: rt }),
        })

        if (stopped) return 'transient_failure'

        if (!res.ok) {
          console.error('[CentralAuth] Refresh failed:', res.status)
          if (res.status === 400 || res.status === 401 || res.status === 403) {
            return 'permanent_failure'
          }
          return 'transient_failure'
        }

        const data = (await res.json()) as Partial<TokenRefreshResponse>
        if (stopped) return 'ok'
        if (!data.access_token || typeof data.access_token !== 'string') {
          return 'transient_failure'
        }

        transientFailures = 0
        const expiresIn =
          typeof data.expires_in === 'number' && Number.isFinite(data.expires_in)
            ? data.expires_in
            : DEFAULT_TTL_FALLBACK_SECONDS

        setToken(data.access_token)
        setTokenExpiry(expiresIn)

        if (data.refresh_token && typeof data.refresh_token === 'string') {
          setRefreshToken(data.refresh_token)
        }

        if (!stopped) {
          schedule(expiresIn)
        }
        return 'ok'
      } catch (err) {
        console.error('[CentralAuth] Refresh error:', err)
        return 'transient_failure'
      } finally {
        inFlightRefresh = null
      }
    })()

    return inFlightRefresh
  }

  function scheduleTransientRetry(): void {
    if (stopped) return
    transientFailures += 1
    if (transientFailures > MAX_TRANSIENT_RETRIES) {
      console.warn('[CentralAuth] Max transient refresh retries reached')
      return
    }
    const backoffSeconds = Math.min(
      MAX_RETRY_SECONDS,
      BASE_RETRY_SECONDS * 2 ** (transientFailures - 1),
    )
    if (refreshTimer) clearTimeout(refreshTimer)
    refreshTimer = setTimeout(() => {
      void runScheduledRefresh()
    }, backoffSeconds * 1000)
  }

  async function runScheduledRefresh(): Promise<void> {
    if (stopped) return
    const outcome = await executeRefresh()
    if (stopped) return

    if (outcome === 'permanent_failure') {
      console.warn('[CentralAuth] Auto-refresh unauthorized — logging out')
      transientFailures = 0
      removeTokens()
      onLogout()
    } else if (outcome === 'transient_failure') {
      scheduleTransientRetry()
    }
  }

  /**
   * Call the consumer backend's refresh proxy to get a new access token.
   * Deduplicates concurrent calls via a single-flight lock.
   */
  async function refresh(): Promise<boolean> {
    const outcome = await executeRefresh()
    return outcome === 'ok'
  }

  /**
   * Schedule the next proactive token refresh.
   *
   * @param expiresIn - Seconds until the current token expires
   */
  function schedule(expiresIn: number): void {
    stopped = false
    if (refreshTimer) clearTimeout(refreshTimer)

    const safeExpiresIn = Number.isFinite(expiresIn) ? expiresIn : DEFAULT_TTL_FALLBACK_SECONDS
    const refreshIn =
      Math.max(MIN_REFRESH_INTERVAL_SECONDS, safeExpiresIn - refreshBufferSeconds) *
      1000

    refreshTimer = setTimeout(() => {
      void runScheduledRefresh()
    }, refreshIn)
  }

  /**
   * Initialize the refresh flow on app startup.
   * If the token is missing or expired and a refresh token is present, attempts an immediate refresh.
   * If valid, schedules the next refresh based on remaining TTL.
   */
  function init(): void {
    stopped = false
    transientFailures = 0
    const token = getToken()
    if (!token) {
      if (getRefreshToken()) {
        void runScheduledRefresh()
      }
      return
    }

    const ttl = getTokenTtl(token)
    if (ttl <= 0) {
      void runScheduledRefresh()
    } else {
      schedule(ttl)
    }
  }

  /** Stop the auto-refresh timer. Call this on logout. */
  function stop(): void {
    stopped = true
    transientFailures = 0
    if (refreshTimer) {
      clearTimeout(refreshTimer)
      refreshTimer = null
    }
  }

  /**
   * Perform a full logout: stop refresh timer, clear local tokens,
   * and redirect to Central Auth to sign out the session.
   *
   * @param redirectTo - URL to redirect after logout (defaults to current origin + '/auth/login')
   */
  function logout(redirectTo?: string): void {
    stop()
    removeTokens()

    if (typeof window === 'undefined') {
      return
    }

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_to: redirectTo ?? `${window.location.origin}/auth/login`,
    })

    window.location.href = `${normalizedAuthUrl}${LOGOUT_PATH}?${params.toString()}`
  }

  return { refresh, schedule, init, stop, logout }
}
