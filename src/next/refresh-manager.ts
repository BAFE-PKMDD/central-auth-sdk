import { DEFAULT_REFRESH_GRACE_MS } from '../constants'
import { proxyTokenRefresh } from '../server/refresh-token'
import type { TokenRefreshResponse } from '../types'
import type { RefreshManager, RefreshManagerConfig } from './types'

const NETWORK_ERROR_PATTERNS = [
  'network_error',
  'fetch failed',
  'econnrefused',
  'enotfound',
  'etimedout',
  'failed to fetch',
  'unable to connect',
  'failed to connect',
  'connect error',
  'connection error',
  'network error',
  'service temporarily unavailable',
  'is the computer able to access the url',
  '503',
  '502',
  '504',
]

/**
 * Checks whether an error is transient / network-related (e.g. Central Auth downtime,
 * connection refused, DNS failure, or gateway 502/503/504).
 * Safe for use in Edge middleware as well as Node / Bun runtimes.
 */
export function isNetworkError(err: unknown): boolean {
  if (!err) return false
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase()
  return NETWORK_ERROR_PATTERNS.some((pattern) => msg.includes(pattern))
}

/**
 * Create a per-app refresh deduplication manager with a configurable grace cache.
 * Concurrent calls for the same refresh token share one upstream request, and recently
 * rotated tokens stay cached briefly so racing SSR/API requests don't trigger token reuse errors.
 */
export function createRefreshManager(
  config: RefreshManagerConfig,
): RefreshManager {
  const {
    centralAuthUrl,
    clientId,
    clientSecret,
    graceMs = DEFAULT_REFRESH_GRACE_MS,
    timeoutMs,
  } = config

  const inFlightRefreshes = new Map<string, Promise<TokenRefreshResponse>>()
  const recentRefreshesCache = new Map<
    string,
    { result: TokenRefreshResponse; expiresAt: number }
  >()

  function clearRefreshCache(refreshToken?: string): void {
    if (refreshToken) {
      const cached = recentRefreshesCache.get(refreshToken)
      recentRefreshesCache.delete(refreshToken)
      inFlightRefreshes.delete(refreshToken)
      if (cached?.result?.refresh_token) {
        recentRefreshesCache.delete(cached.result.refresh_token)
        inFlightRefreshes.delete(cached.result.refresh_token)
      }
      return
    }
    recentRefreshesCache.clear()
    inFlightRefreshes.clear()
  }

  async function performRefresh(
    refreshToken: string,
  ): Promise<TokenRefreshResponse> {
    const cached = recentRefreshesCache.get(refreshToken)
    if (cached && Date.now() < cached.expiresAt) {
      return cached.result
    }

    const existing = inFlightRefreshes.get(refreshToken)
    if (existing) {
      return await existing
    }

    const promise = (async () => {
      try {
        const result = await proxyTokenRefresh({
          centralAuthUrl,
          clientId,
          clientSecret,
          refreshToken,
          ...(timeoutMs !== undefined ? { timeoutMs } : {}),
        })

        if (result && result.access_token) {
          const expiresAt = Date.now() + graceMs
          recentRefreshesCache.set(refreshToken, { result, expiresAt })
          if (result.refresh_token) {
            recentRefreshesCache.set(result.refresh_token, {
              result,
              expiresAt,
            })
          }
        }

        return result
      } finally {
        inFlightRefreshes.delete(refreshToken)
        const now = Date.now()
        for (const [key, value] of recentRefreshesCache.entries()) {
          if (now >= value.expiresAt) {
            recentRefreshesCache.delete(key)
          }
        }
      }
    })()

    inFlightRefreshes.set(refreshToken, promise)
    return await promise
  }

  return { performRefresh, clearRefreshCache }
}
