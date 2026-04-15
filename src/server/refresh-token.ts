import { TOKEN_REFRESH_ENDPOINT_PATH } from '../constants'
import type { TokenRefreshProxyConfig, TokenRefreshResponse } from '../types'

/**
 * Proxy a token refresh request to Central Auth.
 *
 * This function calls Central Auth's `/api/token/refresh` endpoint,
 * attaching the `client_id` and `client_secret` server-side so that
 * secrets never reach the browser.
 *
 * @param config - Refresh proxy configuration including credentials
 * @returns The token refresh response with new access + refresh tokens
 * @throws Error if the Central Auth request fails
 *
 * @example
 * ```ts
 * // Express
 * app.post('/auth/refresh', async (req, res) => {
 *   try {
 *     const result = await proxyTokenRefresh({
 *       centralAuthUrl: process.env.CENTRAL_AUTH_URL!,
 *       clientId: process.env.CLIENT_ID!,
 *       clientSecret: process.env.CLIENT_SECRET!,
 *       refreshToken: req.body.refresh_token,
 *     })
 *     res.json(result)
 *   } catch (err) {
 *     res.status(401).json({ error: err.message })
 *   }
 * })
 *
 * // Hono
 * app.post('/auth/refresh', async (c) => {
 *   const body = await c.req.json()
 *   const result = await proxyTokenRefresh({
 *     centralAuthUrl: process.env.CENTRAL_AUTH_URL!,
 *     clientId: process.env.CLIENT_ID!,
 *     clientSecret: process.env.CLIENT_SECRET!,
 *     refreshToken: body.refresh_token,
 *   })
 *   return c.json(result)
 * })
 * ```
 */
export async function proxyTokenRefresh(
  config: TokenRefreshProxyConfig,
): Promise<TokenRefreshResponse> {
  const { centralAuthUrl, clientId, clientSecret, refreshToken } = config

  let res: Response
  try {
    res = await fetch(
      `${centralAuthUrl}${TOKEN_REFRESH_ENDPOINT_PATH}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          refresh_token: refreshToken,
          client_id: clientId,
          client_secret: clientSecret,
        }),
      },
    )
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown network error'
    throw new Error(`NETWORK_ERROR: ${msg}`)
  }

  let data: Record<string, unknown>
  try {
    data = (await res.json()) as Record<string, unknown>
  } catch (err) {
    throw new Error(`PARSE_ERROR: Failed to parse response from Central Auth (Status ${res.status})`)
  }

  if (!res.ok) {
    const errorMessage =
      (data.error as string) ?? `Token refresh failed with status ${res.status}`
    throw new Error(`API_ERROR: ${errorMessage}`)
  }

  return data as unknown as TokenRefreshResponse
}
