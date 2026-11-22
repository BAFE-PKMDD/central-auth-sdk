import { TOKEN_REVOKE_ENDPOINT_PATH } from '../constants'
import type { TokenRevokeProxyConfig } from '../types'

/**
 * Proxy a token revoke request to Central Auth.
 *
 * This function calls Central Auth's `/api/token/revoke` endpoint,
 * attaching the `client_id` and `client_secret` server-side so that
 * secrets never reach the browser.
 *
 * @param config - Revoke proxy configuration including credentials
 * @returns `{ success: true }` if the token was revoked
 * @throws Error if the Central Auth request fails
 *
 * @example
 * ```ts
 * // Express
 * app.post('/auth/revoke', async (req, res) => {
 *   try {
 *     const result = await proxyTokenRevoke({
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
 * app.post('/auth/revoke', async (c) => {
 *   const body = await c.req.json()
 *   const result = await proxyTokenRevoke({
 *     centralAuthUrl: process.env.CENTRAL_AUTH_URL!,
 *     clientId: process.env.CLIENT_ID!,
 *     clientSecret: process.env.CLIENT_SECRET!,
 *     refreshToken: body.refresh_token,
 *   })
 *   return c.json(result)
 * })
 * ```
 */
export async function proxyTokenRevoke(
  config: TokenRevokeProxyConfig,
): Promise<{ success: boolean }> {
  const {
    centralAuthUrl,
    clientId,
    clientSecret,
    refreshToken,
    timeoutMs = 10_000,
  } = config
  const normalizedUrl = centralAuthUrl.replace(/\/+$/, '')

  let res: Response
  try {
    res = await fetch(
      `${normalizedUrl}${TOKEN_REVOKE_ENDPOINT_PATH}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          refresh_token: refreshToken,
          client_id: clientId,
          client_secret: clientSecret,
        }),
        signal: AbortSignal.timeout(timeoutMs),
      },
    )
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown network error'
    throw new Error(`NETWORK_ERROR: ${msg}`)
  }

  let data: Record<string, unknown>
  try {
    data = (await res.json()) as Record<string, unknown>
  } catch {
    throw new Error(
      `PARSE_ERROR: Failed to parse response from Central Auth (Status ${res.status})`,
    )
  }

  if (!res.ok) {
    const errorMessage =
      (data.error as string) ?? `Token revoke failed with status ${res.status}`
    throw new Error(`API_ERROR: ${errorMessage}`)
  }

  return { success: true }
}
