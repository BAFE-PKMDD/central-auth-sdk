import { TOKEN_REVOKE_ENDPOINT_PATH } from '../constants'
import type { TokenRevokeProxyConfig } from '../types'
import { postTokenEndpoint } from './post-json'

/**
 * Proxy a token revoke request to Central Auth.
 *
 * This function calls Central Auth's `/api/token/revoke` endpoint,
 * attaching the `client_id` and `client_secret` server-side so that
 * secrets never reach the browser.
 *
 * @param config - Revoke proxy configuration including credentials
 * @returns `{ success: boolean }` reflecting whether the token was revoked
 * @throws {CentralAuthError} if the Central Auth request fails
 */
export async function proxyTokenRevoke(
  config: TokenRevokeProxyConfig,
): Promise<{ success: boolean }> {
  const {
    centralAuthUrl,
    clientId,
    clientSecret,
    refreshToken,
    origin,
    timeoutMs = 10_000,
  } = config

  const data = await postTokenEndpoint({
    centralAuthUrl,
    path: TOKEN_REVOKE_ENDPOINT_PATH,
    body: {
      refresh_token: refreshToken,
      client_id: clientId,
      client_secret: clientSecret,
    },
    origin,
    timeoutMs,
    defaultErrorPrefix: 'Token revoke failed',
  })

  return {
    success: typeof data.success === 'boolean' ? data.success : true,
  }
}
