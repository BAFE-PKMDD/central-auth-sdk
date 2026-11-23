import { TOKEN_REFRESH_ENDPOINT_PATH } from '../constants'
import {
  CentralAuthError,
  type TokenRefreshProxyConfig,
  type TokenRefreshResponse,
} from '../types'
import { postTokenEndpoint } from './post-json'

/**
 * Proxy a token refresh request to Central Auth.
 *
 * This function calls Central Auth's `/api/token/refresh` endpoint,
 * attaching the `client_id` and `client_secret` server-side so that
 * secrets never reach the browser.
 *
 * @param config - Refresh proxy configuration including credentials
 * @returns The token refresh response with new access + refresh tokens
 * @throws {CentralAuthError} if the Central Auth request fails
 */
export async function proxyTokenRefresh(
  config: TokenRefreshProxyConfig,
): Promise<TokenRefreshResponse> {
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
    path: TOKEN_REFRESH_ENDPOINT_PATH,
    body: {
      refresh_token: refreshToken,
      client_id: clientId,
      client_secret: clientSecret,
    },
    origin,
    timeoutMs,
    defaultErrorPrefix: 'Token refresh failed',
  })

  if (typeof data.access_token !== 'string' || data.access_token.length === 0) {
    throw new CentralAuthError(
      'PARSE_ERROR',
      'Missing access_token in refresh response from Central Auth',
    )
  }

  return data as unknown as TokenRefreshResponse
}
