import { TOKEN_EXCHANGE_ENDPOINT_PATH } from '../constants'
import {
  CentralAuthError,
  type TokenExchangeProxyConfig,
  type TokenExchangeResponse,
} from '../types'
import { postTokenEndpoint } from './post-json'

/**
 * Proxy a one-time authorization code exchange request to Central Auth.
 * Attaches `client_id`, `client_secret`, and optional PKCE `code_verifier` server-side.
 *
 * @param config - Exchange proxy configuration including authorization code and credentials
 * @returns The exchange response containing access and refresh tokens
 * @throws {CentralAuthError} if the Central Auth request fails
 */
export async function proxyTokenExchange(
  config: TokenExchangeProxyConfig,
): Promise<TokenExchangeResponse> {
  const {
    centralAuthUrl,
    clientId,
    clientSecret,
    code,
    codeVerifier,
    origin,
    timeoutMs = 10_000,
  } = config

  const body: Record<string, unknown> = {
    code,
    client_id: clientId,
    client_secret: clientSecret,
  }
  if (codeVerifier) {
    body.code_verifier = codeVerifier
  }

  const data = await postTokenEndpoint({
    centralAuthUrl,
    path: TOKEN_EXCHANGE_ENDPOINT_PATH,
    body,
    origin,
    timeoutMs,
    defaultErrorPrefix: 'Token exchange failed',
  })

  if (typeof data.access_token !== 'string' || data.access_token.length === 0) {
    throw new CentralAuthError(
      'PARSE_ERROR',
      'Missing access_token in exchange response from Central Auth',
    )
  }

  return data as unknown as TokenExchangeResponse
}
