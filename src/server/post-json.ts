import { CentralAuthError } from '../types'

interface PostTokenEndpointOptions {
  centralAuthUrl: string
  path: string
  body: Record<string, unknown>
  origin?: string
  timeoutMs?: number
  defaultErrorPrefix: string
}

/**
 * Shared POST helper for Central Auth token endpoints.
 * Attaches optional Origin header, enforces timeout, parses JSON,
 * and raises structured `CentralAuthError` instances on failure.
 */
export async function postTokenEndpoint(
  options: PostTokenEndpointOptions,
): Promise<Record<string, unknown>> {
  const {
    centralAuthUrl,
    path,
    body,
    origin,
    timeoutMs = 10_000,
    defaultErrorPrefix,
  } = options
  const normalizedUrl = centralAuthUrl.replace(/\/+$/, '')

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (origin) {
    headers.Origin = origin
  }

  let res: Response
  try {
    res = await fetch(`${normalizedUrl}${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown network error'
    throw new CentralAuthError('NETWORK_ERROR', msg)
  }

  let rawData: unknown
  try {
    rawData = await res.json()
  } catch {
    throw new CentralAuthError(
      'PARSE_ERROR',
      `Failed to parse response from Central Auth (Status ${res.status})`,
      res.status,
    )
  }

  if (!rawData || typeof rawData !== 'object' || Array.isArray(rawData)) {
    throw new CentralAuthError(
      'PARSE_ERROR',
      `Unexpected response payload from Central Auth (Status ${res.status})`,
      res.status,
    )
  }

  const data = rawData as Record<string, unknown>

  if (!res.ok) {
    const errorMessage =
      typeof data.error === 'string' && data.error.length > 0
        ? data.error
        : `${defaultErrorPrefix} with status ${res.status}`
    throw new CentralAuthError('API_ERROR', errorMessage, res.status)
  }

  return data
}
