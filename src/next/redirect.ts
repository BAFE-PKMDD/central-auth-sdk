import type { NextRequestLike } from './types'

export { sanitizeRedirectPath } from '../redirect'

const CONTROL_CHARS_RE = /[\u0000-\u001f\u007f]/

/**
 * Validate catch-all proxy route segments before interpolating into a backend URL path.
 * Rejects empty segments, dot traversal (`.` / `..`), encoded dots/slashes,
 * backslashes, `@`, and control characters.
 */
export function sanitizeProxySegments(segments: string[]): string[] | null {
  if (!Array.isArray(segments) || segments.length === 0) {
    return null
  }

  const sanitized: string[] = []
  for (const segment of segments) {
    if (!segment || typeof segment !== 'string') {
      return null
    }
    const lower = segment.toLowerCase()
    if (
      segment === '.' ||
      segment.includes('..') ||
      lower.includes('%2e') ||
      segment.includes('\\') ||
      lower.includes('%5c') ||
      segment.includes('@') ||
      segment.includes('/') ||
      lower.includes('%2f') ||
      CONTROL_CHARS_RE.test(segment)
    ) {
      return null
    }
    sanitized.push(encodeURIComponent(segment))
  }

  return sanitized
}

export function tryParseOrigin(rawUrl: string): string | null {
  try {
    return new URL(rawUrl).origin
  } catch {
    return null
  }
}

export type GetRequestOriginOptions = {
  request?: Pick<NextRequestLike, 'headers' | 'nextUrl'>
  host?: string | null
  configuredAppUrl?: string
  allowedOrigins?: string[]
  isProduction?: boolean
  fallbackOrigin?: string
}

/**
 * Resolve the canonical application origin for OAuth callbacks without trusting arbitrary forwarded hosts.
 */
export function getRequestOrigin(options: GetRequestOriginOptions): string {
  const {
    request,
    host: explicitHost,
    configuredAppUrl,
    allowedOrigins = [],
    isProduction = false,
    fallbackOrigin = 'http://localhost:3000',
  } = options

  const trimmedConfigured = configuredAppUrl?.trim()
  if (trimmedConfigured) {
    const parsedOrigin = tryParseOrigin(trimmedConfigured)
    if (parsedOrigin) {
      return parsedOrigin
    }
  }

  const allowlist = allowedOrigins.map((item) => item.trim()).filter(Boolean)
  const host = explicitHost !== undefined ? explicitHost : request?.headers.get('host')
  const proto = isProduction ? 'https' : 'http'

  if (host && !host.includes('0.0.0.0')) {
    const candidate = `${proto}://${host}`
    if (allowlist.length === 0 || allowlist.includes(candidate)) {
      return candidate
    }
  }

  return request?.nextUrl?.origin || fallbackOrigin
}
