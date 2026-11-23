const CONTROL_CHARS_RE = /[\u0000-\u001f\u007f]/
const SINGLE_LEADING_SLASH_RE = /^\/(?!\/)/

/**
 * Sanitize an untrusted redirect path to prevent open redirects and DOM XSS.
 * Allows only single-leading-slash relative paths without `:`, `\`, or control characters.
 */
export function sanitizeRedirectPath(
  raw: string | null | undefined,
  fallback = '/dashboard',
): string {
  if (!raw || typeof raw !== 'string') {
    return fallback
  }

  const trimmed = raw.trim()
  if (
    !SINGLE_LEADING_SLASH_RE.test(trimmed) ||
    trimmed.includes(':') ||
    trimmed.includes('\\') ||
    CONTROL_CHARS_RE.test(trimmed)
  ) {
    return fallback
  }

  return trimmed
}
