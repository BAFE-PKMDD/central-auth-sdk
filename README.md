# @bafe-pkmdd/central-auth-sdk

A framework-agnostic JavaScript/TypeScript SDK for applications integrating with **Central Auth** — the centralized authentication service.

This SDK provides:

- **Client SDK** — Token storage, JWT decode, and automatic refresh flow (works with React, Vue, Svelte, vanilla JS, etc.)
- **Server SDK** — JWT verification via JWKS and token refresh proxy helpers (works with Express, Fastify, Hono, Koa, etc.)

---

## Installation

```bash
# npm
npm install @bafe-pkmdd/central-auth-sdk

# bun
bun add @bafe-pkmdd/central-auth-sdk

# yarn
yarn add @bafe-pkmdd/central-auth-sdk

# pnpm
pnpm add @bafe-pkmdd/central-auth-sdk
```

---

## Prerequisites

Before using this SDK, you need:

1. A running **Central Auth** instance
2. A registered **application** in Central Auth with:
   - A `CLIENT_ID`
   - A `CLIENT_SECRET` (server-side only)
   - An allowed **redirect URI** (e.g., `http://localhost:5173/callback`)

---

## Environment Variables

Set these environment variables in your **server** application. Never expose these to the browser.

| Variable | Description | Example |
|---|---|---|
| `CENTRAL_AUTH_URL` | Full URL of the Central Auth instance | `https://auth.example.com` |
| `CLIENT_ID` | OAuth client ID from Central Auth app registration | `myapp_abc123def456` |
| `CLIENT_SECRET` | OAuth client secret (⚠️ **server-side only**) | `sk_live_...` |

For local development, your `.env` file should look like:

```env
CENTRAL_AUTH_URL=http://localhost:3000
CLIENT_ID=myapp_abc123def456
CLIENT_SECRET=your_client_secret_here
```

> **⚠️ Security Note:** `CLIENT_SECRET` must NEVER be exposed to the browser. The SDK's architecture enforces this by having the client call your server's refresh proxy, which attaches the secret server-side.

---

## Quick Start

### 1. Set up the server (token verification + refresh proxy)

```ts
// server.ts — works with any framework (Express, Fastify, Hono, etc.)
import {
  verifyAccessToken,
  extractBearerToken,
  proxyTokenRefresh,
} from '@bafe-pkmdd/central-auth-sdk/server'

// ─── Token Refresh Proxy ────────────────────────────────
// This endpoint keeps CLIENT_SECRET server-side.
// The browser sends only the refresh_token.

// Express example:
app.post('/auth/refresh', async (req, res) => {
  try {
    const result = await proxyTokenRefresh({
      centralAuthUrl: process.env.CENTRAL_AUTH_URL!,
      clientId: process.env.CLIENT_ID!,
      clientSecret: process.env.CLIENT_SECRET!,
      refreshToken: req.body.refresh_token,
    })
    res.json(result)
  } catch (err) {
    res.status(401).json({ error: err.message })
  }
})

// ─── JWT Verification Middleware ─────────────────────────
// Protects your API routes by verifying JWTs against Central Auth's JWKS.

app.use('/api', async (req, res, next) => {
  const token = extractBearerToken(req.headers.authorization)

  if (!token) {
    return res.status(401).json({ error: 'Missing Authorization header' })
  }

  const result = await verifyAccessToken(token, {
    centralAuthUrl: process.env.CENTRAL_AUTH_URL!,
  })

  if (!result.success) {
    const status = result.isExpired ? 401 : 403
    return res.status(status).json({
      error: result.error,
      isExpired: result.isExpired,
    })
  }

  // result.payload is typed as JWTPayload
  req.user = result.payload
  next()
})
```

### 2. Set up the client (token storage + refresh flow)

```ts
// auth.ts — works with any frontend framework
import {
  setToken,
  setRefreshToken,
  setTokenExpiry,
  getToken,
  getTokenTtl,
  removeTokens,
  decodeToken,
  isAuthenticated,
  createRefreshFlow,
} from '@bafe-pkmdd/central-auth-sdk/client'

// Create the refresh flow once at app level
export const auth = createRefreshFlow({
  // URL of YOUR server's refresh proxy (not Central Auth directly)
  refreshEndpoint: 'http://localhost:4000/auth/refresh',
  // Central Auth instance URL (used for logout redirect)
  centralAuthUrl: 'https://auth.example.com',
  // Your app's client ID from Central Auth
  clientId: 'myapp_abc123',
  // Optional: how many seconds before expiry to refresh (default: 30)
  refreshBufferSeconds: 30,
  // Called when auto-refresh fails (e.g. refresh token revoked)
  onLogout: () => {
    window.location.href = '/login'
  },
})
```

### 3. Handle the OAuth callback

After the user logs in via Central Auth, they're redirected back to your app with `token` and `refresh_token` in the URL query parameters.

```ts
// callback handler — works with any router
function handleCallback() {
  const params = new URLSearchParams(window.location.search)
  const token = params.get('token')
  const refreshToken = params.get('refresh_token')

  if (token) {
    // Store tokens
    setToken(token)

    if (refreshToken) {
      setRefreshToken(refreshToken)
      const ttl = getTokenTtl(token)
      setTokenExpiry(ttl)
      auth.schedule(ttl) // Start proactive refresh timer
    }

    // Decode user info from JWT (no verification — display only)
    const user = decodeToken(token)
    console.log('Logged in as:', user?.email)

    // Redirect to dashboard
    window.history.replaceState({}, '', '/dashboard')
  }
}
```

### 4. Initialize on page load

```ts
// main.ts or App entry point
if (isAuthenticated()) {
  auth.init() // Resumes refresh timer or refreshes if expired
}
```

### 5. Logout

```ts
function handleLogout() {
  // Full logout: stops timer, clears tokens, revokes refresh token,
  // signs out central-auth session, then redirects back.
  auth.logout()

  // Optionally specify where to redirect after logout:
  // auth.logout('https://myapp.com/goodbye')
}
```

---

## API Reference

### Client SDK (`@bafe-pkmdd/central-auth-sdk/client`)

#### Token Storage

| Function | Signature | Description |
|---|---|---|
| `configureStorage` | `(prefix: string) => void` | Set a custom localStorage key prefix (default: `central_auth`) |
| `getToken` | `() => string \| null` | Retrieve stored access token |
| `setToken` | `(token: string) => void` | Store access token |
| `getRefreshToken` | `() => string \| null` | Retrieve stored refresh token |
| `setRefreshToken` | `(token: string) => void` | Store refresh token |
| `setTokenExpiry` | `(expiresIn: number) => void` | Store expiry time (seconds from now) |
| `getTokenExpiry` | `() => number` | Get stored expiry (Unix ms timestamp) |
| `removeTokens` | `() => void` | Clear all auth data from localStorage |
| `isAuthenticated` | `() => boolean` | Returns `true` if an access token exists |

#### JWT Decode

| Function | Signature | Description |
|---|---|---|
| `decodeToken` | `(token: string) => Record<string, unknown> \| null` | Decode JWT payload (⚠️ no verification, display only) |
| `getTokenTtl` | `(token: string) => number` | Seconds remaining until token expiry |

#### Refresh Flow

| Function | Signature | Description |
|---|---|---|
| `createRefreshFlow` | `(config: RefreshFlowConfig) => RefreshFlowInstance` | Create a managed refresh flow |

**`RefreshFlowConfig`**:

```ts
{
  refreshEndpoint: string       // URL of your server's refresh proxy
  centralAuthUrl: string        // Central Auth instance URL (for logout redirect)
  clientId: string              // OAuth client ID (passed to logout redirect)
  refreshBufferSeconds?: number // Seconds before expiry to refresh (default: 30)
  onLogout?: () => void         // Called when auto-refresh fails
}
```

**Returned instance methods**:

| Method | Description |
|---|---|
| `refresh()` | Manually trigger a token refresh. Returns `Promise<boolean>`. |
| `schedule(expiresIn)` | Schedule the next refresh `expiresIn` seconds from now. |
| `init()` | Initialize on page load — refreshes immediately if expired, or schedules if valid. |
| `stop()` | Stop the auto-refresh timer. |
| `logout(redirectTo?)` | Full logout: stops timer, clears tokens, and redirects to Central Auth to revoke the session. |

---

### Server SDK (`@bafe-pkmdd/central-auth-sdk/server`)

#### JWKS

| Function | Signature | Description |
|---|---|---|
| `createJWKS` | `(centralAuthUrl: string) => JWKSKeySet` | Create a JWKS remote key set for JWT verification |

#### Token Verification

| Function | Signature | Description |
|---|---|---|
| `extractBearerToken` | `(authHeader?: string \| null) => string \| null` | Extract JWT from `Authorization: Bearer ...` header |
| `verifyAccessToken` | `(token: string, config: VerifyTokenConfig) => Promise<VerifyTokenResult>` | Verify JWT against Central Auth JWKS |

**`VerifyTokenConfig`**:

```ts
{
  centralAuthUrl: string           // Central Auth instance URL
  jwks?: JWKSKeySet                // Optional pre-created JWKS (for caching)
}
```

**`VerifyTokenResult`** (discriminated union):

```ts
// Success
{ success: true, payload: JWTPayload }

// Failure
{ success: false, error: string, isExpired: boolean }
```

#### Token Refresh Proxy

| Function | Signature | Description |
|---|---|---|
| `proxyTokenRefresh` | `(config: TokenRefreshProxyConfig) => Promise<TokenRefreshResponse>` | Proxy a refresh request to Central Auth (keeps secrets server-side) |

**`TokenRefreshProxyConfig`**:

```ts
{
  centralAuthUrl: string   // Central Auth instance URL
  clientId: string         // OAuth client ID
  clientSecret: string     // OAuth client secret (SERVER-SIDE ONLY)
  refreshToken: string     // Refresh token from the client
}
```

**`TokenRefreshResponse`**:

```ts
{
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}
```

#### Token Revoke Proxy

| Function | Signature | Description |
|---|---|---|
| `proxyTokenRevoke` | `(config: TokenRevokeProxyConfig) => Promise<{ success: boolean }>` | Revoke a refresh token on Central Auth (server-to-server) |

**`TokenRevokeProxyConfig`**:

```ts
{
  centralAuthUrl: string   // Central Auth instance URL
  clientId: string         // OAuth client ID
  clientSecret: string     // OAuth client secret (SERVER-SIDE ONLY)
  refreshToken: string     // Refresh token to revoke
}
```

---

### Shared Types (`@bafe-pkmdd/central-auth-sdk`)

**`JWTPayload`** — Central Auth JWT claims:

```ts
{
  sub: string                    // User ID
  email: string                  // User email
  name: string                   // Display name
  role?: string                  // Global role
  activeOrganizationId?: string  // Active org context
  appRole?: {                    // App-specific RBAC role
    name: string
    color: string | null
  } | null
  permissions?: string[]         // Flat permission list (e.g. "project:read")
  exp?: number                   // Expiry (Unix seconds)
  iat?: number                   // Issued-at (Unix seconds)
}
```

---

## Framework Examples

### Express.js

```ts
import express from 'express'
import { verifyAccessToken, extractBearerToken, proxyTokenRefresh } from '@bafe-pkmdd/central-auth-sdk/server'

const app = express()
app.use(express.json())

app.post('/auth/refresh', async (req, res) => {
  try {
    const result = await proxyTokenRefresh({
      centralAuthUrl: process.env.CENTRAL_AUTH_URL!,
      clientId: process.env.CLIENT_ID!,
      clientSecret: process.env.CLIENT_SECRET!,
      refreshToken: req.body.refresh_token,
    })
    res.json(result)
  } catch (err) {
    res.status(401).json({ error: (err as Error).message })
  }
})

app.use('/api', async (req, res, next) => {
  const token = extractBearerToken(req.headers.authorization)
  if (!token) return res.status(401).json({ error: 'Unauthorized' })

  const result = await verifyAccessToken(token, {
    centralAuthUrl: process.env.CENTRAL_AUTH_URL!,
  })
  if (!result.success) return res.status(401).json({ error: result.error })

  req.user = result.payload
  next()
})

app.get('/api/me', (req, res) => {
  res.json({ user: req.user })
})
```

### Hono

```ts
import { Hono } from 'hono'
import { verifyAccessToken, extractBearerToken, proxyTokenRefresh } from '@bafe-pkmdd/central-auth-sdk/server'

const app = new Hono()

app.post('/auth/refresh', async (c) => {
  const body = await c.req.json()
  try {
    const result = await proxyTokenRefresh({
      centralAuthUrl: process.env.CENTRAL_AUTH_URL!,
      clientId: process.env.CLIENT_ID!,
      clientSecret: process.env.CLIENT_SECRET!,
      refreshToken: body.refresh_token,
    })
    return c.json(result)
  } catch (err) {
    return c.json({ error: (err as Error).message }, 401)
  }
})

app.use('/api/*', async (c, next) => {
  const token = extractBearerToken(c.req.header('Authorization'))
  if (!token) return c.json({ error: 'Unauthorized' }, 401)

  const result = await verifyAccessToken(token, {
    centralAuthUrl: process.env.CENTRAL_AUTH_URL!,
  })
  if (!result.success) return c.json({ error: result.error }, 401)

  c.set('user', result.payload)
  await next()
})
```

### Fastify

```ts
import Fastify from 'fastify'
import { verifyAccessToken, extractBearerToken, proxyTokenRefresh } from '@bafe-pkmdd/central-auth-sdk/server'

const fastify = Fastify()

fastify.post('/auth/refresh', async (request, reply) => {
  try {
    const result = await proxyTokenRefresh({
      centralAuthUrl: process.env.CENTRAL_AUTH_URL!,
      clientId: process.env.CLIENT_ID!,
      clientSecret: process.env.CLIENT_SECRET!,
      refreshToken: (request.body as any).refresh_token,
    })
    return result
  } catch (err) {
    reply.code(401).send({ error: (err as Error).message })
  }
})

fastify.addHook('onRequest', async (request, reply) => {
  if (!request.url.startsWith('/api')) return

  const token = extractBearerToken(request.headers.authorization)
  if (!token) return reply.code(401).send({ error: 'Unauthorized' })

  const result = await verifyAccessToken(token, {
    centralAuthUrl: process.env.CENTRAL_AUTH_URL!,
  })
  if (!result.success) return reply.code(401).send({ error: result.error })

  request.user = result.payload
})
```

### React (Client)

```tsx
import { useEffect, useState } from 'react'
import {
  setToken, setRefreshToken, setTokenExpiry,
  getToken, getTokenTtl, removeTokens,
  decodeToken, isAuthenticated, createRefreshFlow,
} from '@bafe-pkmdd/central-auth-sdk/client'

const CENTRAL_AUTH_URL = 'https://auth.example.com'
const CLIENT_ID = 'myapp_abc123'
const CALLBACK_URL = 'http://localhost:5173/callback'

const auth = createRefreshFlow({
  refreshEndpoint: '/auth/refresh',
  centralAuthUrl: CENTRAL_AUTH_URL,
  clientId: CLIENT_ID,
  onLogout: () => { window.location.href = '/' },
})

function App() {
  const [user, setUser] = useState(null)

  useEffect(() => {
    // Handle OAuth callback
    if (window.location.pathname === '/callback') {
      const params = new URLSearchParams(window.location.search)
      const token = params.get('token')
      const refreshToken = params.get('refresh_token')

      if (token) {
        setToken(token)
        if (refreshToken) {
          setRefreshToken(refreshToken)
          const ttl = getTokenTtl(token)
          setTokenExpiry(ttl)
          auth.schedule(ttl)
        }
        setUser(decodeToken(token))
        window.history.replaceState({}, '', '/dashboard')
      }
      return
    }

    // Resume session on page load
    if (isAuthenticated()) {
      setUser(decodeToken(getToken()!))
      auth.init()
    }
  }, [])

  const handleLogin = () => {
    window.location.href =
      `${CENTRAL_AUTH_URL}/auth/login?client_id=${CLIENT_ID}&redirect_to=${encodeURIComponent(CALLBACK_URL)}`
  }

  const handleLogout = () => {
    auth.logout()
  }

  // ... render your app
}
```

### Vue (Client)

```ts
// composables/use-auth.ts
import {
  setToken, setRefreshToken, setTokenExpiry,
  getToken, getTokenTtl, removeTokens,
  decodeToken, isAuthenticated, createRefreshFlow,
} from '@bafe-pkmdd/central-auth-sdk/client'
import { ref, onMounted } from 'vue'

const auth = createRefreshFlow({
  refreshEndpoint: '/auth/refresh',
  centralAuthUrl: import.meta.env.VITE_CENTRAL_AUTH_URL,
  clientId: import.meta.env.VITE_CLIENT_ID,
  onLogout: () => { window.location.href = '/login' },
})

export function useAuth() {
  const user = ref(null)

  onMounted(() => {
    if (isAuthenticated()) {
      user.value = decodeToken(getToken()!)
      auth.init()
    }
  })

  function login(centralAuthUrl: string, clientId: string, callbackUrl: string) {
    window.location.href =
      `${centralAuthUrl}/auth/login?client_id=${clientId}&redirect_to=${encodeURIComponent(callbackUrl)}`
  }

  function logout() {
    auth.logout()
  }

  return { user, login, logout, auth }
}
```

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Browser (React / Vue / Svelte / Vanilla)        │
│                                                  │
│  @bafe-pkmdd/central-auth-sdk/client                   │
│  ┌────────────────┐  ┌─────────────────────────┐ │
│  │ Token Storage   │  │ Refresh Flow            │ │
│  │ (localStorage)  │  │ (auto-refresh timer)    │ │
│  └────────────────┘  └────────┬────────────────┘ │
│                               │ POST /auth/refresh│
└───────────────────────────────┼──────────────────┘
                                │
┌───────────────────────────────▼──────────────────┐
│  Your Backend (Express / Hono / Fastify / etc.)  │
│                                                  │
│  @bafe-pkmdd/central-auth-sdk/server                   │
│  ┌─────────────────────┐  ┌────────────────────┐ │
│  │ proxyTokenRefresh() │  │ verifyAccessToken() │ │
│  │ (attaches secret)   │  │ (JWKS verification) │ │
│  └─────────┬───────────┘  └──────────┬─────────┘ │
│            │                         │            │
└────────────┼─────────────────────────┼────────────┘
             │                         │
┌────────────▼─────────────────────────▼────────────┐
│         Central Auth Service                       │
│  POST /api/token/refresh    GET /api/auth/jwks     │
└────────────────────────────────────────────────────┘
```

---

## License

MIT
