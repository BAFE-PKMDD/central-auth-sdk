import type {
  SessionEventPayload,
  SessionEventStore,
  SessionEventStoreConfig,
} from './types'

type SSEController = ReadableStreamDefaultController<Uint8Array>

const encoder = new TextEncoder()

/**
 * Create a distributed SSE connection registry backed by Redis Pub/Sub.
 * Coordinates back-channel logout notifications across Next.js instances.
 */
export function createSessionEventStore(
  config: SessionEventStoreConfig,
): SessionEventStore {
  const {
    redisPub,
    redisSub,
    channel = 'session_events',
    isProduction = false,
  } = config

  const connections = new Map<string, Set<SSEController>>()
  let initialized = false
  let listenersAttached = false

  function handleRedisMessage(payload: SessionEventPayload): void {
    const { type, userId, tokenHash } = payload
    const userConnections = connections.get(userId)
    if (!userConnections || userConnections.size === 0) return

    const frame =
      type === 'token_logout' && tokenHash
        ? `event: token_logout\ndata: ${JSON.stringify({ token_hash: tokenHash })}\n\n`
        : 'event: logout\ndata: {}\n\n'
    const bytes = encoder.encode(frame)

    let notified = 0
    for (const controller of Array.from(userConnections)) {
      try {
        controller.enqueue(bytes)
        notified += 1
      } catch {
        userConnections.delete(controller)
      }
    }

    if (!isProduction) {
      console.log(
        `[SessionEvents:Sub] Relayed ${type} to ${notified} local socket(s) for ${userId}`,
      )
    }

    if (userConnections.size === 0) {
      connections.delete(userId)
    }
  }

  async function subscribeChannel(): Promise<void> {
    try {
      await redisSub.subscribe(channel)
      if (!isProduction) {
        console.log(`[SessionEvents] Redis subscribed to ${channel}`)
      }
    } catch (err) {
      if (!isProduction) {
        console.warn('[SessionEvents] Redis subscribe error:', err)
      }
    }
  }

  async function init(): Promise<void> {
    if (initialized) return
    initialized = true

    if (!listenersAttached) {
      listenersAttached = true
      redisSub.on('ready', () => {
        void subscribeChannel()
      })
      redisSub.on('message', (msgChannel, message) => {
        if (msgChannel !== channel) return
        try {
          const parsed = JSON.parse(message) as SessionEventPayload
          if (
            parsed &&
            typeof parsed.userId === 'string' &&
            (parsed.type === 'logout' || parsed.type === 'token_logout')
          ) {
            handleRedisMessage(parsed)
          }
        } catch (err) {
          console.error('[SessionEvents] Invalid redis message:', err)
        }
      })
    }

    try {
      if (redisSub.status === 'wait' && typeof redisSub.connect === 'function') {
        await redisSub.connect().catch((err: unknown) => {
          if (!isProduction) {
            const msg = err instanceof Error ? err.message : String(err)
            console.warn('[SessionEvents] Redis lazy connect deferred:', msg)
          }
        })
      }
      if (!redisSub.status || redisSub.status === 'ready') {
        await subscribeChannel()
      }
    } catch (err) {
      if (!isProduction) {
        console.warn('[SessionEvents] Redis init error:', err)
      }
    }
  }

  function addConnection(userId: string, controller: SSEController): void {
    let set = connections.get(userId)
    if (!set) {
      set = new Set()
      connections.set(userId, set)
    }
    set.add(controller)
  }

  function removeConnection(userId: string, controller: SSEController): void {
    const userConnections = connections.get(userId)
    if (!userConnections) return
    userConnections.delete(controller)
    if (userConnections.size === 0) {
      connections.delete(userId)
    }
  }

  function pushLogout(userId: string): number {
    Promise.resolve(
      redisPub.publish(channel, JSON.stringify({ type: 'logout', userId })),
    ).catch((err) => {
      console.error('[SessionEvents] Redis publish logout error:', err)
    })
    return 1
  }

  function pushTokenLogout(userId: string, tokenHash: string): number {
    Promise.resolve(
      redisPub.publish(
        channel,
        JSON.stringify({ type: 'token_logout', userId, tokenHash }),
      ),
    ).catch((err) => {
      console.error('[SessionEvents] Redis publish token_logout error:', err)
    })
    return 1
  }

  return {
    init,
    addConnection,
    removeConnection,
    pushLogout,
    pushTokenLogout,
  }
}

export type CreateSseStreamResponseOptions = {
  store: SessionEventStore
  userId: string
  tokenHash?: string | null
  signal?: AbortSignal
  heartbeatIntervalMs?: number
}

/**
 * Build an SSE Response stream bound to a `SessionEventStore` with automatic
 * heartbeat frames and disconnect/abort cleanup.
 */
export function createSseStreamResponse(
  options: CreateSseStreamResponseOptions,
): Response {
  const {
    store,
    userId,
    tokenHash = null,
    signal,
    heartbeatIntervalMs = 30_000,
  } = options

  let heartbeat: ReturnType<typeof setInterval> | undefined
  let controllerRef: SSEController | undefined

  const cleanup = () => {
    if (heartbeat !== undefined) {
      clearInterval(heartbeat)
      heartbeat = undefined
    }
    if (controllerRef) {
      store.removeConnection(userId, controllerRef)
    }
  }

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controllerRef = controller
      store.addConnection(userId, controller)

      controller.enqueue(
        encoder.encode(
          `event: connected\ndata: ${JSON.stringify({ status: 'ok', token_hash: tokenHash })}\n\n`,
        ),
      )

      heartbeat = setInterval(() => {
        try {
          controller.enqueue(encoder.encode(': heartbeat\n\n'))
        } catch {
          cleanup()
        }
      }, heartbeatIntervalMs)

      signal?.addEventListener('abort', cleanup, { once: true })
    },
    cancel() {
      cleanup()
    },
  })

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  })
}
