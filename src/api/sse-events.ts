/**
 * SSE (Server-Sent Events) real-time push for analysis progress.
 *
 * Provides an EventBus singleton that tools can publish events to,
 * and an SSE endpoint handler that streams those events to connected clients.
 *
 * Endpoint: GET /api/v1/events?stream=<stream_id>
 */

import type { IncomingMessage, ServerResponse } from 'http'
import { EventEmitter } from 'events'
import { logger } from '../logger.js'

// ═══════════════════════════════════════════════════════════════════════════
// Event Types
// ═══════════════════════════════════════════════════════════════════════════

export interface AnalysisEvent {
  type: 'progress' | 'result' | 'error' | 'status' | 'heartbeat'
  stream: string
  timestamp: string
  payload: unknown
}

// ═══════════════════════════════════════════════════════════════════════════
// EventBus — global pub/sub for analysis events
// ═══════════════════════════════════════════════════════════════════════════

class AnalysisEventBus extends EventEmitter {
  private static instance: AnalysisEventBus | null = null

  static getInstance(): AnalysisEventBus {
    if (!AnalysisEventBus.instance) {
      AnalysisEventBus.instance = new AnalysisEventBus()
      AnalysisEventBus.instance.setMaxListeners(200)
    }
    return AnalysisEventBus.instance
  }

  /** Publish an event to a specific stream (e.g. sample_id or batch_id). */
  publish(stream: string, type: AnalysisEvent['type'], payload: unknown): void {
    const event: AnalysisEvent = {
      type,
      stream,
      timestamp: new Date().toISOString(),
      payload,
    }
    this.emit('event', event)
    this.emit(`event:${stream}`, event)
  }
}

export const eventBus = AnalysisEventBus.getInstance()

// ═══════════════════════════════════════════════════════════════════════════
// SSE Handler — streams events to HTTP clients
// ═══════════════════════════════════════════════════════════════════════════

interface SseClient {
  res: ServerResponse
  stream: string | null
  heartbeatTimer: NodeJS.Timeout
}

const clients = new Set<SseClient>()

/**
 * Handle an SSE connection request.
 * Query params:
 *   - stream: (optional) filter events by stream ID (e.g. sample_id)
 */
export function handleSseConnection(req: IncomingMessage, res: ServerResponse, searchParams: URLSearchParams): void {
  const stream = searchParams.get('stream') || null

  // SSE headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
    'X-Accel-Buffering': 'no',
  })

  // Send initial connection event
  sendSseEvent(res, 'connected', { stream, timestamp: new Date().toISOString() })

  // Heartbeat every 30s to keep connection alive
  const heartbeatTimer = setInterval(() => {
    if (res.writableEnded) {
      clearInterval(heartbeatTimer)
      return
    }
    sendSseEvent(res, 'heartbeat', { timestamp: new Date().toISOString() })
  }, 30_000)

  const client: SseClient = { res, stream, heartbeatTimer }
  clients.add(client)

  // Listen for events
  const eventHandler = (event: AnalysisEvent) => {
    if (res.writableEnded) return
    if (stream && event.stream !== stream) return
    sendSseEvent(res, event.type, event)
  }

  eventBus.on('event', eventHandler)

  // Cleanup on disconnect
  const cleanup = () => {
    clearInterval(heartbeatTimer)
    clients.delete(client)
    eventBus.off('event', eventHandler)
    logger.debug({ stream }, 'SSE client disconnected')
  }

  req.on('close', cleanup)
  req.on('error', cleanup)

  logger.debug({ stream, totalClients: clients.size }, 'SSE client connected')
}

function sendSseEvent(res: ServerResponse, event: string, data: unknown): void {
  if (res.writableEnded) return
  try {
    res.write(`event: ${event}\n`)
    res.write(`data: ${JSON.stringify(data)}\n\n`)
  } catch {
    // Client may have disconnected
  }
}

/**
 * Get the count of active SSE connections.
 */
export function getActiveSseClients(): number {
  // Prune dead connections
  for (const client of clients) {
    if (client.res.writableEnded) {
      clearInterval(client.heartbeatTimer)
      clients.delete(client)
    }
  }
  return clients.size
}
