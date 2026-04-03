/**
 * Debug session state manager — tracks active GDB debug sessions.
 */

import { randomUUID } from 'crypto'
import { GdbMiClient } from './gdb-mi-client.js'

export interface BreakpointInfo {
  id: string
  address?: string
  symbol?: string
  condition?: string
  hit_count: number
}

export interface SessionHistoryEntry {
  timestamp: string
  action: string
  detail: Record<string, unknown>
}

export interface DebugSession {
  id: string
  sampleId: string
  gdb: GdbMiClient
  breakpoints: BreakpointInfo[]
  history: SessionHistoryEntry[]
  createdAt: Date
  lastActivity: Date
}

const MAX_CONCURRENT_SESSIONS = 3
const IDLE_TIMEOUT_MS = 10 * 60 * 1000 // 10 minutes

export class DebugSessionManager {
  private sessions = new Map<string, DebugSession>()
  private cleanupTimer: ReturnType<typeof setInterval> | null = null

  constructor() {
    this.cleanupTimer = setInterval(() => this.sweepIdleSessions(), 60_000)
  }

  get activeCount(): number {
    return this.sessions.size
  }

  getSession(id: string): DebugSession | undefined {
    return this.sessions.get(id)
  }

  listSessions(): Array<{
    id: string
    sampleId: string
    createdAt: string
    lastActivity: string
    breakpoints: number
  }> {
    return [...this.sessions.values()].map((s) => ({
      id: s.id,
      sampleId: s.sampleId,
      createdAt: s.createdAt.toISOString(),
      lastActivity: s.lastActivity.toISOString(),
      breakpoints: s.breakpoints.length,
    }))
  }

  async createSession(sampleId: string, binaryPath: string, gdbPath?: string, useWine = false): Promise<DebugSession> {
    if (this.sessions.size >= MAX_CONCURRENT_SESSIONS) {
      throw new Error(
        `Maximum concurrent debug sessions reached (${MAX_CONCURRENT_SESSIONS}). End an existing session first.`
      )
    }

    const gdb = new GdbMiClient()
    const extraArgs = useWine ? [] : []
    const effectiveBinary = useWine ? binaryPath : binaryPath
    const effectiveGdb = gdbPath || 'gdb'

    await gdb.start(effectiveBinary, effectiveGdb, extraArgs)

    const session: DebugSession = {
      id: randomUUID(),
      sampleId,
      gdb,
      breakpoints: [],
      history: [],
      createdAt: new Date(),
      lastActivity: new Date(),
    }

    this.sessions.set(session.id, session)

    session.history.push({
      timestamp: new Date().toISOString(),
      action: 'session_start',
      detail: { binary_path: binaryPath, gdb_path: effectiveGdb, use_wine: useWine },
    })

    return session
  }

  async endSession(id: string): Promise<SessionHistoryEntry[]> {
    const session = this.sessions.get(id)
    if (!session) throw new Error(`Session not found: ${id}`)

    session.history.push({
      timestamp: new Date().toISOString(),
      action: 'session_end',
      detail: { breakpoints_at_end: session.breakpoints.length },
    })

    session.gdb.kill()
    const history = [...session.history]
    this.sessions.delete(id)
    return history
  }

  touch(id: string): void {
    const session = this.sessions.get(id)
    if (session) {
      session.lastActivity = new Date()
    }
  }

  private sweepIdleSessions(): void {
    const now = Date.now()
    for (const [id, session] of this.sessions) {
      if (now - session.lastActivity.getTime() > IDLE_TIMEOUT_MS) {
        session.gdb.kill()
        this.sessions.delete(id)
      }
    }
  }

  dispose(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer)
      this.cleanupTimer = null
    }
    for (const [, session] of this.sessions) {
      session.gdb.kill()
    }
    this.sessions.clear()
  }
}

// Singleton instance
let _instance: DebugSessionManager | null = null

export function getDebugSessionManager(): DebugSessionManager {
  if (!_instance) {
    _instance = new DebugSessionManager()
  }
  return _instance
}
