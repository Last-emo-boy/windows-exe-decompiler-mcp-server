/**
 * Dashboard API — serves JSON data for the web dashboard.
 *
 * Endpoints:
 *   GET /api/v1/dashboard/overview  — server overview (uptime, version, tool/plugin counts)
 *   GET /api/v1/dashboard/tools     — full tool listing with categories
 *   GET /api/v1/dashboard/plugins   — plugin statuses
 *   GET /api/v1/dashboard/samples   — recent samples
 *   GET /api/v1/dashboard/workers   — worker pool stats
 *   GET /api/v1/dashboard/config    — config diagnostics
 */

import type { ServerResponse } from 'http'
import os from 'os'
import type { DatabaseManager } from '../../database.js'
import type { MCPServer } from '../../server.js'
import { getPluginManager } from '../../plugins.js'
import { validateConfig, type ValidationReport } from '../../config-validator.js'
import { config } from '../../config.js'
import { getActiveSseClients } from '../sse-events.js'
import { logger } from '../../logger.js'

const SERVER_START_TIME = Date.now()

export interface DashboardDeps {
  server: MCPServer | null
  database: DatabaseManager
}

let _deps: DashboardDeps | null = null

export function initDashboard(deps: DashboardDeps): void {
  _deps = deps
}

function sendJson(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(data))
}

// ══════════════════════════════════════════════════════════════════════════
// Route handler
// ══════════════════════════════════════════════════════════════════════════

export function handleDashboardApi(
  res: ServerResponse,
  pathname: string,
  _searchParams: URLSearchParams
): boolean {
  if (!pathname.startsWith('/api/v1/dashboard')) return false

  const route = pathname.replace('/api/v1/dashboard', '') || '/'

  switch (route) {
    case '/overview':
      handleOverview(res)
      return true
    case '/tools':
      handleTools(res)
      return true
    case '/plugins':
      handlePlugins(res)
      return true
    case '/samples':
      handleSamples(res, _searchParams)
      return true
    case '/workers':
      handleWorkers(res)
      return true
    case '/config':
      handleConfig(res)
      return true
    case '/system':
      handleSystem(res)
      return true
    default:
      sendJson(res, 404, { error: 'Dashboard route not found' })
      return true
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Individual handlers
// ══════════════════════════════════════════════════════════════════════════

function handleOverview(res: ServerResponse): void {
  const tools = _deps?.server?.getToolDefinitions() ?? []
  const prompts = _deps?.server?.getPromptDefinitions() ?? []
  let pluginMgr: ReturnType<typeof getPluginManager> | null = null
  try { pluginMgr = getPluginManager() } catch { /* not initialized */ }
  const pluginStatuses = pluginMgr?.getStatuses() ?? []

  const loaded = pluginStatuses.filter(p => p.status === 'loaded').length
  const sseClients = getActiveSseClients()

  // Query recent sample count
  let sampleCount = 0
  let recentAnalyses = 0
  try {
    const countResult = _deps?.database?.querySql<{ cnt: number }>('SELECT COUNT(*) as cnt FROM samples') ?? []
    sampleCount = countResult[0]?.cnt ?? 0

    const recentResult = _deps?.database?.querySql<{ cnt: number }>(
      `SELECT COUNT(*) as cnt FROM samples WHERE created_at > datetime('now', '-24 hours')`
    ) ?? []
    recentAnalyses = recentResult[0]?.cnt ?? 0
  } catch { /* table may not exist yet */ }

  sendJson(res, 200, {
    server: {
      version: '1.0.0-beta.2',
      uptime_seconds: Math.floor((Date.now() - SERVER_START_TIME) / 1000),
      uptime_human: formatUptime(Date.now() - SERVER_START_TIME),
      started_at: new Date(SERVER_START_TIME).toISOString(),
      node_version: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    counts: {
      tools: tools.length,
      prompts: prompts.length,
      plugins_total: pluginStatuses.length,
      plugins_loaded: loaded,
      samples: sampleCount,
      recent_analyses_24h: recentAnalyses,
      sse_clients: sseClients,
    },
    memory: {
      rss_mb: Math.round(process.memoryUsage().rss / 1024 / 1024),
      heap_used_mb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
      heap_total_mb: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
    },
  })
}

function handleTools(res: ServerResponse): void {
  const tools = _deps?.server?.getToolDefinitions() ?? []

  // Categorize tools by prefix
  const categories = new Map<string, Array<{ name: string; description: string }>>()
  for (const t of tools) {
    const dotIdx = t.name.indexOf('.')
    const category = dotIdx > 0 ? t.name.substring(0, dotIdx) : 'core'
    if (!categories.has(category)) categories.set(category, [])
    categories.get(category)!.push({ name: t.name, description: t.description })
  }

  const result = Array.from(categories.entries())
    .map(([category, items]) => ({ category, count: items.length, tools: items }))
    .sort((a, b) => b.count - a.count)

  sendJson(res, 200, { total: tools.length, categories: result })
}

function handlePlugins(res: ServerResponse): void {
  let pluginMgr: ReturnType<typeof getPluginManager> | null = null
  try { pluginMgr = getPluginManager() } catch { /* not initialized */ }

  const statuses = pluginMgr?.getStatuses() ?? []

  sendJson(res, 200, {
    total: statuses.length,
    loaded: statuses.filter(s => s.status === 'loaded').length,
    skipped: statuses.filter(s => s.status.startsWith('skipped')).length,
    errored: statuses.filter(s => s.status === 'error').length,
    plugins: statuses.map(s => ({
      id: s.id,
      name: s.name,
      version: s.version ?? null,
      description: s.description ?? null,
      status: s.status,
      tool_count: s.tools.length,
      tools: s.tools,
      error: s.error ?? null,
    })),
  })
}

function handleSamples(res: ServerResponse, params: URLSearchParams): void {
  const limit = Math.min(parseInt(params.get('limit') || '50', 10) || 50, 200)
  const offset = parseInt(params.get('offset') || '0', 10) || 0

  let samples: unknown[] = []
  let total = 0
  try {
    const countResult = _deps?.database?.querySql<{ cnt: number }>('SELECT COUNT(*) as cnt FROM samples') ?? []
    total = countResult[0]?.cnt ?? 0

    samples = _deps?.database?.querySql(
      'SELECT id, original_name, sha256, file_size, created_at FROM samples ORDER BY created_at DESC LIMIT ? OFFSET ?',
      [limit, offset]
    ) ?? []
  } catch { /* table may not exist */ }

  sendJson(res, 200, { total, offset, limit, samples })
}

function handleWorkers(res: ServerResponse): void {
  // Worker stats are not directly accessible from here, but we can expose what we have
  sendJson(res, 200, {
    pool: {
      note: 'Worker pool statistics are available when the pool is running',
    },
    process: {
      pid: process.pid,
      uptime_seconds: Math.floor(process.uptime()),
      cpu_usage: process.cpuUsage(),
    },
    system: {
      total_memory_gb: Math.round(os.totalmem() / 1024 / 1024 / 1024 * 10) / 10,
      free_memory_gb: Math.round(os.freemem() / 1024 / 1024 / 1024 * 10) / 10,
      cpus: os.cpus().length,
      load_average: os.loadavg(),
    },
  })
}

function handleConfig(res: ServerResponse): void {
  let report: ValidationReport | null = null
  try {
    report = validateConfig(config)
  } catch (err) {
    logger.warn({ err }, 'Dashboard: config validation failed')
  }

  sendJson(res, 200, {
    validation: report,
    active: {
      server_port: config.server.port,
      api_port: config.api.port,
      api_enabled: config.api.enabled,
      database_type: config.database.type,
      workspace_root: config.workspace.root,
      cache_enabled: config.cache.enabled,
      log_level: config.logging.level,
      ghidra_enabled: config.workers.ghidra.enabled,
      static_enabled: config.workers.static.enabled,
      dotnet_enabled: config.workers.dotnet.enabled,
      sandbox_enabled: config.workers.sandbox.enabled,
      frida_enabled: config.workers.frida.enabled,
    },
  })
}

function handleSystem(res: ServerResponse): void {
  sendJson(res, 200, {
    hostname: os.hostname(),
    platform: `${os.type()} ${os.release()}`,
    arch: os.arch(),
    node: process.version,
    pid: process.pid,
    cpus: os.cpus().map(c => ({ model: c.model, speed: c.speed })),
    memory: {
      total_gb: Math.round(os.totalmem() / 1024 / 1024 / 1024 * 10) / 10,
      free_gb: Math.round(os.freemem() / 1024 / 1024 / 1024 * 10) / 10,
      usage_percent: Math.round((1 - os.freemem() / os.totalmem()) * 100),
    },
    uptime_host_seconds: Math.floor(os.uptime()),
    uptime_process_seconds: Math.floor(process.uptime()),
    env: {
      NODE_ENV: process.env.NODE_ENV ?? 'development',
      LOG_LEVEL: process.env.LOG_LEVEL ?? 'info',
    },
  })
}

// ══════════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════════

function formatUptime(ms: number): string {
  const s = Math.floor(ms / 1000)
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  const parts: string[] = []
  if (d > 0) parts.push(`${d}d`)
  if (h > 0) parts.push(`${h}h`)
  if (m > 0) parts.push(`${m}m`)
  parts.push(`${sec}s`)
  return parts.join(' ')
}
