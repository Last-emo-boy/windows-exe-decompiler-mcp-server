/**
 * Dashboard API — serves JSON data for the web dashboard.
 *
 * Endpoints:
 *   GET /api/v1/dashboard/overview          — server overview (uptime, version, tool/plugin counts)
 *   GET /api/v1/dashboard/tools             — full tool listing with categories
 *   GET /api/v1/dashboard/plugins           — plugin statuses
 *   GET /api/v1/dashboard/samples           — recent samples
 *   GET /api/v1/dashboard/samples/:id       — sample detail with analyses & artifacts
 *   GET /api/v1/dashboard/analyses          — recent analyses
 *   GET /api/v1/dashboard/artifacts         — artifact listing with type/sample filter
 *   GET /api/v1/dashboard/artifacts/:id/content — artifact file content for rendering
 *   GET /api/v1/dashboard/workers           — worker pool stats
 *   GET /api/v1/dashboard/config            — config diagnostics
 *   GET /api/v1/dashboard/system            — host/process information
 */

import type { ServerResponse } from 'http'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import type { DatabaseManager } from '../../database.js'
import type { MCPServer } from '../../server.js'
import type { WorkspaceManager } from '../../workspace-manager.js'
import { getPluginManager } from '../../plugins.js'
import { validateConfig, type ValidationReport } from '../../config-validator.js'
import { config } from '../../config.js'
import { getActiveSseClients, eventBus } from '../sse-events.js'
import { logger, logRingBuffer, type LogEntry } from '../../logger.js'

const SERVER_START_TIME = Date.now()

export interface DashboardDeps {
  server: MCPServer | null
  database: DatabaseManager
  workspaceManager?: WorkspaceManager
}

let _deps: DashboardDeps | null = null

export function initDashboard(deps: DashboardDeps): void {
  _deps = deps

  // Forward new log entries to SSE stream so the dashboard can display them in real time
  logRingBuffer.onEntry((entry: LogEntry) => {
    eventBus.publish('server-logs', 'log', {
      level: entry.levelLabel,
      time: entry.time,
      msg: entry.msg,
    })
  })
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

  // Handle parameterized routes first
  const sampleDetailMatch = route.match(/^\/samples\/(.+)$/)
  if (sampleDetailMatch) {
    handleSampleDetail(res, decodeURIComponent(sampleDetailMatch[1]))
    return true
  }

  const artifactContentMatch = route.match(/^\/artifacts\/(.+)\/content$/)
  if (artifactContentMatch) {
    handleArtifactContent(res, decodeURIComponent(artifactContentMatch[1])).catch(err => {
      logger.error({ err }, 'Dashboard: artifact content handler failed')
      if (!res.writableEnded) {
        sendJson(res, 500, { error: 'Internal error reading artifact' })
      }
    })
    return true
  }

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
    case '/analyses':
      handleAnalyses(res, _searchParams)
      return true
    case '/artifacts':
      handleArtifacts(res, _searchParams)
      return true
    case '/workers':
      handleWorkers(res)
      return true
    case '/config':
      handleConfig(res)
      return true
    case '/logs':
      handleLogs(res, _searchParams)
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
      'SELECT id, sha256, size, file_type, source, created_at FROM samples ORDER BY created_at DESC LIMIT ? OFFSET ?',
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

// ── Logs ────────────────────────────────────────────────────────────────

const LEVEL_NAME_TO_NUM: Record<string, number> = {
  trace: 10, debug: 20, info: 30, warn: 40, error: 50, fatal: 60,
}

function handleLogs(res: ServerResponse, params: URLSearchParams): void {
  const limit = Math.min(parseInt(params.get('limit') || '100', 10) || 100, 500)
  const levelParam = params.get('level')?.toLowerCase()
  const minLevel = levelParam ? (LEVEL_NAME_TO_NUM[levelParam] ?? undefined) : undefined

  const entries = logRingBuffer.getRecent(limit, minLevel)
  sendJson(res, 200, { logs: entries, total: entries.length })
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
// Sample detail
// ══════════════════════════════════════════════════════════════════════════

function handleSampleDetail(res: ServerResponse, sampleId: string): void {
  try {
    const sample = _deps?.database?.findSample(sampleId)
    if (!sample) {
      sendJson(res, 404, { error: 'Sample not found' })
      return
    }

    const analyses = _deps?.database?.querySql<{
      id: string; stage: string; backend: string; status: string;
      started_at: string | null; finished_at: string | null
    }>(
      'SELECT id, stage, backend, status, started_at, finished_at FROM analyses WHERE sample_id = ? ORDER BY started_at DESC',
      [sampleId]
    ) ?? []

    const artifacts = _deps?.database?.querySql<{
      id: string; type: string; path: string; mime: string | null; created_at: string
    }>(
      'SELECT id, type, path, mime, created_at FROM artifacts WHERE sample_id = ? ORDER BY created_at DESC',
      [sampleId]
    ) ?? []

    const functions = _deps?.database?.querySql<{
      address: string; name: string | null; size: number | null; score: number | null
    }>(
      'SELECT address, name, size, score FROM functions WHERE sample_id = ? ORDER BY score DESC LIMIT 20',
      [sampleId]
    ) ?? []

    const functionCount = _deps?.database?.querySql<{ cnt: number }>(
      'SELECT COUNT(*) as cnt FROM functions WHERE sample_id = ?', [sampleId]
    ) ?? []

    sendJson(res, 200, {
      sample,
      analyses,
      artifacts,
      functions: { top: functions, total: functionCount[0]?.cnt ?? 0 },
    })
  } catch {
    sendJson(res, 500, { error: 'Failed to load sample detail' })
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Analyses listing
// ══════════════════════════════════════════════════════════════════════════

function handleAnalyses(res: ServerResponse, params: URLSearchParams): void {
  const limit = Math.min(parseInt(params.get('limit') || '50', 10) || 50, 200)
  const offset = parseInt(params.get('offset') || '0', 10) || 0
  const sampleId = params.get('sample_id')
  const status = params.get('status')

  try {
    let where = ''
    const sqlParams: unknown[] = []
    const clauses: string[] = []
    if (sampleId) { clauses.push('sample_id = ?'); sqlParams.push(sampleId) }
    if (status) { clauses.push('status = ?'); sqlParams.push(status) }
    if (clauses.length) where = ' WHERE ' + clauses.join(' AND ')

    const countResult = _deps?.database?.querySql<{ cnt: number }>(
      `SELECT COUNT(*) as cnt FROM analyses${where}`, sqlParams
    ) ?? []
    const total = countResult[0]?.cnt ?? 0

    const analyses = _deps?.database?.querySql(
      `SELECT id, sample_id, stage, backend, status, started_at, finished_at FROM analyses${where} ORDER BY started_at DESC LIMIT ? OFFSET ?`,
      [...sqlParams, limit, offset]
    ) ?? []

    sendJson(res, 200, { total, offset, limit, analyses })
  } catch {
    sendJson(res, 200, { total: 0, offset, limit, analyses: [] })
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Artifacts listing
// ══════════════════════════════════════════════════════════════════════════

function handleArtifacts(res: ServerResponse, params: URLSearchParams): void {
  const limit = Math.min(parseInt(params.get('limit') || '50', 10) || 50, 200)
  const offset = parseInt(params.get('offset') || '0', 10) || 0
  const sampleId = params.get('sample_id')
  const type = params.get('type')

  try {
    let where = ''
    const sqlParams: unknown[] = []
    const clauses: string[] = []
    if (sampleId) { clauses.push('sample_id = ?'); sqlParams.push(sampleId) }
    if (type) { clauses.push('type = ?'); sqlParams.push(type) }
    if (clauses.length) where = ' WHERE ' + clauses.join(' AND ')

    const countResult = _deps?.database?.querySql<{ cnt: number }>(
      `SELECT COUNT(*) as cnt FROM artifacts${where}`, sqlParams
    ) ?? []
    const total = countResult[0]?.cnt ?? 0

    const artifacts = _deps?.database?.querySql(
      `SELECT id, sample_id, type, path, sha256, mime, created_at FROM artifacts${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...sqlParams, limit, offset]
    ) ?? []

    // Get distinct types for filter menu
    const types = _deps?.database?.querySql<{ type: string; cnt: number }>(
      'SELECT type, COUNT(*) as cnt FROM artifacts GROUP BY type ORDER BY cnt DESC'
    ) ?? []

    sendJson(res, 200, { total, offset, limit, artifacts, types })
  } catch {
    sendJson(res, 200, { total: 0, offset, limit, artifacts: [], types: [] })
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Artifact content (for report viewer)
// ══════════════════════════════════════════════════════════════════════════

async function handleArtifactContent(res: ServerResponse, artifactId: string): Promise<void> {
  try {
    const artifact = _deps?.database?.findArtifact(artifactId)
    if (!artifact) {
      sendJson(res, 404, { error: 'Artifact not found' })
      return
    }

    if (!_deps?.workspaceManager) {
      sendJson(res, 500, { error: 'Workspace manager not available' })
      return
    }

    const workspace = await (_deps as { workspaceManager: WorkspaceManager }).workspaceManager.getWorkspace(artifact.sample_id)
    const absPath = _deps.workspaceManager.normalizePath(workspace.root, artifact.path)

    // Security: verify path is inside workspace
    const workspaceRoot = _deps.workspaceManager.getWorkspaceRoot()
    const resolvedPath = path.resolve(absPath)
    if (!resolvedPath.startsWith(path.resolve(workspaceRoot))) {
      sendJson(res, 403, { error: 'Path outside workspace' })
      return
    }

    const stat = await fs.stat(resolvedPath)
    const MAX_RENDER_SIZE = 2 * 1024 * 1024 // 2MB

    if (stat.size > MAX_RENDER_SIZE) {
      sendJson(res, 200, {
        artifact_id: artifact.id,
        type: artifact.type,
        path: artifact.path,
        mime: artifact.mime,
        size: stat.size,
        truncated: true,
        content: null,
        error: `File too large for inline rendering (${(stat.size / 1024 / 1024).toFixed(1)} MB)`,
      })
      return
    }

    const raw = await fs.readFile(resolvedPath)

    // Detect if text or binary
    const isText = isTextContent(raw, artifact.path, artifact.mime)

    if (isText) {
      const content = raw.toString('utf-8')
      let parsed: unknown = null
      const ext = path.extname(artifact.path).toLowerCase()

      if (ext === '.json' || artifact.mime === 'application/json') {
        try { parsed = JSON.parse(content) } catch { /* not valid JSON */ }
      }

      sendJson(res, 200, {
        artifact_id: artifact.id,
        type: artifact.type,
        path: artifact.path,
        mime: artifact.mime,
        size: stat.size,
        truncated: false,
        encoding: 'utf8',
        content,
        parsed_json: parsed,
        format: detectFormat(artifact.path, artifact.mime, content),
      })
    } else {
      sendJson(res, 200, {
        artifact_id: artifact.id,
        type: artifact.type,
        path: artifact.path,
        mime: artifact.mime,
        size: stat.size,
        truncated: false,
        encoding: 'base64',
        content: raw.toString('base64'),
        format: 'binary',
      })
    }
  } catch (err) {
    logger.warn({ err, artifactId }, 'Dashboard: failed to read artifact content')
    sendJson(res, 404, { error: 'Artifact file not found on disk' })
  }
}

function isTextContent(buf: Buffer, filePath: string, mime: string | null): boolean {
  const textExtensions = new Set([
    '.txt', '.md', '.json', '.xml', '.html', '.htm', '.csv',
    '.log', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
    '.c', '.h', '.cpp', '.py', '.js', '.ts', '.java', '.rs',
    '.dot', '.svg', '.yar', '.yara', '.rule', '.sig',
  ])
  const ext = path.extname(filePath).toLowerCase()
  if (textExtensions.has(ext)) return true
  if (mime?.startsWith('text/')) return true
  if (mime === 'application/json' || mime === 'application/xml') return true

  // Heuristic: check first 1KB for null bytes
  const sample = buf.subarray(0, Math.min(buf.length, 1024))
  for (let i = 0; i < sample.length; i++) {
    if (sample[i] === 0) return false
  }
  return true
}

function detectFormat(filePath: string, mime: string | null, content: string): string {
  const ext = path.extname(filePath).toLowerCase()
  if (ext === '.md' || ext === '.markdown') return 'markdown'
  if (ext === '.json' || mime === 'application/json') return 'json'
  if (ext === '.html' || ext === '.htm' || mime === 'text/html') return 'html'
  if (ext === '.xml' || mime === 'application/xml') return 'xml'
  if (ext === '.svg') return 'svg'
  if (ext === '.dot') return 'dot'
  if (ext === '.csv') return 'csv'
  if (ext === '.yaml' || ext === '.yml') return 'yaml'
  if (['.c', '.h', '.cpp', '.py', '.js', '.ts', '.java', '.rs'].includes(ext)) return 'code'
  return 'text'
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
