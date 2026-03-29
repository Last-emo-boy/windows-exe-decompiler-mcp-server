import { createHash, randomUUID } from 'crypto'
import { spawn, type ChildProcessWithoutNullStreams } from 'child_process'
import type { DatabaseManager } from './database.js'
import { config } from './config.js'
import { logger } from './logger.js'
import { resolvePackagePath } from './runtime-paths.js'

export interface RuntimeWorkerPoolLeaseMetadata {
  family: string
  compatibility_key: string
  deployment_key: string
  worker_id: string
  pool_kind: 'persistent_process'
  warm_reuse: boolean
  cold_start: boolean
}

interface WorkerSpawnConfig {
  command: string
  args: string[]
}

interface StaticWorkerRequestLike {
  tool: string
  context?: {
    versions?: Record<string, string>
  }
  args?: Record<string, unknown>
}

interface StaticWorkerResponseLike {
  job_id?: string
  ok: boolean
  warnings?: string[]
  errors?: string[]
  data?: unknown
  artifacts?: unknown[]
  metrics?: Record<string, unknown>
}

interface PooledWorkerState {
  id: string
  family: string
  compatibilityKey: string
  deploymentKey: string
  child: ChildProcessWithoutNullStreams
  busy: boolean
  unhealthy: boolean
  createdAt: string
  lastUsedAt: string
  stdoutBuffer: string
  pending?: {
    resolve: (value: StaticWorkerResponseLike) => void
    reject: (error: Error) => void
    timer: NodeJS.Timeout
  }
}

interface WorkerFamilyCounters {
  warmReuseCount: number
  coldStartCount: number
  evictionCount: number
  lastError: string | null
}

const DEFAULT_IDLE_TTL_MS = 2 * 60 * 1000
const DEFAULT_POOL_CAP = 4

export function buildStaticWorkerCompatibilityKey(request: StaticWorkerRequestLike): string {
  const payload = JSON.stringify({
    tool: request.tool,
    tool_version: request.context?.versions?.tool_version || 'unknown',
    mode:
      request.args?.scan_mode ||
      request.args?.mode ||
      request.args?.analysis_mode ||
      'default',
    python: config.workers.static.pythonPath || (process.platform === 'win32' ? 'python' : 'python3'),
    worker_path: resolvePackagePath('workers', 'static_worker.py'),
  })
  return createHash('sha256').update(payload).digest('hex')
}

export function buildRizinPreviewCompatibilityKey(input: {
  backendPath: string
  backendVersion?: string | null
  operation: string
  helperPath?: string
}): string {
  const payload = JSON.stringify({
    backend_path: input.backendPath,
    backend_version: input.backendVersion || 'unknown',
    operation: input.operation,
    helper_path: input.helperPath || resolvePackagePath('workers', 'rizin_preview_worker.py'),
  })
  return createHash('sha256').update(payload).digest('hex')
}

export class RuntimeWorkerPool {
  private readonly workers = new Map<string, PooledWorkerState>()
  private readonly familyCounters = new Map<string, WorkerFamilyCounters>()

  async executeStaticWorker(
    request: StaticWorkerRequestLike & Record<string, unknown>,
    options: {
      database?: DatabaseManager
      family?: string
      compatibilityKey?: string
      poolCap?: number
      idleTtlMs?: number
      timeoutMs?: number
    } = {}
  ): Promise<{ response: StaticWorkerResponseLike; lease: RuntimeWorkerPoolLeaseMetadata }> {
    return this.executePooledWorker(request, {
      ...options,
      family: options.family || 'static_python',
      compatibilityKey: options.compatibilityKey || buildStaticWorkerCompatibilityKey(request),
      spawnConfig: {
        command:
          config.workers.static.pythonPath ||
          (process.platform === 'win32' ? 'python' : 'python3'),
        args: [resolvePackagePath('workers', 'static_worker.py')],
      },
    })
  }

  async executeHelperWorker(
    request: Record<string, unknown>,
    options: {
      database?: DatabaseManager
      family: string
      compatibilityKey: string
      spawnConfig: WorkerSpawnConfig
      poolCap?: number
      idleTtlMs?: number
      timeoutMs?: number
    }
  ): Promise<{ response: StaticWorkerResponseLike; lease: RuntimeWorkerPoolLeaseMetadata }> {
    return this.executePooledWorker(request, options)
  }

  private async executePooledWorker(
    request: Record<string, unknown>,
    options: {
      database?: DatabaseManager
      family: string
      compatibilityKey: string
      spawnConfig: WorkerSpawnConfig
      poolCap?: number
      idleTtlMs?: number
      timeoutMs?: number
    }
  ): Promise<{ response: StaticWorkerResponseLike; lease: RuntimeWorkerPoolLeaseMetadata }> {
    const family = options.family
    const compatibilityKey = options.compatibilityKey
    const poolCap = options.poolCap || DEFAULT_POOL_CAP
    const idleTtlMs = options.idleTtlMs || DEFAULT_IDLE_TTL_MS
    const deploymentKey = this.buildDeploymentKey(options.spawnConfig)

    this.evictIdleWorkers(options.database, idleTtlMs)

    let worker = this.findIdleWorker(family, compatibilityKey, deploymentKey)
    let warmReuse = false
    let coldStart = false

    if (worker) {
      warmReuse = true
      const counters = this.getCounters(family, compatibilityKey)
      counters.warmReuseCount += 1
      this.persistFamilyState(options.database, family, compatibilityKey, deploymentKey)
    } else {
      const liveCount = this.countLiveWorkers(family, compatibilityKey)
      if (liveCount >= poolCap) {
        this.evictIdleWorkers(options.database, 0, family, compatibilityKey)
      }
      worker = this.findIdleWorker(family, compatibilityKey, deploymentKey)
      if (!worker) {
        worker = this.createWorker(
          family,
          compatibilityKey,
          deploymentKey,
          options.spawnConfig
        )
        coldStart = true
        const counters = this.getCounters(family, compatibilityKey)
        counters.coldStartCount += 1
        this.persistFamilyState(options.database, family, compatibilityKey, deploymentKey)
      }
    }

    worker.busy = true
    worker.lastUsedAt = new Date().toISOString()
    this.persistFamilyState(options.database, family, compatibilityKey, deploymentKey)

    try {
      const response = await this.sendRequest(worker, request, options.timeoutMs)
      worker.busy = false
      worker.lastUsedAt = new Date().toISOString()
      this.persistFamilyState(options.database, family, compatibilityKey, deploymentKey)
      return {
        response,
        lease: {
          family,
          compatibility_key: compatibilityKey,
          deployment_key: deploymentKey,
          worker_id: worker.id,
          pool_kind: 'persistent_process',
          warm_reuse: warmReuse,
          cold_start: coldStart,
        },
      }
    } catch (error) {
      worker.busy = false
      worker.unhealthy = true
      const counters = this.getCounters(family, compatibilityKey)
      counters.lastError = error instanceof Error ? error.message : String(error)
      this.disposeWorker(worker, options.database, true)
      throw error
    }
  }

  private buildDeploymentKey(spawnConfig: WorkerSpawnConfig): string {
    const payload = JSON.stringify({
      command: spawnConfig.command,
      args: spawnConfig.args,
      pid: process.pid,
    })
    return createHash('sha256').update(payload).digest('hex')
  }

  private familyKey(family: string, compatibilityKey: string): string {
    return `${family}:${compatibilityKey}`
  }

  private getCounters(family: string, compatibilityKey: string): WorkerFamilyCounters {
    const key = this.familyKey(family, compatibilityKey)
    const existing = this.familyCounters.get(key)
    if (existing) {
      return existing
    }
    const created: WorkerFamilyCounters = {
      warmReuseCount: 0,
      coldStartCount: 0,
      evictionCount: 0,
      lastError: null,
    }
    this.familyCounters.set(key, created)
    return created
  }

  private countLiveWorkers(family: string, compatibilityKey: string): number {
    let count = 0
    for (const worker of this.workers.values()) {
      if (
        worker.family === family &&
        worker.compatibilityKey === compatibilityKey &&
        !worker.unhealthy
      ) {
        count += 1
      }
    }
    return count
  }

  private findIdleWorker(
    family: string,
    compatibilityKey: string,
    deploymentKey: string
  ): PooledWorkerState | undefined {
    for (const worker of this.workers.values()) {
      if (
        worker.family === family &&
        worker.compatibilityKey === compatibilityKey &&
        worker.deploymentKey === deploymentKey &&
        !worker.busy &&
        !worker.unhealthy
      ) {
        return worker
      }
    }
    return undefined
  }

  private createWorker(
    family: string,
    compatibilityKey: string,
    deploymentKey: string,
    spawnConfig: WorkerSpawnConfig
  ): PooledWorkerState {
    const child = spawn(spawnConfig.command, spawnConfig.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    })

    const state: PooledWorkerState = {
      id: randomUUID(),
      family,
      compatibilityKey,
      deploymentKey,
      child,
      busy: false,
      unhealthy: false,
      createdAt: new Date().toISOString(),
      lastUsedAt: new Date().toISOString(),
      stdoutBuffer: '',
    }

    child.stdout.on('data', (chunk) => {
      state.stdoutBuffer += chunk.toString()
      this.consumeStdout(state)
    })

    child.stderr.on('data', (chunk) => {
      logger.debug(
        { worker_family: family, worker_id: state.id, stderr: chunk.toString() },
        'Pooled static worker stderr'
      )
    })

    child.on('close', (code) => {
      if (state.pending) {
        const pending = state.pending
        state.pending = undefined
        clearTimeout(pending.timer)
        pending.reject(new Error(`Static worker exited with code ${code}`))
      }
      state.unhealthy = true
    })

    child.on('error', (error) => {
      if (state.pending) {
        const pending = state.pending
        state.pending = undefined
        clearTimeout(pending.timer)
        pending.reject(error)
      }
      state.unhealthy = true
    })

    this.workers.set(state.id, state)
    return state
  }

  private consumeStdout(state: PooledWorkerState): void {
    let newlineIndex = state.stdoutBuffer.indexOf('\n')
    while (newlineIndex >= 0) {
      const line = state.stdoutBuffer.slice(0, newlineIndex).trim()
      state.stdoutBuffer = state.stdoutBuffer.slice(newlineIndex + 1)
      if (line.length > 0 && state.pending) {
        const pending = state.pending
        state.pending = undefined
        clearTimeout(pending.timer)
        try {
          pending.resolve(JSON.parse(line) as StaticWorkerResponseLike)
        } catch (error) {
          pending.reject(
            new Error(`Failed to parse pooled worker response: ${error instanceof Error ? error.message : String(error)}`)
          )
        }
      }
      newlineIndex = state.stdoutBuffer.indexOf('\n')
    }
  }

  private async sendRequest(
    worker: PooledWorkerState,
    request: Record<string, unknown>,
    timeoutMs?: number
  ): Promise<StaticWorkerResponseLike> {
    if (worker.pending) {
      throw new Error(`Worker ${worker.id} is already busy`)
    }

    return new Promise<StaticWorkerResponseLike>((resolve, reject) => {
      const timer = setTimeout(() => {
        worker.pending = undefined
        reject(new Error(`Static worker timed out after ${timeoutMs || config.workers.static.timeout * 1000}ms`))
      }, timeoutMs || config.workers.static.timeout * 1000)

      worker.pending = {
        resolve,
        reject,
        timer,
      }

      try {
        worker.child.stdin.write(`${JSON.stringify(request)}\n`)
      } catch (error) {
        worker.pending = undefined
        clearTimeout(timer)
        reject(error instanceof Error ? error : new Error(String(error)))
      }
    })
  }

  private evictIdleWorkers(
    database?: DatabaseManager,
    idleTtlMs: number = DEFAULT_IDLE_TTL_MS,
    family?: string,
    compatibilityKey?: string
  ): void {
    const now = Date.now()
    for (const worker of [...this.workers.values()]) {
      if (worker.busy) {
        continue
      }
      if (family && worker.family !== family) {
        continue
      }
      if (compatibilityKey && worker.compatibilityKey !== compatibilityKey) {
        continue
      }
      const idleMs = now - new Date(worker.lastUsedAt).getTime()
      if (idleMs >= idleTtlMs || worker.unhealthy) {
        this.disposeWorker(worker, database, false)
      }
    }
  }

  private disposeWorker(
    worker: PooledWorkerState,
    database?: DatabaseManager,
    unhealthy: boolean = false
  ): void {
    try {
      worker.child.kill()
    } catch {
      // ignore shutdown failures
    }
    this.workers.delete(worker.id)
    const counters = this.getCounters(worker.family, worker.compatibilityKey)
    counters.evictionCount += 1
    if (unhealthy && !counters.lastError) {
      counters.lastError = 'worker_marked_unhealthy'
    }
    this.persistFamilyState(database, worker.family, worker.compatibilityKey, worker.deploymentKey)
  }

  private persistFamilyState(
    database: DatabaseManager | undefined,
    family: string,
    compatibilityKey: string,
    deploymentKey: string
  ): void {
    if (!database) {
      return
    }
    const counters = this.getCounters(family, compatibilityKey)
    const familyWorkers = [...this.workers.values()].filter(
      (worker) => worker.family === family && worker.compatibilityKey === compatibilityKey
    )
    const now = new Date().toISOString()
    database.upsertRuntimeWorkerFamilyState({
      family,
      compatibility_key: compatibilityKey,
      deployment_key: deploymentKey,
      pool_kind: 'persistent_process',
      live_workers: familyWorkers.length,
      idle_workers: familyWorkers.filter((worker) => !worker.busy && !worker.unhealthy).length,
      busy_workers: familyWorkers.filter((worker) => worker.busy).length,
      unhealthy_workers: familyWorkers.filter((worker) => worker.unhealthy).length,
      warm_reuse_count: counters.warmReuseCount,
      cold_start_count: counters.coldStartCount,
      eviction_count: counters.evictionCount,
      last_error: counters.lastError,
      metadata_json: JSON.stringify({
        worker_ids: familyWorkers.map((worker) => worker.id),
      }),
      created_at: now,
      updated_at: now,
      last_used_at: familyWorkers
        .map((worker) => worker.lastUsedAt)
        .sort()
        .reverse()[0] || now,
    })
  }
}

let globalRuntimeWorkerPool: RuntimeWorkerPool | null = null

export function getRuntimeWorkerPool(): RuntimeWorkerPool {
  if (!globalRuntimeWorkerPool) {
    globalRuntimeWorkerPool = new RuntimeWorkerPool()
  }
  return globalRuntimeWorkerPool
}
