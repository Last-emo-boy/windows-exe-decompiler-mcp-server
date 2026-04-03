/**
 * Python Process Pool — Concurrency-limited Python worker execution.
 *
 * Prevents fork-bomb / OOM scenarios by limiting the number of
 * concurrent Python child processes across all tool invocations.
 *
 * This is distinct from WorkerPool (which manages JobQueue task allocation).
 * PythonProcessPool limits raw `spawn(python, ...)` calls.
 *
 * Usage:
 *   import { pythonProcessPool } from './python-process-pool.js'
 *   const result = await pythonProcessPool.run(pythonCmd, workerPath, request)
 */

import { spawn, type ChildProcess } from 'child_process'
import os from 'os'
import { logger } from './logger.js'

export interface PythonProcessPoolOptions {
  /** Maximum concurrent Python workers (default: min(cpuCount, 8)) */
  maxConcurrency?: number
  /** Per-worker timeout in ms (default: 120_000) */
  defaultTimeoutMs?: number
}

interface QueueEntry {
  resolve: (result: PythonWorkerResult) => void
  reject: (error: Error) => void
  pythonCmd: string
  workerPath: string
  requestJson: string
  timeoutMs: number
}

export interface PythonWorkerResult {
  ok: boolean
  data?: unknown
  errors?: string[]
  warnings?: string[]
  metrics?: Record<string, unknown>
}

export class PythonProcessPool {
  private maxConcurrency: number
  private defaultTimeoutMs: number
  private active = 0
  private queue: QueueEntry[] = []
  private totalSpawned = 0
  private totalCompleted = 0
  private totalErrors = 0

  constructor(options: PythonProcessPoolOptions = {}) {
    const cpuCount = os.cpus().length
    const envWorkers = parseInt(process.env.MAX_PYTHON_WORKERS || '', 10)
    this.maxConcurrency = options.maxConcurrency
      ?? (envWorkers > 0 ? envWorkers : Math.max(2, Math.min(cpuCount, 8)))
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 120_000
    logger.info(
      { maxConcurrency: this.maxConcurrency, cpuCount },
      'PythonProcessPool initialized'
    )
  }

  /**
   * Execute a Python worker with concurrency limiting.
   * Queues the request if the pool is at capacity.
   */
  run(
    pythonCmd: string,
    workerPath: string,
    request: Record<string, unknown>,
    timeoutMs?: number
  ): Promise<PythonWorkerResult> {
    return new Promise<PythonWorkerResult>((resolve, reject) => {
      const entry: QueueEntry = {
        resolve,
        reject,
        pythonCmd,
        workerPath,
        requestJson: JSON.stringify(request),
        timeoutMs: timeoutMs ?? this.defaultTimeoutMs,
      }

      if (this.active < this.maxConcurrency) {
        this.execute(entry)
      } else {
        this.queue.push(entry)
        logger.debug(
          { queueLength: this.queue.length, active: this.active, workerPath },
          'Python worker queued (pool at capacity)'
        )
      }
    })
  }

  private execute(entry: QueueEntry): void {
    this.active++
    this.totalSpawned++

    const { pythonCmd, workerPath, requestJson, timeoutMs, resolve, reject } = entry
    let settled = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const proc: ChildProcess = spawn(pythonCmd, [workerPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    })

    const chunks: Buffer[] = []
    const stderrChunks: Buffer[] = []

    proc.stdout?.on('data', (chunk: Buffer) => chunks.push(chunk))
    proc.stderr?.on('data', (chunk: Buffer) => stderrChunks.push(chunk))

    const settle = (result: PythonWorkerResult | Error) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)

      this.active--
      if (result instanceof Error) {
        this.totalErrors++
        reject(result)
      } else {
        this.totalCompleted++
        resolve(result)
      }
      this.drainQueue()
    }

    proc.on('close', (code) => {
      const stdout = Buffer.concat(chunks).toString('utf8')
      const stderr = Buffer.concat(stderrChunks).toString('utf8')

      if (code !== 0) {
        settle({
          ok: false,
          errors: [`Worker exited with code ${code}`, stderr].filter(Boolean),
        })
        return
      }

      try {
        const parsed = JSON.parse(stdout)
        settle(parsed as PythonWorkerResult)
      } catch {
        settle({
          ok: false,
          errors: [`Failed to parse worker output: ${stdout.slice(0, 500)}`],
        })
      }
    })

    proc.on('error', (err) => {
      settle(new Error(`Worker spawn failed: ${err.message}`))
    })

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        if (!settled) {
          proc.kill('SIGTERM')
          setTimeout(() => { if (!settled) proc.kill('SIGKILL') }, 2000)
          settle({
            ok: false,
            errors: [`Worker timed out after ${timeoutMs}ms`],
          })
        }
      }, timeoutMs)
    }

    // Send request via stdin
    try {
      proc.stdin?.write(requestJson)
      proc.stdin?.end()
    } catch (err) {
      settle(new Error(`Failed to write to worker stdin: ${(err as Error).message}`))
    }
  }

  private drainQueue(): void {
    while (this.active < this.maxConcurrency && this.queue.length > 0) {
      const next = this.queue.shift()!
      this.execute(next)
    }
  }

  /** Get pool stats for health/monitoring endpoints */
  getStats() {
    return {
      maxConcurrency: this.maxConcurrency,
      active: this.active,
      queued: this.queue.length,
      totalSpawned: this.totalSpawned,
      totalCompleted: this.totalCompleted,
      totalErrors: this.totalErrors,
    }
  }
}

/** Singleton instance configured via environment */
export const pythonProcessPool = new PythonProcessPool()
