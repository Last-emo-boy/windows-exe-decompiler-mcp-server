/**
 * system.health tool implementation
 * Aggregated runtime health checks for high-availability operations.
 */

import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { spawn } from 'child_process'
import { randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { checkGhidraHealth, type GhidraHealthStatus } from '../ghidra-config.js'
import { resolvePackagePath } from '../runtime-paths.js'
import { lookupCachedResult } from './cache-observability.js'
import {
  RequiredUserInputSchema,
  SetupActionSchema,
  buildBaselinePythonSetupActions,
  buildGhidraRequiredUserInputs,
  buildGhidraSetupActions,
  buildPyGhidraSetupActions,
  mergeRequiredUserInputs,
  mergeSetupActions,
} from '../setup-guidance.js'

const TOOL_NAME = 'system.health'

const ComponentSchema = z.object({
  status: z.enum(['healthy', 'degraded', 'unhealthy', 'skipped']),
  ok: z.boolean(),
  error: z.string().nullable().optional(),
  details: z.record(z.any()).optional(),
})

const CacheObservabilitySchema = z.object({
  key: z.string().nullable(),
  tier: z.string().nullable(),
  created_at: z.string().nullable(),
  expires_at: z.string().nullable(),
  hit_at: z.string().nullable(),
  sample_sha256: z.string().nullable(),
  sample_state_consistent: z.boolean().nullable(),
})

export const SystemHealthInputSchema = z.object({
  sample_id: z
    .string()
    .optional()
    .describe('Optional sample ID used to verify cache metadata consistency'),
  timeout_ms: z
    .number()
    .int()
    .min(2000)
    .max(120000)
    .default(10000)
    .describe('Timeout for each external probe in milliseconds'),
  include_ghidra: z
    .boolean()
    .default(true)
    .describe('Include ghidra.health probe'),
  include_static_worker: z
    .boolean()
    .default(true)
    .describe('Include Python static-worker dependency probe'),
  include_cache_probe: z
    .boolean()
    .default(true)
    .describe('Include cache observability probe (key/tier/timestamps/sample consistency)'),
})

export const SystemHealthOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      overall_status: z.enum(['healthy', 'degraded', 'unhealthy']),
      checked_at: z.string(),
      components: z.object({
        workspace: ComponentSchema,
        database: ComponentSchema,
        ghidra: ComponentSchema,
        static_worker: ComponentSchema,
        cache: ComponentSchema,
      }),
      cache_observability: CacheObservabilitySchema,
      recommendations: z.array(z.string()),
      setup_actions: z.array(SetupActionSchema),
      required_user_inputs: z.array(RequiredUserInputSchema),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export type SystemHealthInput = z.infer<typeof SystemHealthInputSchema>
export type SystemHealthOutput = z.infer<typeof SystemHealthOutputSchema>

export const systemHealthToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Run aggregated environment health checks (workspace, database, Ghidra, Python static worker dependencies).',
  inputSchema: SystemHealthInputSchema,
  outputSchema: SystemHealthOutputSchema,
}

interface StaticWorkerHealthData {
  status?: string
  worker?: Record<string, unknown>
  dependencies?: Record<string, unknown>
  yara_rules?: Record<string, unknown>
  checked_at?: string
}

interface WorkerResponse {
  job_id: string
  ok: boolean
  warnings: string[]
  errors: string[]
  data: unknown
  artifacts: unknown[]
  metrics: Record<string, unknown>
}

interface SystemHealthDependencies {
  checkGhidra?: (timeoutMs: number) => GhidraHealthStatus
  probeStaticWorker?: (timeoutMs: number) => Promise<StaticWorkerHealthData>
  cacheManager?: CacheManager
}

function normalizeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

async function callStaticWorkerHealth(timeoutMs: number): Promise<StaticWorkerHealthData> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath('workers', 'static_worker.py')
    const pythonCommand = process.platform === 'win32' ? 'python' : 'python3'
    const processTimeoutMs = Math.max(timeoutMs, 2000)

    const pythonProcess = spawn(pythonCommand, [workerPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''
    let settled = false

    const onDone = (fn: () => void) => {
      if (settled) {
        return
      }
      settled = true
      fn()
    }

    const timer = setTimeout(() => {
      onDone(() => {
        pythonProcess.kill()
        reject(new Error(`Static worker health probe timed out after ${processTimeoutMs}ms`))
      })
    }, processTimeoutMs)

    pythonProcess.stdout.on('data', (data) => {
      stdout += data.toString()
    })

    pythonProcess.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    pythonProcess.on('error', (error) => {
      onDone(() => {
        clearTimeout(timer)
        reject(new Error(`Failed to spawn Python worker: ${error.message}`))
      })
    })

    pythonProcess.on('close', (code) => {
      onDone(() => {
        clearTimeout(timer)
        if (code !== 0) {
          reject(new Error(`Python worker exited with code ${code}. stderr: ${stderr}`))
          return
        }

        try {
          const lines = stdout
            .trim()
            .split('\n')
            .map((line) => line.trim())
            .filter((line) => line.length > 0)
          const lastLine = lines[lines.length - 1]
          const response = JSON.parse(lastLine) as WorkerResponse
          if (!response.ok) {
            reject(new Error((response.errors || []).join('; ') || 'Static worker probe failed'))
            return
          }
          resolve((response.data || {}) as StaticWorkerHealthData)
        } catch (error) {
          reject(
            new Error(
              `Failed to parse static worker health response: ${normalizeError(error)}. stdout: ${stdout}`
            )
          )
        }
      })
    })

    try {
      const request = {
        job_id: randomUUID(),
        tool: 'system.health',
        sample: {
          sample_id: 'health-check',
          path: '',
        },
        args: {},
        context: {
          request_time_utc: new Date().toISOString(),
          policy: {
            allow_dynamic: false,
            allow_network: false,
          },
          versions: {
            tool_version: '1.0.0',
          },
        },
      }

      pythonProcess.stdin.write(JSON.stringify(request) + '\n')
      pythonProcess.stdin.end()
    } catch (error) {
      onDone(() => {
        clearTimeout(timer)
        reject(new Error(`Failed to write health request: ${normalizeError(error)}`))
      })
    }
  })
}

async function checkWorkspaceWritable(root: string) {
  const probeFile = path.join(root, `.health-probe-${process.pid}-${Date.now()}.tmp`)
  await fs.mkdir(root, { recursive: true })
  await fs.writeFile(probeFile, `probe:${Date.now()}:${os.hostname()}`, 'utf-8')
  await fs.unlink(probeFile)
}

export function createSystemHealthHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SystemHealthDependencies
) {
  const runGhidraCheck = dependencies?.checkGhidra || checkGhidraHealth
  const runStaticWorkerProbe = dependencies?.probeStaticWorker || callStaticWorkerHealth
  const cacheManager = dependencies?.cacheManager

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = SystemHealthInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const recommendations: string[] = []
      let setupActions = [] as z.infer<typeof SetupActionSchema>[]
      let requiredUserInputs = [] as z.infer<typeof RequiredUserInputSchema>[]
      const warnings: string[] = []

      const workspaceRoot = workspaceManager.getWorkspaceRoot()
      let workspaceComponent: z.infer<typeof ComponentSchema>
      try {
        await checkWorkspaceWritable(workspaceRoot)
        workspaceComponent = {
          status: 'healthy',
          ok: true,
          details: { root: workspaceRoot, writable: true },
        }
      } catch (error) {
        workspaceComponent = {
          status: 'unhealthy',
          ok: false,
          error: normalizeError(error),
          details: { root: workspaceRoot, writable: false },
        }
        recommendations.push('Fix workspace permissions/path to restore write access.')
      }

      let databaseComponent: z.infer<typeof ComponentSchema>
      try {
        const row = database.getDatabase().prepare('SELECT 1 as ok').get() as { ok?: number }
        databaseComponent = {
          status: row?.ok === 1 ? 'healthy' : 'degraded',
          ok: row?.ok === 1,
          details: { query_ok: row?.ok === 1 },
        }
        if (row?.ok !== 1) {
          recommendations.push('Check database integrity and connectivity.')
        }
      } catch (error) {
        databaseComponent = {
          status: 'unhealthy',
          ok: false,
          error: normalizeError(error),
        }
        recommendations.push('Repair SQLite database access before production use.')
      }

      let ghidraComponent: z.infer<typeof ComponentSchema> = {
        status: 'skipped',
        ok: true,
      }
      if (input.include_ghidra) {
        try {
          const ghidraStatus = runGhidraCheck(input.timeout_ms)
          ghidraComponent = {
            status: ghidraStatus.ok ? 'healthy' : 'degraded',
            ok: ghidraStatus.ok,
            error: ghidraStatus.ok ? null : (ghidraStatus.errors || []).join('; '),
            details: ghidraStatus,
          }
          if (ghidraStatus.checks?.pyghidra_available === false) {
            warnings.push(
              'PyGhidra is unavailable; Python post-scripts may fail and Java fallback will be used.'
            )
            recommendations.push(
              'Install pyghidra in the active Python environment to improve script compatibility.'
            )
            setupActions = mergeSetupActions(setupActions, buildPyGhidraSetupActions())
          }
          if (!ghidraStatus.ok) {
            recommendations.push('Fix Ghidra install path or launch check before decompiler workloads.')
            setupActions = mergeSetupActions(setupActions, buildGhidraSetupActions())
            requiredUserInputs = mergeRequiredUserInputs(
              requiredUserInputs,
              buildGhidraRequiredUserInputs()
            )
          }
        } catch (error) {
          ghidraComponent = {
            status: 'degraded',
            ok: false,
            error: normalizeError(error),
          }
          recommendations.push('Investigate ghidra.health probe failure.')
          setupActions = mergeSetupActions(
            setupActions,
            buildGhidraSetupActions(),
            buildPyGhidraSetupActions()
          )
          requiredUserInputs = mergeRequiredUserInputs(
            requiredUserInputs,
            buildGhidraRequiredUserInputs()
          )
        }
      }

      let staticWorkerComponent: z.infer<typeof ComponentSchema> = {
        status: 'skipped',
        ok: true,
      }
      if (input.include_static_worker) {
        try {
          const workerHealth = await runStaticWorkerProbe(input.timeout_ms)
          const statusRaw = String(workerHealth.status || 'degraded').toLowerCase()
          const status =
            statusRaw === 'healthy'
              ? 'healthy'
              : statusRaw === 'unhealthy'
                ? 'unhealthy'
                : 'degraded'
          staticWorkerComponent = {
            status,
            ok: status === 'healthy',
            error: status === 'healthy' ? null : `Static worker status=${statusRaw}`,
            details: workerHealth,
          }
          if (status !== 'healthy') {
            recommendations.push(
              'Install/repair Python dependencies (yara-python, flare-floss, yara rules) for static analysis stability.'
            )
            setupActions = mergeSetupActions(setupActions, buildBaselinePythonSetupActions())
          }
        } catch (error) {
          staticWorkerComponent = {
            status: 'degraded',
            ok: false,
            error: normalizeError(error),
          }
          recommendations.push('Fix Python runtime or static worker startup to avoid analysis outages.')
          setupActions = mergeSetupActions(setupActions, buildBaselinePythonSetupActions())
        }
      }

      let cacheComponent: z.infer<typeof ComponentSchema> = {
        status: 'skipped',
        ok: true,
        details: { reason: 'cache probe disabled' },
      }
      let cacheObservability: z.infer<typeof CacheObservabilitySchema> = {
        key: null,
        tier: null,
        created_at: null,
        expires_at: null,
        hit_at: null,
        sample_sha256: null,
        sample_state_consistent: null,
      }
      if (input.include_cache_probe) {
        if (!cacheManager) {
          cacheComponent = {
            status: 'skipped',
            ok: true,
            details: { reason: 'cache manager not configured' },
          }
        } else {
          try {
            let expectedSampleSha: string | undefined
            if (input.sample_id) {
              const sample = database.findSample(input.sample_id)
              if (sample) {
                expectedSampleSha = sample.sha256
              } else {
                cacheComponent = {
                  status: 'degraded',
                  ok: false,
                  error: `Sample not found for cache consistency check: ${input.sample_id}`,
                }
                recommendations.push(
                  'Provide a valid sample_id to verify cache metadata consistency against current sample state.'
                )
              }
            }

            if (cacheComponent.status !== 'degraded') {
              const probeKey = `health_cache_probe_${Date.now()}_${randomUUID().replace(/-/g, '')}`
              const probePayload = {
                tool: TOOL_NAME,
                checked_at: new Date().toISOString(),
                host: os.hostname(),
              }
              await cacheManager.setCachedResult(probeKey, probePayload, 60_000, expectedSampleSha)

              const cachedLookup = await lookupCachedResult(cacheManager, probeKey)
              if (!cachedLookup) {
                cacheComponent = {
                  status: 'degraded',
                  ok: false,
                  error: 'cache probe write/read failed',
                  details: { probe_key: probeKey },
                }
                recommendations.push('Investigate cache read/write path; probe key was not retrievable.')
              } else {
                const metadata = cachedLookup.metadata
                const sampleStateConsistent =
                  expectedSampleSha !== undefined
                    ? metadata.sampleSha256 === expectedSampleSha
                    : null

                cacheObservability = {
                  key: metadata.key,
                  tier: metadata.tier,
                  created_at: metadata.createdAt || null,
                  expires_at: metadata.expiresAt || null,
                  hit_at: metadata.fetchedAt || null,
                  sample_sha256: metadata.sampleSha256 || null,
                  sample_state_consistent: sampleStateConsistent,
                }

                const cacheHealthy =
                  sampleStateConsistent !== false && typeof metadata.key === 'string'
                cacheComponent = {
                  status: cacheHealthy ? 'healthy' : 'degraded',
                  ok: cacheHealthy,
                  error: cacheHealthy ? null : 'cache metadata sample_sha256 mismatch',
                  details: {
                    probe_key: metadata.key,
                    tier: metadata.tier,
                    sample_sha256: metadata.sampleSha256 || null,
                    expected_sample_sha256: expectedSampleSha || null,
                  },
                }
                if (!cacheHealthy) {
                  recommendations.push(
                    'Align cache metadata sample_sha256 with active sample state to reduce stale-cache risk.'
                  )
                }
              }
            }
          } catch (error) {
            cacheComponent = {
              status: 'degraded',
              ok: false,
              error: normalizeError(error),
            }
            recommendations.push('Fix cache probe failures to improve cache observability.')
          }
        }
      }

      const essentialUnhealthy =
        workspaceComponent.status === 'unhealthy' || databaseComponent.status === 'unhealthy'
      const optionalIssues = [ghidraComponent, staticWorkerComponent, cacheComponent].some(
        (item) => item.status === 'degraded' || item.status === 'unhealthy'
      )

      const overallStatus: 'healthy' | 'degraded' | 'unhealthy' = essentialUnhealthy
        ? 'unhealthy'
        : optionalIssues
          ? 'degraded'
          : 'healthy'

      if (overallStatus !== 'healthy') {
        warnings.push(`System health is ${overallStatus}`)
      }

      return {
        ok: overallStatus !== 'unhealthy',
        data: {
          overall_status: overallStatus,
          checked_at: new Date().toISOString(),
          components: {
            workspace: workspaceComponent,
            database: databaseComponent,
            ghidra: ghidraComponent,
            static_worker: staticWorkerComponent,
            cache: cacheComponent,
          },
          cache_observability: cacheObservability,
          recommendations,
          setup_actions: setupActions,
          required_user_inputs: requiredUserInputs,
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
