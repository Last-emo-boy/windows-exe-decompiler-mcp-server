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
import { pythonProcessPool } from '../python-process-pool.js'
import { checkGhidraHealth, type GhidraHealthStatus } from '../ghidra-config.js'
import { resolvePackagePath } from '../runtime-paths.js'
import { lookupCachedResult } from './cache-observability.js'
import { resolveAnalysisBackends } from '../static-backend-discovery.js'
import {
  RequiredUserInputSchema,
  SetupActionSchema,
  buildBaselinePythonSetupActions,
  buildCoreLinuxToolchainSetupActions,
  buildDynamicDependencyRequiredUserInputs,
  buildStaticAnalysisRequiredUserInputs,
  buildStaticAnalysisSetupActions,
  buildDynamicDependencySetupActions,
  buildHeavyBackendSetupActions,
  buildJavaRequiredUserInputs,
  buildJavaSetupActions,
  buildGhidraRequiredUserInputs,
  buildGhidraSetupActions,
  buildPyGhidraSetupActions,
  buildFridaRequiredUserInputs,
  buildFridaSetupActions,
  mergeRequiredUserInputs,
  mergeSetupActions,
} from '../setup-guidance.js'
import { ToolSurfaceRoleSchema } from '../tool-surface-guidance.js'

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
      result_mode: z.literal('environment_health'),
      tool_surface_role: ToolSurfaceRoleSchema,
      preferred_primary_tools: z.array(z.string()),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
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
    'Run aggregated environment health checks for workspace, database, Ghidra, static-analysis dependencies, and cache observability. ' +
    'Use this after setup_required results, degraded environment warnings, or repeated infrastructure-style failures. ' +
    'Do not use this as the primary sample-analysis workflow for a healthy environment. ' +
    '\n\nDecision guide:\n' +
    '- Use when: a tool reports setup_required, dependency failures, readonly database symptoms, or degraded health.\n' +
    '- Do not use when: you already have a valid sample_id and just need to continue analysis.\n' +
    '- Typical next step: follow setup_actions and required_user_inputs, then retry the blocked analysis tool.\n' +
    '- Common mistake: retrying the same failing analysis tool without inspecting health/setup guidance first.',
  inputSchema: SystemHealthInputSchema,
  outputSchema: SystemHealthOutputSchema,
}

interface StaticWorkerHealthData {
  status?: string
  worker?: Record<string, unknown>
  dependencies?: Record<string, unknown>
  capa_rules?: Record<string, unknown>
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
          if (ghidraStatus.checks?.java_available === false || ghidraStatus.checks?.java_version_ok === false) {
            recommendations.push(
              'Install/configure Java 21+ and set JAVA_HOME before retrying Ghidra workloads.'
            )
            setupActions = mergeSetupActions(setupActions, buildJavaSetupActions())
            requiredUserInputs = mergeRequiredUserInputs(
              requiredUserInputs,
              buildJavaRequiredUserInputs()
            )
          }
          if (!ghidraStatus.ok) {
            recommendations.push('Fix Ghidra install path or launch check before decompiler workloads.')
            setupActions = mergeSetupActions(setupActions, buildJavaSetupActions(), buildGhidraSetupActions())
            requiredUserInputs = mergeRequiredUserInputs(
              requiredUserInputs,
              buildJavaRequiredUserInputs(),
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
            buildJavaSetupActions(),
            buildGhidraSetupActions(),
            buildPyGhidraSetupActions()
          )
          requiredUserInputs = mergeRequiredUserInputs(
            requiredUserInputs,
            buildJavaRequiredUserInputs(),
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
          const analysisBackends = resolveAnalysisBackends()
          const workerDependencies = (workerHealth.dependencies || {}) as Record<string, any>
          const pefileAvailable = workerDependencies.pefile?.available !== false
          const liefAvailable = workerDependencies.lief?.available !== false
          const capaAvailable = workerDependencies.capa?.available !== false
          const fridaAvailable = workerDependencies.frida?.available !== false
          const staticDependencyIssues: string[] = []
          const runningInDocker = /^(1|true|yes|on)$/i.test(process.env.RUNNING_IN_DOCKER || '')
          const qilingRootfsConfigured = process.env.QILING_ROOTFS?.trim()
          let qilingRootfsReady = false

          if (qilingRootfsConfigured) {
            try {
              const stats = await fs.stat(qilingRootfsConfigured)
              qilingRootfsReady = stats.isDirectory()
            } catch {
              qilingRootfsReady = false
            }
          }

          let statusRaw = String(workerHealth.status || 'degraded').toLowerCase()
          let status: z.infer<typeof ComponentSchema>['status'] =
            statusRaw === 'healthy'
              ? 'healthy'
              : statusRaw === 'unhealthy'
                ? 'unhealthy'
                : 'degraded'

          if (!pefileAvailable) {
            staticDependencyIssues.push('pefile unavailable')
          }
          if (!liefAvailable) {
            staticDependencyIssues.push('LIEF unavailable')
          }
          if (!capaAvailable) {
            staticDependencyIssues.push('capa unavailable')
          }
          if (!fridaAvailable) {
            staticDependencyIssues.push('frida unavailable')
          }
          if (runningInDocker) {
            const dockerRequiredBackends = [
              ['graphviz', analysisBackends.graphviz.available],
              ['rizin', analysisBackends.rizin.available],
              ['yara_x', analysisBackends.yara_x.available],
              ['upx', analysisBackends.upx.available],
              ['wine', analysisBackends.wine.available],
              ['winedbg', analysisBackends.winedbg.available],
              ['frida_cli', analysisBackends.frida_cli.available],
              ['qiling', analysisBackends.qiling.available],
              ['angr', analysisBackends.angr.available],
              ['panda', analysisBackends.panda.available],
              ['retdec', analysisBackends.retdec.available],
            ] as const
            for (const [name, available] of dockerRequiredBackends) {
              if (!available) {
                staticDependencyIssues.push(`${name} unavailable`)
              }
            }
            if (qilingRootfsConfigured && !qilingRootfsReady) {
              staticDependencyIssues.push('qiling rootfs path missing')
            }
          }

          if (status === 'healthy' && staticDependencyIssues.length > 0) {
            status = 'degraded'
          }

          staticWorkerComponent = {
            status,
            ok: status === 'healthy',
            error:
              status === 'healthy'
                ? null
                : `Static worker status=${statusRaw}${staticDependencyIssues.length > 0 ? `; ${staticDependencyIssues.join('; ')}` : ''}`,
            details: {
              ...workerHealth,
              external_backends: analysisBackends,
              qiling_rootfs: {
                configured_path: qilingRootfsConfigured || null,
                ready: qilingRootfsConfigured ? qilingRootfsReady : null,
                caveat:
                  'Qiling requires an externally supplied Windows rootfs (DLLs and registry hives are not bundled).',
              },
            },
          }

          if (status !== 'healthy') {
            recommendations.push(
              'Install or configure the optional static-analysis stack (pefile, LIEF, flare-capa, capa rules, Detect It Easy) for full early-stage analysis coverage.'
            )
            setupActions = mergeSetupActions(
              setupActions,
              buildBaselinePythonSetupActions(),
              buildStaticAnalysisSetupActions(),
              buildCoreLinuxToolchainSetupActions(),
              buildDynamicDependencySetupActions(),
              buildHeavyBackendSetupActions()
            )
            requiredUserInputs = mergeRequiredUserInputs(
              requiredUserInputs,
              buildStaticAnalysisRequiredUserInputs(),
              buildDynamicDependencyRequiredUserInputs()
            )
            if (!capaAvailable) {
              recommendations.push('Install flare-capa to enable static capability recognition.')
            }
            if (!analysisBackends.capa_rules.available) {
              recommendations.push(
                'Provide CAPA_RULES_PATH or workers.static.capaRulesPath so capability triage can load rules.'
              )
            }
            if (!analysisBackends.die.available) {
              recommendations.push(
                'Provide DIE_PATH or add diec.exe to PATH for compiler, protector, and packer attribution.'
              )
            }
            if (!fridaAvailable) {
              recommendations.push('Install frida and frida-tools for runtime API tracing and dynamic instrumentation.')
              setupActions = mergeSetupActions(setupActions, buildFridaSetupActions())
              requiredUserInputs = mergeRequiredUserInputs(
                requiredUserInputs,
                buildFridaRequiredUserInputs()
              )
            }
            if (!analysisBackends.graphviz.available) {
              recommendations.push('Install Graphviz dot to enable SVG and PNG CFG rendering artifacts.')
            }
            if (!analysisBackends.rizin.available) {
              recommendations.push('Install or configure Rizin for lightweight fallback disassembly and graph workflows.')
            }
            if (!analysisBackends.yara_x.available) {
              recommendations.push('Install YARA-X alongside legacy YARA to prepare for newer rule-engine workflows.')
            }
            if (!analysisBackends.upx.available) {
              recommendations.push('Install UPX for common packed-sample helper workflows.')
            }
            if (!analysisBackends.wine.available || !analysisBackends.winedbg.available) {
              recommendations.push('Install Wine plus winedbg for Linux-hosted Windows user-mode execution and debugger-style troubleshooting.')
            }
            if (!analysisBackends.qiling.available) {
              recommendations.push('Install Qiling for automated Windows API emulation workflows.')
            } else if (!qilingRootfsConfigured || !qilingRootfsReady) {
              recommendations.push(
                'Mount a Windows Qiling rootfs and set QILING_ROOTFS before relying on Qiling-based automated debugging.'
              )
            }
            if (!analysisBackends.angr.available) {
              recommendations.push('Install angr in an isolated Python environment and set ANGR_PYTHON for advanced CFG and path exploration workflows.')
            }
            if (!analysisBackends.panda.available) {
              recommendations.push('Install pandare/PANDA bindings if you need record/replay-oriented dynamic workflows.')
            }
            if (!analysisBackends.retdec.available) {
              recommendations.push('Install RetDec as an artifact-first heavy decompiler backend for alternate native lifting workflows.')
            }
          }
        } catch (error) {
          staticWorkerComponent = {
            status: 'degraded',
            ok: false,
            error: normalizeError(error),
            details: {
              external_backends: resolveAnalysisBackends(),
            },
          }
          recommendations.push('Fix Python runtime or static worker startup to avoid analysis outages.')
          setupActions = mergeSetupActions(
            setupActions,
            buildBaselinePythonSetupActions(),
            buildStaticAnalysisSetupActions(),
            buildCoreLinuxToolchainSetupActions(),
            buildDynamicDependencySetupActions(),
            buildHeavyBackendSetupActions()
          )
          requiredUserInputs = mergeRequiredUserInputs(
            requiredUserInputs,
            buildStaticAnalysisRequiredUserInputs(),
            buildDynamicDependencyRequiredUserInputs()
          )
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

      const recommendedNextTools =
        overallStatus === 'healthy'
          ? ['workflow.analyze.start', 'workflow.summarize', 'workflow.triage']
          : ['system.setup.guide']
      const nextActions =
        overallStatus === 'healthy'
          ? [
              'Proceed with workflow.analyze.start for the primary staged-runtime path, or use workflow.triage only when you intentionally want the compatibility quick-profile surface.',
            ]
          : [
              'Inspect setup_actions and required_user_inputs before retrying blocked analysis tools.',
              'Use system.setup.guide if you need a consolidated bootstrap or remediation plan.',
              'Retry the original analysis tool only after the degraded dependencies or permissions issues are addressed.',
            ]

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
          python_process_pool: pythonProcessPool.getStats(),
          recommendations,
          setup_actions: setupActions,
          required_user_inputs: requiredUserInputs,
          result_mode: 'environment_health',
          tool_surface_role: 'primary',
          preferred_primary_tools: [],
          recommended_next_tools: recommendedNextTools,
          next_actions: nextActions,
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
