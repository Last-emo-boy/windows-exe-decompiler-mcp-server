/**
 * dynamic.dependencies tool
 * Dynamic-analysis capability bootstrap probe (safe: no sample execution).
 */

import { spawn } from 'child_process'
import path from 'path'
import fs from 'fs/promises'
import { v4 as uuidv4 } from 'uuid'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { resolvePackagePath } from '../runtime-paths.js'
import {
  RequiredUserInputSchema,
  SetupActionSchema,
  buildBaselinePythonSetupActions,
  buildCoreLinuxToolchainSetupActions,
  buildDynamicDependencySetupActions,
  buildDynamicDependencyRequiredUserInputs,
  mergeSetupActions,
  mergeRequiredUserInputs,
} from '../setup-guidance.js'
import { resolveAnalysisBackends } from '../static-backend-discovery.js'

const TOOL_NAME = 'dynamic.dependencies'
const TOOL_VERSION = '0.1.0'

export const DynamicDependenciesInputSchema = z.object({
  sample_id: z
    .string()
    .optional()
    .describe('Optional sample ID; not required because this probe does not execute binaries'),
})

export const DynamicDependenciesOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'partial', 'bootstrap_required']),
      available_components: z.array(z.string()),
      components: z.record(z.any()),
      recommendations: z.array(z.string()),
      setup_actions: z.array(SetupActionSchema).optional(),
      required_user_inputs: z.array(RequiredUserInputSchema).optional(),
      checked_at: z.string(),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const dynamicDependenciesToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Probe dynamic-analysis readiness across Speakeasy, Frida, Frida CLI, Qiling, angr, PANDA, Wine/winedbg, and related helper runtimes without executing the sample.',
  inputSchema: DynamicDependenciesInputSchema,
  outputSchema: DynamicDependenciesOutputSchema,
}

interface WorkerRequest {
  job_id: string
  tool: string
  sample: {
    sample_id: string
    path: string
  }
  args: Record<string, unknown>
  context: {
    request_time_utc: string
    policy: {
      allow_dynamic: boolean
      allow_network: boolean
    }
    versions: Record<string, string>
  }
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

interface DynamicDependenciesDependencies {
  callWorker?: (request: WorkerRequest) => Promise<WorkerResponse>
}

function buildBootstrapFallback(startTime: number, errorMessage: string): WorkerResult {
  return {
    ok: true,
    data: {
      status: 'bootstrap_required',
      available_components: [],
      components: {
        speakeasy: {
          available: false,
          version: null,
          distribution: null,
          api_available: false,
          warnings: [],
          error: errorMessage,
        },
        frida: {
          available: false,
          version: null,
          error: errorMessage,
        },
        psutil: {
          available: false,
          version: null,
          error: errorMessage,
        },
        qiling: {
          available: false,
          version: null,
          error: errorMessage,
        },
        angr: {
          available: false,
          version: null,
          error: errorMessage,
        },
        panda: {
          available: false,
          version: null,
          error: errorMessage,
        },
        wine: {
          available: false,
          version: null,
          error: errorMessage,
        },
        winedbg: {
          available: false,
          version: null,
          error: errorMessage,
        },
        frida_cli: {
          available: false,
          version: null,
          error: errorMessage,
        },
        worker: {
          available: false,
          error: errorMessage,
        },
      },
      recommendations: [
        'Install baseline Python dependencies first: pip install -r requirements.txt',
        'Install FLARE Speakeasy emulator for PE user-mode emulation: pip install speakeasy-emulator',
        'Install frida for runtime API tracing: pip install frida',
        'Install frida-tools for CLI tracing helpers: pip install frida-tools',
        'Install psutil for process telemetry collection: pip install psutil',
        'Install Qiling for automated Windows API emulation: pip install qiling',
        'Install angr in an isolated environment for advanced CFG/path exploration.',
        'Install pandare for PANDA-oriented record/replay helpers: pip install pandare',
        'Install Wine and winedbg when Linux-hosted Windows user-mode execution or debugger-style triage is needed.',
      ],
      setup_actions: mergeSetupActions(
        buildBaselinePythonSetupActions(),
        buildCoreLinuxToolchainSetupActions(),
        buildDynamicDependencySetupActions()
      ),
      required_user_inputs: mergeRequiredUserInputs(buildDynamicDependencyRequiredUserInputs()),
      checked_at: new Date().toISOString(),
    },
    warnings: [`dynamic.dependencies probe degraded: ${errorMessage}`],
    metrics: {
      elapsed_ms: Date.now() - startTime,
      tool: TOOL_NAME,
    },
  }
}

async function callStaticWorker(request: WorkerRequest): Promise<WorkerResponse> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath('workers', 'static_worker.py')
    const pythonCommand = process.platform === 'win32' ? 'python' : 'python3'
    const pythonProcess = spawn(pythonCommand, [workerPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''

    pythonProcess.stdout.on('data', (data) => {
      stdout += data.toString()
    })

    pythonProcess.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    pythonProcess.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Python worker exited with code ${code}. stderr: ${stderr}`))
        return
      }

      try {
        const lines = stdout.trim().split('\n')
        const lastLine = lines[lines.length - 1]
        const response: WorkerResponse = JSON.parse(lastLine)
        resolve(response)
      } catch (error) {
        reject(
          new Error(
            `Failed to parse worker response: ${(error as Error).message}. stdout: ${stdout}`
          )
        )
      }
    })

    pythonProcess.on('error', (error) => {
      reject(new Error(`Failed to spawn Python worker: ${error.message}`))
    })

    try {
      pythonProcess.stdin.write(JSON.stringify(request) + '\n')
      pythonProcess.stdin.end()
    } catch (error) {
      reject(new Error(`Failed to write to worker stdin: ${(error as Error).message}`))
    }
  })
}

export function createDynamicDependenciesHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: DynamicDependenciesDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const runWorker = dependencies?.callWorker || callStaticWorker

    try {
      const input = DynamicDependenciesInputSchema.parse(args)

      let sampleId = input.sample_id || 'dynamic-probe'
      let samplePath = ''
      if (input.sample_id) {
        const sample = database.findSample(input.sample_id)
        if (!sample) {
          return {
            ok: false,
            errors: [`Sample not found: ${input.sample_id}`],
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
            },
          }
        }

        const workspace = await workspaceManager.getWorkspace(input.sample_id)
        const fs = await import('fs/promises')
        const files = await fs.readdir(workspace.original)
        if (files.length > 0) {
          samplePath = path.join(workspace.original, files[0])
        }
      }

      const workerRequest: WorkerRequest = {
        job_id: uuidv4(),
        tool: TOOL_NAME,
        sample: {
          sample_id: sampleId,
          path: samplePath,
        },
        args: {},
        context: {
          request_time_utc: new Date().toISOString(),
          policy: {
            allow_dynamic: false,
            allow_network: false,
          },
          versions: {
            tool_version: TOOL_VERSION,
          },
        },
      }

      let workerResponse: WorkerResponse
      try {
        workerResponse = await runWorker(workerRequest)
      } catch (error) {
        return buildBootstrapFallback(startTime, (error as Error).message)
      }

      if (!workerResponse.ok) {
        return buildBootstrapFallback(
          startTime,
          workerResponse.errors.join('; ') || 'dynamic dependency probe failed'
        )
      }

      const rawData = (workerResponse.data || {}) as Record<string, unknown>
      const analysisBackends = resolveAnalysisBackends()
      const qilingRootfs = process.env.QILING_ROOTFS?.trim()
      let qilingRootfsReady = false
      if (qilingRootfs) {
        try {
          qilingRootfsReady = (await fs.stat(qilingRootfs)).isDirectory()
        } catch {
          qilingRootfsReady = false
        }
      }

      const mergedComponents: Record<string, Record<string, unknown>> = {
        ...(typeof rawData.components === 'object' && rawData.components ? (rawData.components as Record<string, unknown>) : {}),
        frida_cli: {
          ...analysisBackends.frida_cli,
          caveat: 'Frida CLI provides helper commands such as frida-ps and frida-trace but still depends on target-side instrumentation support.',
        },
        qiling: {
          ...analysisBackends.qiling,
          rootfs_path: qilingRootfs || null,
          rootfs_ready: qilingRootfs ? qilingRootfsReady : null,
          caveat: 'Qiling needs an externally supplied Windows rootfs and registry snapshot; the server does not bundle Microsoft DLLs.',
        },
        angr: {
          ...analysisBackends.angr,
          caveat: 'angr is exposed through ANGR_PYTHON and is intended for targeted advanced analysis, not as a default background dependency for every workflow.',
        },
        panda: {
          ...analysisBackends.panda,
          caveat: 'PANDA/pandare availability here reflects Python-side readiness; full record/replay workflows may still require additional host/runtime tuning.',
        },
        wine: {
          ...analysisBackends.wine,
          caveat: 'Wine is a Linux-hosted compatibility layer, not a full Windows desktop or kernel debugger.',
        },
        winedbg: {
          ...analysisBackends.winedbg,
          caveat: 'winedbg covers basic debugger-style flows for Wine-hosted targets, not WinDbg/x64dbg-equivalent kernel or GUI scenarios.',
        },
      }

      const availableComponents = [
        ...new Set(
          [
            ...(Array.isArray(rawData.available_components)
              ? rawData.available_components.map((item) => String(item))
              : []),
            ...Object.entries(mergedComponents)
              .filter(([, payload]) => Boolean((payload as Record<string, unknown>)?.available))
              .map(([name]) => name),
          ].filter(Boolean)
        ),
      ]

      let status = String(rawData.status || 'partial')
      const criticalReadiness = [
        (mergedComponents.speakeasy as Record<string, unknown> | undefined)?.available,
        (mergedComponents.frida as Record<string, unknown> | undefined)?.available,
        (mergedComponents.psutil as Record<string, unknown> | undefined)?.available,
        (mergedComponents.frida_cli as Record<string, unknown> | undefined)?.available,
        (mergedComponents.qiling as Record<string, unknown> | undefined)?.available,
        (mergedComponents.angr as Record<string, unknown> | undefined)?.available,
        (mergedComponents.panda as Record<string, unknown> | undefined)?.available,
        (mergedComponents.wine as Record<string, unknown> | undefined)?.available,
        (mergedComponents.winedbg as Record<string, unknown> | undefined)?.available,
      ].filter((item): item is boolean => typeof item === 'boolean')
      const criticalReadyCount = criticalReadiness.filter(Boolean).length
      if (criticalReadiness.length > 0) {
        if (criticalReadyCount === criticalReadiness.length && (!qilingRootfs || qilingRootfsReady)) {
          status = 'ready'
        } else if (criticalReadyCount > 0) {
          status = 'partial'
        } else {
          status = 'bootstrap_required'
        }
      }

      const recommendations = Array.isArray(rawData.recommendations)
        ? [...new Set(rawData.recommendations.map((item) => String(item)))]
        : []
      if (!analysisBackends.frida_cli.available) {
        recommendations.push('Install frida-tools so frida-ps and frida-trace are available for automated runtime workflows.')
      }
      if (!analysisBackends.qiling.available) {
        recommendations.push('Install Qiling for automated Windows API emulation and hook-based dynamic analysis.')
      } else if (!qilingRootfs || !qilingRootfsReady) {
        recommendations.push('Mount a Windows Qiling rootfs and set QILING_ROOTFS before relying on Qiling-backed automation.')
      }
      if (!analysisBackends.angr.available) {
        recommendations.push('Install angr in an isolated Python environment and set ANGR_PYTHON for targeted CFG and path exploration.')
      }
      if (!analysisBackends.panda.available) {
        recommendations.push('Install pandare if you want PANDA-style record/replay helper workflows.')
      }
      if (!analysisBackends.wine.available || !analysisBackends.winedbg.available) {
        recommendations.push('Install Wine plus winedbg for Linux-hosted Windows execution and debugger-style troubleshooting.')
      }
      const normalizedRecommendations = [...new Set(recommendations)]
      const shouldAddSetupActions = status !== 'ready'
      const setupActions = shouldAddSetupActions
        ? mergeSetupActions(
            buildBaselinePythonSetupActions(),
            buildCoreLinuxToolchainSetupActions(),
            buildDynamicDependencySetupActions()
          )
        : []
      const requiredUserInputs = shouldAddSetupActions
        ? mergeRequiredUserInputs(buildDynamicDependencyRequiredUserInputs())
        : []

      return {
        ok: true,
        data: {
          ...rawData,
          status,
          available_components: availableComponents,
          components: mergedComponents,
          recommendations: normalizedRecommendations,
          setup_actions: setupActions,
          required_user_inputs: requiredUserInputs,
        },
        warnings: workerResponse.warnings,
        errors: workerResponse.errors,
        artifacts: workerResponse.artifacts as ArtifactRef[],
        metrics: {
          ...workerResponse.metrics,
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
