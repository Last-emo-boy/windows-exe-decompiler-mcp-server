/**
 * frida.runtime.instrument tool
 * Dynamic instrumentation using Frida for runtime API tracing and behavior analysis.
 */

import { spawn } from 'child_process'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { resolvePackagePath } from '../runtime-paths.js'
import {
  RequiredUserInputSchema,
  SetupActionSchema,
  buildFridaSetupActions,
  buildFridaRequiredUserInputs,
} from '../setup-guidance.js'

const TOOL_NAME = 'frida.runtime.instrument'
const TOOL_VERSION = '0.1.0'

export const FridaRuntimeInstrumentInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  mode: z
    .enum(['spawn', 'attach'])
    .optional()
    .default('spawn')
    .describe('Instrumentation mode: spawn for new process, attach for running process'),
  pid: z
    .number()
    .int()
    .positive()
    .optional()
    .describe('Process ID to attach to (required for attach mode)'),
  script_name: z
    .enum(['api_trace', 'string_decoder', 'anti_debug_bypass', 'crypto_finder', 'file_registry_monitor', 'default'])
    .optional()
    .default('api_trace')
    .describe('Pre-built Frida script to use'),
  script_content: z
    .string()
    .optional()
    .describe('Custom Frida JavaScript script content (overrides script_name)'),
  script_parameters: z
    .record(z.any())
    .optional()
    .describe('Parameters to pass to the Frida script'),
  timeout_sec: z
    .number()
    .int()
    .min(5)
    .max(300)
    .optional()
    .default(30)
    .describe('Execution timeout in seconds'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist trace output as artifact'),
  register_analysis: z
    .boolean()
    .optional()
    .default(true)
    .describe('Register analysis record in database'),
})

export type FridaRuntimeInstrumentInput = z.infer<typeof FridaRuntimeInstrumentInputSchema>

const TraceEntrySchema = z.object({
  type: z.string(),
  function: z.string().optional(),
  module: z.string().optional(),
  args: z.array(z.any()).optional(),
  timestamp: z.number().optional(),
  thread_id: z.number().optional(),
})

const TraceSummarySchema = z.object({
  total_calls: z.number(),
  unique_functions: z.number(),
  modules_touched: z.array(z.string()),
  duration_ms: z.number(),
})

export const FridaRuntimeInstrumentOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      session_id: z.string(),
      pid: z.number().nullable(),
      mode: z.string(),
      script_name: z.string(),
      status: z.enum(['completed', 'failed', 'timeout', 'error']),
      trace_summary: TraceSummarySchema,
      traces: z.array(TraceEntrySchema),
      warnings: z.array(z.string()),
      errors: z.array(z.string()),
      setup_actions: z.array(SetupActionSchema).optional(),
      required_user_inputs: z.array(RequiredUserInputSchema).optional(),
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

export type FridaRuntimeInstrumentOutput = z.infer<typeof FridaRuntimeInstrumentOutputSchema>

export const fridaRuntimeInstrumentToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Instrument a Windows PE sample at runtime using Frida for dynamic API tracing and behavior analysis. Supports spawn and attach modes with pre-built or custom scripts.',
  inputSchema: FridaRuntimeInstrumentInputSchema,
  outputSchema: FridaRuntimeInstrumentOutputSchema,
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

interface FridaRuntimeInstrumentDependencies {
  callWorker?: (request: WorkerRequest) => Promise<WorkerResponse>
}

function normalizeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

async function callFridaWorker(request: WorkerRequest): Promise<WorkerResponse> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath('workers', 'frida_worker.py')
    const pythonCommand = process.platform === 'win32' ? 'python' : 'python3'
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
        reject(new Error(`Frida worker timed out after 60s`))
      })
    }, 60000)

    pythonProcess.stdout.on('data', (data) => {
      stdout += data.toString()
    })

    pythonProcess.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    pythonProcess.on('error', (error) => {
      onDone(() => {
        clearTimeout(timer)
        reject(new Error(`Failed to spawn Frida worker: ${error.message}`))
      })
    })

    pythonProcess.on('close', (code) => {
      onDone(() => {
        clearTimeout(timer)
        if (code !== 0) {
          reject(new Error(`Frida worker exited with code ${code}. stderr: ${stderr}`))
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
              `Failed to parse Frida worker response: ${normalizeError(error)}. stdout: ${stdout}`
            )
          )
        }
      })
    })

    try {
      pythonProcess.stdin.write(JSON.stringify(request) + '\n')
      pythonProcess.stdin.end()
    } catch (error) {
      onDone(() => {
        clearTimeout(timer)
        reject(new Error(`Failed to write to Frida worker: ${normalizeError(error)}`))
      })
    }
  })
}

function buildFridaUnavailableResponse(startTime: number, errorMessage: string): WorkerResult {
  return {
    ok: true,
    data: {
      session_id: null,
      pid: null,
      mode: 'spawn',
      script_name: 'none',
      status: 'error',
      trace_summary: {
        total_calls: 0,
        unique_functions: 0,
        modules_touched: [],
        duration_ms: 0,
      },
      traces: [],
      warnings: [`Frida is not available: ${errorMessage}`],
      errors: [errorMessage],
      setup_actions: buildFridaSetupActions(),
      required_user_inputs: buildFridaRequiredUserInputs(),
    },
    metrics: {
      elapsed_ms: Date.now() - startTime,
      tool: TOOL_NAME,
    },
  }
}

export function createFridaRuntimeInstrumentHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: FridaRuntimeInstrumentDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const runWorker = dependencies?.callWorker || callFridaWorker

    try {
      const input = FridaRuntimeInstrumentInputSchema.parse(args)

      // Get sample path
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

      let samplePath = ''
      try {
        const workspace = await workspaceManager.getWorkspace(input.sample_id)
        const fs = await import('fs/promises')
        const files = await fs.readdir(workspace.original)
        if (files.length > 0) {
          samplePath = files[0]
        }
      } catch {
        // Ignore errors reading sample - worker can still run with sample_id context
      }

      // If samplePath is empty, continue with sample_id context - worker can handle it
      // This allows graceful degradation when workspace files are missing

      // Validate attach mode requires PID
      if (input.mode === 'attach' && !input.pid) {
        return {
          ok: false,
          errors: ['PID is required for attach mode'],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      // Build worker request
      const workerRequest: WorkerRequest = {
        job_id: randomUUID(),
        tool: 'frida.runtime.instrument',
        sample: {
          sample_id: input.sample_id,
          path: samplePath,
        },
        args: {
          mode: input.mode,
          pid: input.pid,
          script_name: input.script_name,
          script_content: input.script_content,
          parameters: input.script_parameters,
          timeout_sec: input.timeout_sec,
        },
        context: {
          request_time_utc: new Date().toISOString(),
          policy: {
            allow_dynamic: true,
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
        const errorStr = normalizeError(error)
        if (errorStr.includes('Frida is not installed') || errorStr.includes('ModuleNotFoundError')) {
          return buildFridaUnavailableResponse(startTime, 'Frida runtime not installed. Run: pip install frida')
        }
        return {
          ok: false,
          errors: [errorStr],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      if (!workerResponse.ok) {
        const errorMsg = workerResponse.errors.join('; ') || 'Frida instrumentation failed'
        if (errorMsg.toLowerCase().includes('not installed') || errorMsg.toLowerCase().includes('import')) {
          return buildFridaUnavailableResponse(startTime, errorMsg)
        }
        return {
          ok: false,
          errors: [errorMsg],
          warnings: workerResponse.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      // Process response data
      const rawData = (workerResponse.data || {}) as Record<string, any>
      const traces = Array.isArray(rawData.traces) ? rawData.traces : []
      const traceSummary = {
        total_calls: rawData.trace_count || traces.length,
        unique_functions: new Set(traces.map((t: any) => t.function).filter(Boolean)).size,
        modules_touched: [...new Set(traces.map((t: any) => t.module).filter(Boolean))],
        duration_ms: rawData.duration_ms || 0,
      }

      // Build artifact if persist requested
      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && traces.length > 0) {
        const fs = await import('fs/promises')
        const artifactDir = await workspaceManager.ensureDirectory(input.sample_id, 'dynamic')
        const artifactFilename = `frida_trace_${Date.now()}.json`
        const artifactPath = `${artifactDir}/${artifactFilename}`

        const artifactContent = {
          session_id: rawData.session_id,
          sample_id: input.sample_id,
          captured_at: new Date().toISOString(),
          mode: input.mode,
          script_name: input.script_name,
          traces: traces,
          summary: traceSummary,
        }

        await fs.writeFile(artifactPath, JSON.stringify(artifactContent, null, 2), 'utf-8')

        const sha256 = (data: string) => createHash('sha256').update(data).digest('hex')
        const artifactId = `frida_trace_${sha256(artifactContent.captured_at)}`

        artifacts.push({
          id: artifactId,
          type: 'dynamic_trace',
          path: artifactPath,
          sha256: sha256(JSON.stringify(artifactContent)),
          mime: 'application/json',
          metadata: {
            session_tag: `frida/${input.script_name}/${Date.now()}`,
            captured_at: artifactContent.captured_at,
            script_name: input.script_name,
            mode: input.mode,
          },
        })
      }

      return {
        ok: true,
        data: {
          session_id: rawData.session_id,
          pid: rawData.pid || null,
          mode: input.mode,
          script_name: input.script_name,
          status: 'completed',
          trace_summary: traceSummary,
          traces: traces.slice(0, 500), // Limit returned traces
          warnings: workerResponse.warnings,
          errors: workerResponse.errors,
        },
        warnings: workerResponse.warnings,
        errors: workerResponse.errors,
        artifacts,
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
