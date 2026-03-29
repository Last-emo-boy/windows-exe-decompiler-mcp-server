/**
 * frida.script.inject tool
 * Inject custom or pre-built Frida scripts into running processes.
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

const TOOL_NAME = 'frida.script.inject'
const TOOL_VERSION = '0.1.0'

export const FridaScriptInjectInputSchema = z.object({
  sample_id: z
    .string()
    .optional()
    .describe('Sample ID for context (optional, used for artifact organization)'),
  pid: z.number().int().positive().describe('Process ID to inject script into'),
  script_name: z
    .enum([
      'api_trace',
      'string_decoder',
      'anti_debug_bypass',
      'crypto_finder',
      'file_registry_monitor',
      'default',
    ])
    .optional()
    .describe('Pre-built Frida script to use'),
  script_content: z
    .string()
    .optional()
    .describe('Custom Frida JavaScript script content (overrides script_name)'),
  script_path: z
    .string()
    .optional()
    .describe('Path to a custom Frida script file (overrides script_name and script_content)'),
  script_parameters: z
    .record(z.any())
    .optional()
    .describe('Parameters to pass to the Frida script (e.g., module filters, function patterns)'),
  timeout_sec: z
    .number()
    .int()
    .min(5)
    .max(300)
    .optional()
    .default(30)
    .describe('Script execution timeout in seconds'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist script results as artifact'),
  register_analysis: z
    .boolean()
    .optional()
    .default(true)
    .describe('Register analysis record in database'),
})

export type FridaScriptInjectInput = z.infer<typeof FridaScriptInjectInputSchema>

const ScriptResultSchema = z.object({
  type: z.string(),
  function: z.string().optional(),
  module: z.string().optional(),
  args: z.array(z.any()).optional(),
  value: z.string().optional(),
  data_preview: z.string().optional(),
  timestamp: z.number().optional(),
  thread_id: z.number().optional(),
})

export const FridaScriptInjectOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      session_id: z.string(),
      pid: z.number(),
      script_name: z.string(),
      script_path: z.string().optional(),
      status: z.enum(['completed', 'failed', 'timeout', 'error']),
      messages_captured: z.number(),
      results: z.array(ScriptResultSchema),
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

export type FridaScriptInjectOutput = z.infer<typeof FridaScriptInjectOutputSchema>

export const fridaScriptInjectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Inject a custom or pre-built Frida JavaScript into a running process for dynamic analysis.',
  inputSchema: FridaScriptInjectInputSchema,
  outputSchema: FridaScriptInjectOutputSchema,
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

interface FridaScriptInjectDependencies {
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
      script_name: 'none',
      status: 'error',
      messages_captured: 0,
      results: [],
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

async function readScriptFile(scriptPath: string): Promise<string> {
  const fs = await import('fs/promises')
  const path = await import('path')

  // Try absolute path first
  try {
    return await fs.readFile(scriptPath, 'utf-8')
  } catch (e) {
    // Try relative to package
    const packageRelativePath = resolvePackagePath('frida_scripts', path.basename(scriptPath))
    try {
      return await fs.readFile(packageRelativePath, 'utf-8')
    } catch (e2) {
      throw new Error(`Script file not found: ${scriptPath}`)
    }
  }
}

export function createFridaScriptInjectHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: FridaScriptInjectDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const runWorker = dependencies?.callWorker || callFridaWorker

    try {
      const input = FridaScriptInjectInputSchema.parse(args)

      // Validate: either script_content, script_path, or script_name must be provided
      if (!input.script_content && !input.script_path && !input.script_name) {
        return {
          ok: false,
          errors: ['One of script_content, script_path, or script_name must be provided'],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      // Determine script to use
      let scriptContent = input.script_content
      let scriptPath = input.script_path
      let scriptName = input.script_name || 'custom'

      // If script_path provided, read file
      if (input.script_path) {
        try {
          scriptContent = await readScriptFile(input.script_path)
          scriptName = `file:${input.script_path}`
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

      // Build sample context (optional)
      let sampleContext = {
        sample_id: input.sample_id || 'unknown',
        path: '',
      }

      if (input.sample_id) {
        const sample = database.findSample(input.sample_id)
        if (sample) {
          try {
            const workspace = await workspaceManager.getWorkspace(input.sample_id)
            const fs = await import('fs/promises')
            const files = await fs.readdir(workspace.original)
            if (files.length > 0) {
              sampleContext.path = files[0]
            }
          } catch {
            // Ignore errors reading sample context - worker can still run
          }
        }
      }

      // Build worker request
      const workerRequest: WorkerRequest = {
        job_id: randomUUID(),
        tool: 'frida.script.inject',
        sample: sampleContext,
        args: {
          pid: input.pid,
          script_name: input.script_name,
          script_content: scriptContent,
          script_path: scriptPath,
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
        const errorMsg = workerResponse.errors.join('; ') || 'Frida script injection failed'
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
      const results = Array.isArray(rawData.results) ? rawData.results : []

      // Build artifact if persist requested
      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && results.length > 0) {
        const fs = await import('fs/promises')
        const artifactDir = await workspaceManager.ensureDirectory(
          input.sample_id || 'unknown',
          'dynamic'
        )
        const artifactFilename = `frida_inject_${Date.now()}.json`
        const artifactPath = `${artifactDir}/${artifactFilename}`

        const artifactContent = {
          session_id: rawData.session_id,
          sample_id: input.sample_id || 'unknown',
          pid: input.pid,
          captured_at: new Date().toISOString(),
          script_name: scriptName,
          script_path: scriptPath,
          parameters: input.script_parameters,
          results: results,
          messages_captured: rawData.messages_captured || results.length,
        }

        await fs.writeFile(artifactPath, JSON.stringify(artifactContent, null, 2), 'utf-8')

        const sha256 = (data: string) => createHash('sha256').update(data).digest('hex')
        const artifactId = `frida_inject_${sha256(artifactContent.captured_at)}`

        artifacts.push({
          id: artifactId,
          type: 'script_injection',
          path: artifactPath,
          sha256: sha256(JSON.stringify(artifactContent)),
          mime: 'application/json',
          metadata: {
            session_tag: `frida_inject/${scriptName}/${Date.now()}`,
            captured_at: artifactContent.captured_at,
            script_name: scriptName,
            pid: input.pid,
          },
        })
      }

      return {
        ok: true,
        data: {
          session_id: rawData.session_id,
          pid: input.pid,
          script_name: scriptName,
          script_path: scriptPath,
          status: 'completed',
          messages_captured: rawData.messages_captured || results.length,
          results: results.slice(0, 500), // Limit returned results
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
