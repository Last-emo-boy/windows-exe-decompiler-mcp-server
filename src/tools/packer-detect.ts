/**
 * packer.detect tool implementation
 * Detects if a PE file is packed and identifies the packer used
 * Requirements: 7.1, 7.2, 7.3
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import { v4 as uuidv4 } from 'uuid'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { generateCacheKey } from '../cache-manager.js'
import { resolvePackagePath } from '../runtime-paths.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import { inspectSampleWorkspace, formatMissingOriginalError, resolvePrimarySamplePath } from '../sample-workspace.js'

// ============================================================================
// Constants
// ============================================================================

/**
 * Get the correct Python command for the current platform
 */
function getPythonCommand(): string {
  return process.platform === 'win32' ? 'python' : 'python3'
}

const TOOL_NAME = 'packer.detect'
const TOOL_VERSION = '1.0.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000 // 30 days
const DEFAULT_ENGINES: Array<'yara' | 'entropy' | 'entrypoint'> = ['yara', 'entropy', 'entrypoint']

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for packer.detect tool
 * Requirements: 7.1
 */
export const PackerDetectInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  engines: z.array(z.enum(['yara', 'entropy', 'entrypoint']))
    .optional()
    .default(['yara', 'entropy', 'entrypoint'])
    .describe('Detection engines to use'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
})

export type PackerDetectInput = z.infer<typeof PackerDetectInputSchema>

/**
 * Output schema for packer.detect tool
 * Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
 */
export const PackerDetectOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    packed: z.boolean(),
    confidence: z.number(),
    detections: z.array(z.object({
      method: z.string(),
      name: z.string(),
      confidence: z.number(),
      details: z.record(z.any()),
    })),
    methods: z.array(z.string()),
    confidence_breakdown: z.record(z.number()).optional(),
    feature_fusion: z.record(z.any()).optional(),
    evidence: z.record(z.any()).optional(),
    inference: z.record(z.any()).optional(),
  }).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({
    elapsed_ms: z.number(),
    tool: z.string(),
    engines_used: z.array(z.string()).optional(),
  }).optional(),
})

export type PackerDetectOutput = z.infer<typeof PackerDetectOutputSchema>

function normalizeEngineList(engines: string[] | undefined, sort: boolean = true): string[] {
  const selected = engines && engines.length > 0 ? engines : DEFAULT_ENGINES
  const normalized = selected
    .map((engine) => String(engine).toLowerCase().trim())
    .filter((engine) => engine === 'yara' || engine === 'entropy' || engine === 'entrypoint')
  const deduped = Array.from(new Set(normalized))
  return sort ? deduped.sort() : deduped
}

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for packer.detect
 */
export const packerDetectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: '自动检测 PE 文件是否加壳，使用 YARA 规则、节区熵值分析和入口点检查来识别常见加壳器（如 UPX、Themida、VMProtect）',
  inputSchema: PackerDetectInputSchema,
  outputSchema: PackerDetectOutputSchema,
}

// ============================================================================
// Worker Communication
// ============================================================================

/**
 * Worker request structure
 */
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

/**
 * Worker response structure
 */
interface WorkerResponse {
  job_id: string
  ok: boolean
  warnings: string[]
  errors: string[]
  data: unknown
  artifacts: unknown[]
  metrics: Record<string, unknown>
}

/**
 * Spawn Python Static Worker and communicate via stdin/stdout JSON protocol
 * 
 * Requirements: Worker communication
 * 
 * @param request - Worker request object
 * @returns Worker response object
 */
async function callStaticWorker(request: WorkerRequest): Promise<WorkerResponse> {
  return new Promise((resolve, reject) => {
    // Get Python worker path
    const workerPath = resolvePackagePath('workers', 'static_worker.py')
    
    // Spawn Python process
    const pythonProcess = spawn(getPythonCommand(), [workerPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''

    // Collect stdout
    pythonProcess.stdout.on('data', (data) => {
      stdout += data.toString()
    })

    // Collect stderr
    pythonProcess.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    // Handle process exit
    pythonProcess.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Python worker exited with code ${code}. stderr: ${stderr}`))
        return
      }

      // Parse response from stdout
      try {
        const lines = stdout.trim().split('\n')
        const lastLine = lines[lines.length - 1]
        const response: WorkerResponse = JSON.parse(lastLine)
        resolve(response)
      } catch (error) {
        reject(new Error(`Failed to parse worker response: ${(error as Error).message}. stdout: ${stdout}`))
      }
    })

    // Handle process error
    pythonProcess.on('error', (error) => {
      reject(new Error(`Failed to spawn Python worker: ${error.message}`))
    })

    // Send request to worker via stdin
    try {
      pythonProcess.stdin.write(JSON.stringify(request) + '\n')
      pythonProcess.stdin.end()
    } catch (error) {
      reject(new Error(`Failed to write to worker stdin: ${(error as Error).message}`))
    }
  })
}

// ============================================================================
// Tool Handler
// ============================================================================

/**
 * Create packer.detect tool handler
 * Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
 */
export function createPackerDetectHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = args as PackerDetectInput
    const startTime = Date.now()
    const requestEngines = normalizeEngineList(input.engines, false)
    const cacheEngines = normalizeEngineList(input.engines, true)

    try {
      // 1. Validate sample exists
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }

      // 2. Generate cache key
      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          engines: cacheEngines,
        },
      })

      // 3. Check cache
      if (!input.force_refresh) {
        const cachedLookup = await lookupCachedResult(cacheManager, cacheKey)
        if (cachedLookup) {
          return {
            ok: true,
            data: cachedLookup.data,
            warnings: ['Result from cache', formatCacheWarning(cachedLookup.metadata)],
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
              cached: true,
              cache_key: cachedLookup.metadata.key,
              cache_tier: cachedLookup.metadata.tier,
              cache_created_at: cachedLookup.metadata.createdAt,
              cache_expires_at: cachedLookup.metadata.expiresAt,
              cache_hit_at: cachedLookup.metadata.fetchedAt,
            },
          }
        }
      }

      // 4. Get sample path from workspace, allowing legacy sibling workspace fallback
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      if (!samplePath) {
        const integrity = await inspectSampleWorkspace(workspaceManager, input.sample_id)
        return {
          ok: false,
          errors: [formatMissingOriginalError(input.sample_id, integrity)],
        }
      }

      // 5. Prepare worker request
      const workerRequest: WorkerRequest = {
        job_id: uuidv4(),
        tool: TOOL_NAME,
        sample: {
          sample_id: input.sample_id,
          path: samplePath,
        },
        args: {
          engines: requestEngines,
        },
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

      // 6. Call Static Worker
      // Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
      const workerResponse = await callStaticWorker(workerRequest)

      if (!workerResponse.ok) {
        return {
          ok: false,
          errors: workerResponse.errors,
          warnings: workerResponse.warnings,
        }
      }

      // Extract the result from the worker response
      const responseData = workerResponse.data as { result: unknown; warnings: string[]; metrics: Record<string, unknown> }
      const packerResult = responseData.result

      // 7. Cache result
      await cacheManager.setCachedResult(cacheKey, packerResult, CACHE_TTL_MS)

      // 8. Return result
      return {
        ok: true,
        data: packerResult,
        warnings: input.force_refresh
          ? [
              'force_refresh=true; bypassed cache lookup',
              ...((responseData.warnings || workerResponse.warnings || []) as string[]),
            ]
          : responseData.warnings || workerResponse.warnings,
        errors: workerResponse.errors,
        artifacts: workerResponse.artifacts as ArtifactRef[],
        metrics: {
          ...responseData.metrics,
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
