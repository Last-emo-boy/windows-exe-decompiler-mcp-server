/**
 * pe.exports.extract tool implementation
 * Extracts PE file export table (function names, ordinals, addresses)
 * Requirements: 3.3
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

const TOOL_NAME = 'pe.exports.extract'
const TOOL_VERSION = '1.0.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000 // 30 days

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for pe.exports.extract tool
 * Requirements: 3.3
 */
export const PEExportsExtractInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
})

export type PEExportsExtractInput = z.infer<typeof PEExportsExtractInputSchema>

/**
 * Output schema for pe.exports.extract tool
 * Requirements: 3.3
 */
export const PEExportsExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    exports: z.array(z.object({
      ordinal: z.number(),
      address: z.number(),
      name: z.string().nullable(),
    })),
    forwarders: z.array(z.object({
      ordinal: z.number(),
      address: z.number(),
      name: z.string().nullable(),
      forwarder: z.string(),
    })),
    total_exports: z.number(),
    total_forwarders: z.number(),
    _parser: z.string().optional(),
    _pefile_error: z.string().optional(),
  }).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({
    elapsed_ms: z.number(),
    tool: z.string(),
  }).optional(),
})

export type PEExportsExtractOutput = z.infer<typeof PEExportsExtractOutputSchema>

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for pe.exports.extract
 */
export const peExportsExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: '提取 PE 文件的导出表（函数名称、序号、地址、转发器）',
  inputSchema: PEExportsExtractInputSchema,
  outputSchema: PEExportsExtractOutputSchema,
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
    const pythonCommand = process.platform === 'win32' ? 'python' : 'python3'
    const pythonProcess = spawn(pythonCommand, [workerPath], {
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
 * Create pe.exports.extract tool handler
 * Requirements: 3.3
 */
export function createPEExportsExtractHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = args as PEExportsExtractInput
    const startTime = Date.now()

    try {
      // 1. Generate cache key
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {},
      })

      // 2. Check cache
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

      // 3. Get sample path from workspace, allowing legacy sibling workspace fallback
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      if (!samplePath) {
        const integrity = await inspectSampleWorkspace(workspaceManager, input.sample_id)
        return {
          ok: false,
          errors: [formatMissingOriginalError(input.sample_id, integrity)],
        }
      }

      // 4. Prepare worker request
      const workerRequest: WorkerRequest = {
        job_id: uuidv4(),
        tool: TOOL_NAME,
        sample: {
          sample_id: input.sample_id,
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

      // 5. Call Static Worker
      // Requirements: 3.3
      const workerResponse = await callStaticWorker(workerRequest)

      if (!workerResponse.ok) {
        return {
          ok: false,
          errors: workerResponse.errors,
          warnings: workerResponse.warnings,
        }
      }

      // 6. Cache result
      await cacheManager.setCachedResult(cacheKey, workerResponse.data, CACHE_TTL_MS)

      // 7. Return result
      return {
        ok: true,
        data: workerResponse.data,
        warnings: input.force_refresh
          ? ['force_refresh=true; bypassed cache lookup', ...(workerResponse.warnings || [])]
          : workerResponse.warnings,
        errors: workerResponse.errors,
        artifacts: workerResponse.artifacts as ArtifactRef[],
        metrics: {
          ...workerResponse.metrics,
          elapsed_ms: Date.now() - startTime,
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
