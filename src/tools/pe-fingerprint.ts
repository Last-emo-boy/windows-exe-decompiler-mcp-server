/**
 * pe.fingerprint tool implementation
 * Extracts PE file fingerprint information
 * Requirements: 2.1, 2.2, 2.3, 2.5
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import path from 'path'
import { v4 as uuidv4 } from 'uuid'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { generateCacheKey } from '../cache-manager.js'
import { resolvePackagePath } from '../runtime-paths.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker as callPooledStaticWorker,
} from './static-worker-client.js'

// ============================================================================
// Constants
// ============================================================================

const TOOL_NAME = 'pe.fingerprint'
const TOOL_VERSION = '1.0.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000 // 30 days

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for pe.fingerprint tool
 * Requirements: 2.1, 2.3
 */
export const PEFingerprintInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  fast: z.boolean().optional().default(false).describe('Fast mode (skip section entropy and signature info)'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
})

export type PEFingerprintInput = z.infer<typeof PEFingerprintInputSchema>

/**
 * Output schema for pe.fingerprint tool
 * Requirements: 2.1, 2.2, 2.3
 */
export const PEFingerprintOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    machine: z.number(),
    machine_name: z.string(),
    subsystem: z.number(),
    subsystem_name: z.string(),
    timestamp: z.number(),
    timestamp_iso: z.string().nullable(),
    imphash: z.string().nullable(),
    entry_point: z.number(),
    image_base: z.number(),
    sections: z.array(z.object({
      name: z.string(),
      virtual_address: z.number(),
      virtual_size: z.number(),
      raw_size: z.number(),
      entropy: z.number(),
      characteristics: z.number(),
    })).optional(),
    signature: z.object({
      present: z.boolean(),
      address: z.number().optional(),
      size: z.number().optional(),
      verified: z.boolean().optional(),
    }).optional(),
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

export type PEFingerprintOutput = z.infer<typeof PEFingerprintOutputSchema>

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for pe.fingerprint
 */
export const peFingerprintToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: '提取 PE 文件指纹信息（机器类型、子系统、时间戳、Imphash、节区熵值、签名）',
  inputSchema: PEFingerprintInputSchema,
  outputSchema: PEFingerprintOutputSchema,
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
 * Create pe.fingerprint tool handler
 * Requirements: 2.1, 2.2, 2.3, 2.5
 */
export function createPEFingerprintHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = args as PEFingerprintInput
    const startTime = Date.now()

    try {
      // 1. Generate cache key
      // Requirement: 2.5
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
        args: { fast: input.fast },
      })

      // 2. Check cache
      // Requirement: 2.5
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

      // 3. Get sample path from workspace
      const workspace = await workspaceManager.getWorkspace(input.sample_id)
      
      // Find the sample file in the original directory
      const fs = await import('fs/promises')
      const files = await fs.readdir(workspace.original)
      if (files.length === 0) {
        return {
          ok: false,
          errors: ['Sample file not found in workspace'],
        }
      }
      
      const samplePath = path.join(workspace.original, files[0])

      // 4. Prepare worker request
      const workerRequest: WorkerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        args: {
          fast: input.fast,
        },
        toolVersion: TOOL_VERSION,
      })

      // 5. Call Static Worker
      // Requirements: 2.1, 2.2, 2.3, 2.4
      const workerResponse = await callPooledStaticWorker(workerRequest, {
        database,
        family: 'static_python.preview',
      })

      if (!workerResponse.ok) {
        return {
          ok: false,
          errors: workerResponse.errors,
          warnings: workerResponse.warnings,
        }
      }

      // 6. Cache result
      // Requirement: 2.5 (30-day TTL)
      await cacheManager.setCachedResult(cacheKey, workerResponse.data, CACHE_TTL_MS)

      // 7. Return result
      return {
        ok: true,
        data:
          workerResponse.data && typeof workerResponse.data === 'object'
            ? {
                ...(workerResponse.data as Record<string, unknown>),
                worker_pool:
                  (workerResponse.metrics as Record<string, unknown> | undefined)?.worker_pool,
              }
            : workerResponse.data,
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
