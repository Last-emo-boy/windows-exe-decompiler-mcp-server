/**
 * yara.scan tool implementation
 * Scans PE files using YARA rules to identify malware families and packers
 * Requirements: 5.1, 5.2, 5.3
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

const TOOL_NAME = 'yara.scan'
const TOOL_VERSION = '1.0.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000 // 30 days

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for yara.scan tool
 * Requirements: 5.1, 5.2
 */
export const YaraScanInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  rule_set: z.string().describe('Rule set name (e.g., malware_families, packers)'),
  timeout_ms: z.number().int().min(1000).optional().default(30000).describe('Timeout in milliseconds'),
  rule_tier: z
    .enum(['production', 'experimental', 'test', 'all'])
    .optional()
    .default('production')
    .describe('Rule quality tier. Default production excludes weak test rules.'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
})

export type YaraScanInput = z.infer<typeof YaraScanInputSchema>

/**
 * Output schema for yara.scan tool
 * Requirements: 5.2, 5.3
 */
export const YaraScanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    matches: z.array(z.object({
      rule: z.string(),
      tags: z.array(z.string()),
      meta: z.record(z.any()),
      strings: z.array(z.object({
        identifier: z.string(),
        offset: z.number(),
        matched_data: z.string(),
        location: z.object({
          section: z.string().nullable().optional(),
          offset_in_section: z.number().nullable().optional(),
          rva: z.number().nullable().optional(),
          distance_to_entrypoint: z.number().nullable().optional(),
          function_hint: z.object({
            name: z.string(),
            address: z.string(),
            proximity: z.string(),
          }).nullable().optional(),
        }).optional(),
      })),
      confidence: z.object({
        level: z.enum(['low', 'medium', 'high']),
        score: z.number(),
        reason: z.string(),
      }).optional(),
      evidence: z.object({
        import_dll_hits: z.array(z.string()),
        import_api_hits: z.array(z.string()),
        section_hits: z.array(z.string()).optional(),
        near_entrypoint_hits: z.number().optional(),
        string_only: z.boolean(),
      }).optional(),
      inference: z.object({
        classification: z.string(),
        summary: z.string(),
      }).optional(),
    })),
    ruleset_version: z.string(),
    timed_out: z.boolean(),
    rule_set: z.string(),
    rule_tier: z.string().optional(),
    rule_files: z.array(z.string()).optional(),
    confidence_summary: z.object({
      high: z.number(),
      medium: z.number(),
      low: z.number(),
    }).optional(),
    import_evidence: z.object({
      dll_count: z.number(),
      api_count: z.number(),
    }).optional(),
    offset_mapping: z.object({
      parser: z.string().nullable().optional(),
      sections_count: z.number().optional(),
      entry_point: z.record(z.any()).optional(),
    }).optional(),
    quality_notes: z.array(z.string()).optional(),
  }).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({
    elapsed_ms: z.number(),
    tool: z.string(),
  }).optional(),
})

export type YaraScanOutput = z.infer<typeof YaraScanOutputSchema>

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for yara.scan
 */
export const yaraScanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: '使用 YARA 规则扫描样本，识别已知的恶意软件家族和加壳器',
  inputSchema: YaraScanInputSchema,
  outputSchema: YaraScanOutputSchema,
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
 * Create yara.scan tool handler
 * Requirements: 5.1, 5.2, 5.3, 5.5
 */
export function createYaraScanHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = args as YaraScanInput
    const startTime = Date.now()

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
      // Requirement: 5.5 - Cache key includes ruleset version
      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: { 
          rule_set: input.rule_set,
          timeout_ms: input.timeout_ms,
          rule_tier: input.rule_tier,
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

      // 4. Get sample path from workspace
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

      // 5. Prepare worker request
      const workerRequest: WorkerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        args: {
          rule_set: input.rule_set,
          timeout_ms: input.timeout_ms,
          rule_tier: input.rule_tier,
        },
        toolVersion: TOOL_VERSION,
      })

      // 6. Call Static Worker
      // Requirements: 5.1, 5.2, 5.3
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

      // 7. Cache result
      // Requirement: 5.5 - Cache with ruleset version for invalidation
      await cacheManager.setCachedResult(cacheKey, workerResponse.data, CACHE_TTL_MS)

      // 8. Return result
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
