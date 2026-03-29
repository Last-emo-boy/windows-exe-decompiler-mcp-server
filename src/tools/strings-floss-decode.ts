/**
 * strings.floss.decode tool implementation
 * Uses FLOSS tool to decode obfuscated strings from PE files
 * Requirements: 4.4, 4.5
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import path from 'path'
import { randomUUID } from 'crypto'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { JobQueue } from '../job-queue.js'
import { generateCacheKey } from '../cache-manager.js'
import { resolvePackagePath } from '../runtime-paths.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker as callPooledStaticWorker,
} from './static-worker-client.js'
import {
  buildEnrichedStringBundle,
  EnrichedStringBundleSchema,
} from '../string-xref-analysis.js'
import {
  ENRICHED_STRING_ANALYSIS_ARTIFACT_TYPE,
  persistStringXrefJsonArtifact,
} from '../string-xref-artifacts.js'
import {
  buildDeferredToolResponse,
  shouldDeferLargeSample,
} from '../nonblocking-analysis.js'

// ============================================================================
// Constants
// ============================================================================

const TOOL_NAME = 'strings.floss.decode'
const TOOL_VERSION = '1.0.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000 // 30 days
const DEFAULT_TIMEOUT = 60 // seconds

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for strings.floss.decode tool
 * Requirements: 4.4, 4.5
 */
export const StringsFlossDecodeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  timeout: z.number().int().min(1).optional().default(DEFAULT_TIMEOUT).describe('Timeout in seconds (default: 60)'),
  modes: z.array(z.enum(['static', 'stack', 'tight', 'decoded'])).optional().default(['decoded']).describe('Decoding modes to use'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
  defer_if_slow: z
    .boolean()
    .optional()
    .default(true)
    .describe('When true, FLOSS decoding may be deferred to the background queue instead of blocking the MCP request.'),
  enrich_result: z
    .boolean()
    .optional()
    .default(true)
    .describe('Attach analyst-oriented enriched string classification to decoded strings'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist decoded string intelligence as a JSON artifact for later reuse'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag used when persisting decoded string artifacts'),
})

export type StringsFlossDecodeInput = z.infer<typeof StringsFlossDecodeInputSchema>

/**
 * Output schema for strings.floss.decode tool
 * Requirements: 4.4, 4.5
 */
export const StringsFlossDecodeOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    status: z.enum(['ready', 'queued', 'partial']).optional(),
    sample_id: z.string().optional(),
    result_mode: z.enum(['full']).optional(),
    execution_state: z.enum(['inline', 'queued', 'partial', 'completed']).optional(),
    job_id: z.string().optional(),
    polling_guidance: z.any().optional(),
    recommended_next_tools: z.array(z.string()).optional(),
    next_actions: z.array(z.string()).optional(),
    decoded_strings: z.array(z.object({
      string: z.string(),
      offset: z.number(),
      type: z.string(),
      decoding_method: z.string().nullable(),
    })).optional(),
    count: z.number().optional(),
    timeout_occurred: z.boolean().optional(),
    partial_results: z.boolean().optional(),
    enriched: EnrichedStringBundleSchema.optional(),
    tooling: z.any().optional(),
  }).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({
    elapsed_ms: z.number(),
    tool: z.string(),
  }).optional(),
})

export type StringsFlossDecodeOutput = z.infer<typeof StringsFlossDecodeOutputSchema>

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for strings.floss.decode
 */
export const stringsFlossDecodeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Decode obfuscated strings with FLOSS and return compact enriched analyst labels for decoded output. ' +
    'Use this when you suspect stack/tight/decoded strings; use analysis.context.link to merge FLOSS output with raw strings and function attribution.',
  inputSchema: StringsFlossDecodeInputSchema,
  outputSchema: StringsFlossDecodeOutputSchema,
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

function normalizeStringsFlossDecodeData(
  payload: unknown,
  input: StringsFlossDecodeInput
): Record<string, unknown> {
  const data = payload && typeof payload === 'object' ? ({ ...(payload as Record<string, unknown>) }) : {}
  const decoded = Array.isArray(data.decoded_strings)
    ? data.decoded_strings
        .map((item) => {
          const entry = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
          if (typeof entry.string !== 'string') {
            return null
          }
          return {
            offset: Number(entry.offset || 0),
            string: entry.string,
            type: typeof entry.type === 'string' ? entry.type : null,
            decoding_method:
              typeof entry.decoding_method === 'string' ? entry.decoding_method : null,
          }
        })
        .filter(
          (
            item
          ): item is {
            offset: number
            string: string
            type: string | null
            decoding_method: string | null
          } => Boolean(item)
        )
    : []

  if (input.enrich_result !== false) {
    data.enriched = buildEnrichedStringBundle([], decoded, {
      maxRecords: 80,
      maxHighlights: 12,
    })
  }

  return data
}

// ============================================================================
// Tool Handler
// ============================================================================

/**
 * Create strings.floss.decode tool handler
 * Requirements: 4.4, 4.5
 */
export function createStringsFlossDecodeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  jobQueue?: JobQueue,
  options: { allowDeferred?: boolean } = {}
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = StringsFlossDecodeInputSchema.parse(args)
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
        args: { 
          timeout: input.timeout,
          modes: input.modes,
          enrich_result: input.enrich_result,
        },
      })

      // 2. Check cache
      if (!input.force_refresh) {
        const cachedLookup = await lookupCachedResult(cacheManager, cacheKey)
        if (cachedLookup) {
          const normalizedCachedData = normalizeStringsFlossDecodeData(cachedLookup.data, input)
          return {
            ok: true,
            data: {
              status: 'ready',
              sample_id: input.sample_id,
              result_mode: 'full',
              execution_state: 'completed',
              ...normalizedCachedData,
            },
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

      if (
        input.defer_if_slow !== false &&
        jobQueue &&
        options.allowDeferred !== false &&
        shouldDeferLargeSample(sample, 'full')
      ) {
        return buildDeferredToolResponse({
          jobQueue,
          tool: TOOL_NAME,
          sampleId: input.sample_id,
          args: {
            ...input,
            defer_if_slow: false,
          },
          timeoutMs: Math.max(input.timeout * 1000, 5 * 60 * 1000),
          summary:
            'FLOSS decoding was deferred because full decode passes are expensive on medium or larger samples.',
          nextTools: ['task.status', 'analysis.context.link'],
          nextActions: [
            'Poll task.status with the returned job_id instead of rerunning FLOSS immediately.',
            'If you only need a first-pass string view, use strings.extract(mode=preview) before decoding.',
          ],
        })
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
          timeout: input.timeout,
          modes: input.modes,
        },
        toolVersion: TOOL_VERSION,
      })

      // 5. Call Static Worker
      // Requirements: 4.4, 4.5
      const workerResponse = await callPooledStaticWorker(workerRequest, {
        database,
        family: 'static_python.full',
      })

      if (!workerResponse.ok) {
        return {
          ok: false,
          errors: workerResponse.errors,
          warnings: workerResponse.warnings,
        }
      }

      const normalizedData = normalizeStringsFlossDecodeData(workerResponse.data, input)
      const artifacts = [...((workerResponse.artifacts as ArtifactRef[] | undefined) || [])]
      if (input.persist_artifact !== false) {
        const artifact = await persistStringXrefJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          ENRICHED_STRING_ANALYSIS_ARTIFACT_TYPE,
          'decoded_strings',
          {
            sample_id: input.sample_id,
            session_tag: input.session_tag || null,
            tool: TOOL_NAME,
            created_at: new Date().toISOString(),
            input: {
              timeout: input.timeout,
              modes: input.modes,
            },
            data: normalizedData,
          },
          input.session_tag
        )
        artifacts.push(artifact)
      }

      // 6. Cache result (only if not timeout or partial)
      const responseData = normalizedData as { timeout_occurred?: boolean; partial_results?: boolean }
      if (!responseData.timeout_occurred && !responseData.partial_results) {
        await cacheManager.setCachedResult(cacheKey, normalizedData, CACHE_TTL_MS, sample.sha256)
      }

      // 7. Return result
      return {
        ok: true,
        data: {
          status: 'ready',
          sample_id: input.sample_id,
          result_mode: 'full',
          execution_state: 'completed',
          ...normalizedData,
          worker_pool:
            (workerResponse.metrics as Record<string, unknown> | undefined)?.worker_pool,
        },
        warnings: input.force_refresh
          ? ['force_refresh=true; bypassed cache lookup', ...(workerResponse.warnings || [])]
          : workerResponse.warnings,
        errors: workerResponse.errors,
        artifacts,
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
