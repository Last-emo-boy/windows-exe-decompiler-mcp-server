/**
 * strings.extract tool implementation
 * Extracts readable strings (ASCII and Unicode) from PE files
 * Requirements: 4.1, 4.2, 4.3
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import { randomUUID } from 'crypto'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { JobQueue } from '../job-queue.js'
import { generateCacheKey } from '../cache-manager.js'
import { resolvePackagePath } from '../runtime-paths.js'
import { formatCacheWarning } from './cache-observability.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'
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
import { classifySampleSizeTier } from '../analysis-coverage.js'
import { persistChunkedArrayArtifacts } from '../chunked-analysis-evidence.js'
import {
  AnalysisEvidenceStateSchema,
  buildDeferredEvidenceState,
  buildFreshEvidenceState,
  buildResolvedEvidenceState,
  buildEvidenceReuseWarnings,
  persistCanonicalEvidence,
  resolveCanonicalEvidenceOrCache,
} from '../analysis-evidence.js'

// ============================================================================
// Constants
// ============================================================================

const TOOL_NAME = 'strings.extract'
const TOOL_VERSION = '1.1.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000 // 30 days
const LARGE_SAMPLE_INLINE_STRINGS = 120
const MEDIUM_SAMPLE_INLINE_STRINGS = 180
const DEFAULT_FULL_INLINE_STRINGS = 240
const STRING_CHUNK_SIZE = 200

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for strings.extract tool
 * Requirements: 4.1, 4.2, 4.3
 */
export const StringsExtractInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  mode: z
    .enum(['preview', 'full'])
    .optional()
    .default('preview')
    .describe('preview is bounded and safe for synchronous MCP use. Start with preview on medium or larger samples. full scans the complete sample and may be deferred to the background queue.'),
  min_len: z.number().int().min(1).optional().default(4).describe('Minimum string length'),
  encoding: z.enum(['ascii', 'unicode', 'all']).optional().default('all').describe('Encoding type to extract'),
  max_strings: z.number().int().min(1).optional().default(500).describe('Maximum number of strings to return (default: 500)'),
  max_string_length: z.number().int().min(16).optional().default(512).describe('Maximum length for each returned string'),
  max_scan_bytes: z
    .number()
    .int()
    .min(65536)
    .optional()
    .describe('Optional bounded scan budget used in preview mode. The worker samples the file instead of scanning every byte.'),
  context_window_bytes: z
    .number()
    .int()
    .min(32)
    .max(65536)
    .optional()
    .default(1024)
    .describe('Maximum byte gap used to regroup nearby strings into context windows'),
  max_context_windows: z
    .number()
    .int()
    .min(1)
    .max(100)
    .optional()
    .default(12)
    .describe('Maximum number of context windows returned in the summary'),
  category_filter: z.enum(['all', 'ioc', 'url', 'network', 'ipc', 'command', 'registry', 'file_path', 'suspicious_api'])
    .optional()
    .default('all')
    .describe('Optional category filter; use `ioc` to prioritize IOC-related strings'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
  defer_if_slow: z
    .boolean()
    .optional()
    .default(true)
    .describe('When true, mode=full may return a queued job instead of blocking the MCP request on medium or larger samples.'),
  enrich_result: z
    .boolean()
    .optional()
    .default(true)
    .describe('Attach analyst-oriented enriched string classification and bounded summaries'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist enriched string intelligence as a JSON artifact for later reuse'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag used when persisting enriched string artifacts'),
})

export type StringsExtractInput = z.infer<typeof StringsExtractInputSchema>

/**
 * Output schema for strings.extract tool
 * Requirements: 4.1, 4.2, 4.3, 4.6
 */
export const StringsExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    status: z.enum(['ready', 'queued', 'partial']).optional(),
    sample_id: z.string().optional(),
    result_mode: z.enum(['preview', 'full']).optional(),
    execution_state: z.enum(['inline', 'queued', 'partial', 'completed']).optional(),
    job_id: z.string().optional(),
    polling_guidance: z.any().optional(),
    evidence_state: z.array(AnalysisEvidenceStateSchema).optional(),
    recommended_next_tools: z.array(z.string()).optional(),
    next_actions: z.array(z.string()).optional(),
    strings: z.array(z.object({
      offset: z.number(),
      string: z.string(),
      encoding: z.string(),
    })).optional(),
    count: z.number().optional(),
    total_count: z.number().optional(),
    pre_filter_count: z.number().optional(),
    truncated: z.boolean().optional(),
    max_strings: z.number().optional(),
    max_string_length: z.number().optional(),
    max_scan_bytes: z.number().optional(),
    scan_mode: z.string().optional(),
    scan_bytes: z.number().optional(),
    sampled: z.boolean().optional(),
    min_len: z.number().optional(),
    encoding_filter: z.string().optional(),
    category_filter: z.string().optional(),
    summary: z.object({
      cluster_counts: z.record(z.string(), z.number()),
      clusters: z.record(z.string(), z.array(z.string())),
      top_high_value: z.array(z.object({
        offset: z.number(),
        string: z.string(),
        encoding: z.string(),
        categories: z.array(z.string()),
      })),
      context_windows: z.array(z.object({
        start_offset: z.number(),
        end_offset: z.number(),
        score: z.number(),
        categories: z.array(z.string()),
        strings: z.array(z.object({
          offset: z.number(),
          string: z.string(),
          encoding: z.string(),
          categories: z.array(z.string()),
        })),
      })).optional(),
    }).optional(),
    enriched: EnrichedStringBundleSchema.optional(),
  }).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({
    elapsed_ms: z.number(),
    tool: z.string(),
  }).optional(),
})

export type StringsExtractOutput = z.infer<typeof StringsExtractOutputSchema>

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for strings.extract
 */
export const stringsExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Extract readable strings from a sample and return compact IOC-aware grouping plus enriched analyst labels. ' +
    'Use this for fast string triage; use analysis.context.link when you need merged FLOSS output and function-aware attribution before full reconstruction. ' +
    'On medium/large samples, prefer mode=preview first and only escalate to mode=full when the workflow explicitly needs complete extraction.',
  inputSchema: StringsExtractInputSchema,
  outputSchema: StringsExtractOutputSchema,
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

function normalizeStringsExtractData(
  payload: unknown,
  input: StringsExtractInput
): Record<string, unknown> {
  const data = payload && typeof payload === 'object' ? ({ ...(payload as Record<string, unknown>) }) : {}
  const extracted = Array.isArray(data.strings)
    ? data.strings
        .map((item) => {
          const entry = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
          if (typeof entry.string !== 'string') {
            return null
          }
          return {
            offset: Number(entry.offset || 0),
            string: entry.string,
            encoding: typeof entry.encoding === 'string' ? entry.encoding : null,
          }
        })
        .filter(
          (
            item
          ): item is {
            offset: number
            string: string
            encoding: string | null
          } => Boolean(item)
        )
    : []

  if (input.enrich_result !== false) {
    const summary =
      data.summary && typeof data.summary === 'object' ? (data.summary as Record<string, unknown>) : {}
    data.enriched = buildEnrichedStringBundle(extracted, [], {
      maxRecords: Math.max(20, Math.min(input.max_strings || 500, 120)),
      maxHighlights: 12,
      contextWindows: Array.isArray(summary.context_windows) ? (summary.context_windows as unknown[]) : [],
    })
  }

  return data
}

function chooseInlineStringsLimit(sampleSizeTier: ReturnType<typeof classifySampleSizeTier>): number {
  if (sampleSizeTier === 'large' || sampleSizeTier === 'oversized') {
    return LARGE_SAMPLE_INLINE_STRINGS
  }
  if (sampleSizeTier === 'medium') {
    return MEDIUM_SAMPLE_INLINE_STRINGS
  }
  return DEFAULT_FULL_INLINE_STRINGS
}

// ============================================================================
// Tool Handler
// ============================================================================

/**
 * Create strings.extract tool handler
 * Requirements: 4.1, 4.2, 4.3
 */
export function createStringsExtractHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  jobQueue?: JobQueue,
  options: { allowDeferred?: boolean } = {}
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = StringsExtractInputSchema.parse(args)
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
      const sampleSizeTier = classifySampleSizeTier(sample.size)

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: { 
          mode: input.mode,
          min_len: input.min_len,
          encoding: input.encoding,
          max_strings: input.max_strings,
          max_string_length: input.max_string_length,
          max_scan_bytes: input.max_scan_bytes,
          context_window_bytes: input.context_window_bytes,
          max_context_windows: input.max_context_windows,
          category_filter: input.category_filter,
          enrich_result: input.enrich_result,
        },
      })

      // 2. Check cache
      if (!input.force_refresh) {
        const resolved = await resolveCanonicalEvidenceOrCache(database, cacheManager, cacheKey, {
          sample,
          evidenceFamily: 'strings',
          backend: TOOL_NAME,
          mode: input.mode,
          args: {
            min_len: input.min_len,
            encoding: input.encoding,
            max_strings: input.max_strings,
            max_string_length: input.max_string_length,
            max_scan_bytes: input.max_scan_bytes,
            context_window_bytes: input.context_window_bytes,
            max_context_windows: input.max_context_windows,
            category_filter: input.category_filter,
            enrich_result: input.enrich_result,
          },
        })
        if (resolved) {
          const normalizedCachedData = normalizeStringsExtractData(resolved.record.result, input)
          const warnings =
            resolved.source === 'cache' && resolved.cache
              ? [...buildEvidenceReuseWarnings(resolved), formatCacheWarning(resolved.cache.metadata)]
              : buildEvidenceReuseWarnings(resolved)
          return {
            ok: true,
            data: {
              status: 'ready',
              sample_id: input.sample_id,
              result_mode: input.mode,
              execution_state: 'completed',
              evidence_state: [buildResolvedEvidenceState(resolved)],
              ...normalizedCachedData,
            },
            warnings,
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
              cached: resolved.source === 'cache',
              cache_key: resolved.cache?.metadata.key,
              cache_tier: resolved.cache?.metadata.tier,
              cache_created_at: resolved.cache?.metadata.createdAt,
              cache_expires_at: resolved.cache?.metadata.expiresAt,
              cache_hit_at: resolved.cache?.metadata.fetchedAt,
            },
          }
        }
      }

      if (
        input.mode === 'full' &&
        input.defer_if_slow !== false &&
        jobQueue &&
        options.allowDeferred !== false &&
        shouldDeferLargeSample(sample, input.mode)
      ) {
        return buildDeferredToolResponse({
          jobQueue,
          tool: TOOL_NAME,
          sampleId: input.sample_id,
          args: {
            ...input,
            defer_if_slow: false,
          },
          timeoutMs: 5 * 60 * 1000,
          summary:
            'Full string extraction was deferred because complete scans on medium or larger samples are too expensive for synchronous MCP requests.',
          nextTools: ['task.status', 'analysis.context.link', 'binary.role.profile'],
          nextActions: [
            'Poll task.status with the returned job_id before requesting the same full string extraction again.',
            'Use mode=preview when you only need a bounded first-pass IOC and noise-filtered string view.',
          ],
          metadata: {
            evidence_state: [
              buildDeferredEvidenceState({
                evidenceFamily: 'strings',
                backend: TOOL_NAME,
                mode: input.mode,
                reason:
                  'Full string extraction was deferred because the requested sample size exceeds the synchronous preview budget.',
              }),
            ],
          },
        })
      }

      // 3. Get sample path from workspace
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)

      // 4. Prepare worker request
      const workerRequest: WorkerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        args: {
          scan_mode: input.mode,
          max_scan_bytes: input.mode === 'preview' ? input.max_scan_bytes || 1024 * 1024 : undefined,
          min_len: input.min_len,
          encoding: input.encoding,
          max_strings: input.max_strings,
          max_string_length: input.max_string_length,
          context_window_bytes: input.context_window_bytes,
          max_context_windows: input.max_context_windows,
          category_filter: input.category_filter,
        },
        toolVersion: TOOL_VERSION,
      })

      // 5. Call Static Worker
      // Requirements: 4.1, 4.2, 4.3
      const workerResponse = await callPooledStaticWorker(workerRequest, {
        database,
        family: input.mode === 'full' ? 'static_python.full' : 'static_python.preview',
      })

      if (!workerResponse.ok) {
        return {
          ok: false,
          errors: workerResponse.errors,
          warnings: workerResponse.warnings,
        }
      }

      let normalizedData = normalizeStringsExtractData(workerResponse.data, input)
      const artifacts = [...((workerResponse.artifacts as ArtifactRef[] | undefined) || [])]
      const chunkWarnings: string[] = []

      const extractedStrings = Array.isArray(normalizedData.strings)
        ? (normalizedData.strings as Array<Record<string, unknown>>)
        : []
      if (input.mode === 'full' && extractedStrings.length > chooseInlineStringsLimit(sampleSizeTier)) {
        const chunked = await persistChunkedArrayArtifacts(extractedStrings, {
          family: 'strings',
          inlineLimit: chooseInlineStringsLimit(sampleSizeTier),
          chunkSize: STRING_CHUNK_SIZE,
          notes: [
            'Large-sample full strings were bounded inline and persisted as chunk artifacts.',
          ],
          buildLabel: (index, itemCount) => `strings chunk ${index + 1} (${itemCount} strings)`,
          persistChunk: async ({ index, itemCount, items }) =>
            persistStringXrefJsonArtifact(
              workspaceManager,
              database,
              input.sample_id,
              ENRICHED_STRING_ANALYSIS_ARTIFACT_TYPE,
              `enriched_strings_chunk_${String(index + 1).padStart(3, '0')}`,
              {
                sample_id: input.sample_id,
                session_tag: input.session_tag || null,
                tool: TOOL_NAME,
                created_at: new Date().toISOString(),
                chunk_index: index,
                chunk_item_count: itemCount,
                total_items: extractedStrings.length,
                data: {
                  strings: items,
                },
              },
              input.session_tag
            ),
        })
        if (chunked.manifest) {
          normalizedData = {
            ...normalizedData,
            strings: chunked.inline_items,
            chunk_manifest: chunked.manifest,
          }
          artifacts.push(...chunked.chunk_artifacts)
          chunkWarnings.push(
            `Bounded full strings inline payload to ${chunked.inline_items.length} strings and persisted ${chunked.chunk_artifacts.length} chunk artifact(s).`
          )
        }
      }

      if (input.persist_artifact !== false) {
        const artifact = await persistStringXrefJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          ENRICHED_STRING_ANALYSIS_ARTIFACT_TYPE,
          'enriched_strings',
          {
            sample_id: input.sample_id,
            session_tag: input.session_tag || null,
            tool: TOOL_NAME,
            created_at: new Date().toISOString(),
            input: {
              min_len: input.min_len,
              encoding: input.encoding,
              max_strings: input.max_strings,
              category_filter: input.category_filter,
            },
            data: normalizedData,
          },
          input.session_tag
        )
        artifacts.push(artifact)
      }

      // 6. Cache result
      await cacheManager.setCachedResult(cacheKey, normalizedData, CACHE_TTL_MS, sample.sha256)
      persistCanonicalEvidence(database, {
        sample,
        evidenceFamily: 'strings',
        backend: TOOL_NAME,
        mode: input.mode,
        args: {
          min_len: input.min_len,
          encoding: input.encoding,
          max_strings: input.max_strings,
          max_string_length: input.max_string_length,
          max_scan_bytes: input.max_scan_bytes,
          context_window_bytes: input.context_window_bytes,
          max_context_windows: input.max_context_windows,
          category_filter: input.category_filter,
          enrich_result: input.enrich_result,
        },
        result: normalizedData,
        artifactRefs: artifacts,
        metadata: {
          session_tag: input.session_tag || null,
          cache_key: cacheKey,
          sample_size_tier: sampleSizeTier,
          ...(normalizedData.chunk_manifest ? { chunk_manifest: normalizedData.chunk_manifest } : {}),
        },
        provenance: {
          tool: TOOL_NAME,
          tool_version: TOOL_VERSION,
          precedence: ['analysis_run_stage', 'analysis_evidence', 'artifact', 'cache'],
        },
      })

      // 7. Return result
      return {
        ok: true,
        data: {
          status: 'ready',
          sample_id: input.sample_id,
          result_mode: input.mode,
          execution_state: 'completed',
          worker_pool:
            (workerResponse.metrics as Record<string, unknown> | undefined)?.worker_pool,
          evidence_state: [
            buildFreshEvidenceState({
              evidenceFamily: 'strings',
              backend: TOOL_NAME,
              mode: input.mode,
            }),
          ],
          ...normalizedData,
        },
        warnings: input.force_refresh
          ? [
              'force_refresh=true; bypassed cache lookup',
              ...(workerResponse.warnings || []),
              ...chunkWarnings,
            ]
          : [...(workerResponse.warnings || []), ...chunkWarnings],
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
