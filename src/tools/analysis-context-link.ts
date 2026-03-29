import { z } from 'zod'
import type { ToolDefinition, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { JobQueue } from '../job-queue.js'
import { generateCacheKey } from '../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import { createStringsExtractHandler } from './strings-extract.js'
import { createStringsFlossDecodeHandler } from './strings-floss-decode.js'
import {
  buildEnrichedStringBundle,
  attachFunctionReferencesToBundle,
  buildFunctionContextSummaries,
  compactStringBundleForContext,
  extractSuspiciousApiCandidates,
  type EnrichedStringBundle,
  type XrefFunctionNode,
} from '../string-xref-analysis.js'
import {
  CONTEXT_LINK_SUMMARY_ARTIFACT_TYPE,
  loadStringXrefArtifactSelection,
  persistStringXrefJsonArtifact,
} from '../string-xref-artifacts.js'
import { DecompilerWorker, type CrossReferenceAnalysis } from '../decompiler-worker.js'
import {
  buildDeferredToolResponse,
  shouldDeferLargeSample,
} from '../nonblocking-analysis.js'
import { classifySampleSizeTier } from '../analysis-coverage.js'
import { persistChunkedArrayArtifacts } from '../chunked-analysis-evidence.js'
import {
  buildEvidenceReuseWarnings,
  AnalysisEvidenceStateSchema,
  buildDeferredEvidenceState,
  buildFreshEvidenceState,
  buildResolvedEvidenceState,
  findCanonicalEvidence,
  persistCanonicalEvidence,
} from '../analysis-evidence.js'

const TOOL_NAME = 'analysis.context.link'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000
const LARGE_SAMPLE_INLINE_CONTEXTS = 8
const MEDIUM_SAMPLE_INLINE_CONTEXTS = 12
const DEFAULT_FULL_INLINE_CONTEXTS = 16
const CONTEXT_CHUNK_SIZE = 6

function chooseInlineContextLimit(sampleSizeTier: ReturnType<typeof classifySampleSizeTier>): number {
  if (sampleSizeTier === 'large' || sampleSizeTier === 'oversized') {
    return LARGE_SAMPLE_INLINE_CONTEXTS
  }
  if (sampleSizeTier === 'medium') {
    return MEDIUM_SAMPLE_INLINE_CONTEXTS
  }
  return DEFAULT_FULL_INLINE_CONTEXTS
}

export const analysisContextLinkInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  mode: z
    .enum(['preview', 'full'])
    .optional()
    .default('preview')
    .describe('preview is string-level only and safe for synchronous MCP use. Start with preview on medium or larger samples. full adds FLOSS and bounded Xref correlation and may be deferred to the background queue.'),
  include_decoded: z
    .boolean()
    .optional()
    .default(true)
    .describe('Merge FLOSS-decoded strings into the compact context layer'),
  max_records: z
    .number()
    .int()
    .min(10)
    .max(200)
    .optional()
    .default(60)
    .describe('Maximum normalized enriched string records retained before compacting'),
  max_functions: z
    .number()
    .int()
    .min(1)
    .max(20)
    .optional()
    .default(8)
    .describe('Maximum compact function-context summaries retained'),
  max_strings_per_function: z
    .number()
    .int()
    .min(1)
    .max(8)
    .optional()
    .default(4)
    .describe('Maximum string values retained per compact function context'),
  xref_depth: z
    .number()
    .int()
    .min(1)
    .max(2)
    .optional()
    .default(1)
    .describe('Depth used when resolving function xrefs for compact context building'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist the compact context-link output as a JSON artifact'),
  reuse_cached: z
    .boolean()
    .optional()
    .default(true)
    .describe('Reuse the latest matching persisted context-link artifact or cache entry when available'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass artifact and cache reuse and recompute from the current analysis state'),
  defer_if_slow: z
    .boolean()
    .optional()
    .default(true)
    .describe('When true, mode=full may be deferred to the background queue instead of blocking the MCP request.'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag used when persisting context-link artifacts'),
})

export type AnalysisContextLinkInput = z.infer<typeof analysisContextLinkInputSchema>

export const analysisContextLinkOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'partial']),
      sample_id: z.string(),
      xref_status: z.enum(['available', 'unavailable']),
      result_mode: z.enum(['preview', 'full']).optional(),
      execution_state: z.enum(['inline', 'queued', 'partial', 'completed']).optional(),
      job_id: z.string().optional(),
      polling_guidance: z.any().optional(),
      merged_strings: z.any(),
      function_contexts: z.array(z.any()),
      summary: z.string(),
      source_artifact_refs: z.array(z.any()),
      evidence_state: z.array(AnalysisEvidenceStateSchema).optional(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
      artifact: z.any().optional(),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
      cached: z.boolean().optional(),
      cache_key: z.string().optional(),
      cache_tier: z.string().optional(),
      cache_created_at: z.string().optional(),
      cache_expires_at: z.string().optional(),
      cache_hit_at: z.string().optional(),
    })
    .optional(),
})

export const analysisContextLinkToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build compact intermediate analyst context by merging strings.extract, strings.floss.decode, and bounded xref correlation. ' +
    'Use this after quick triage when you need indicator-to-function context before full reconstruction. ' +
    'Prefer mode=preview first; reserve mode=full for cases where FLOSS plus function-aware attribution is actually needed.',
  inputSchema: analysisContextLinkInputSchema,
  outputSchema: analysisContextLinkOutputSchema,
}

interface AnalysisContextLinkDependencies {
  stringsExtract?: (args: unknown) => Promise<WorkerResult>
  stringsFlossDecode?: (args: unknown) => Promise<WorkerResult>
  analyzeCrossReferences?: (
    sampleId: string,
    options: {
      targetType: 'function' | 'api' | 'string' | 'data'
      query: string
      depth?: number
      limit?: number
      timeout?: number
    }
  ) => Promise<CrossReferenceAnalysis>
}

function buildAnalysisMarker(database: DatabaseManager, sampleId: string): string {
  const latest = database
    .findAnalysesBySample(sampleId)
    .find((analysis) => analysis.backend === 'ghidra')

  if (!latest) {
    return 'no_ghidra_analysis'
  }

  return [
    latest.id,
    latest.status,
    latest.finished_at || latest.started_at || 'unknown',
  ].join(':')
}

function isPrerequisiteError(message: string): boolean {
  const normalized = message.toLowerCase()
  return (
    normalized.includes('please run ghidra.analyze first') ||
    normalized.includes('function index readiness') ||
    normalized.includes('ghidra is not properly configured') ||
    normalized.includes('ghidra function index is not ready')
  )
}

function collectExtractedRecords(data: unknown) {
  const record = data && typeof data === 'object' ? (data as Record<string, unknown>) : {}
  return Array.isArray(record.strings)
    ? record.strings
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
}

function collectDecodedRecords(data: unknown) {
  const record = data && typeof data === 'object' ? (data as Record<string, unknown>) : {}
  return Array.isArray(record.decoded_strings)
    ? record.decoded_strings
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
}

function collectSourceArtifacts(result: WorkerResult): ArtifactRef[] {
  return Array.isArray(result.artifacts)
    ? (result.artifacts.filter((item) => item && typeof item === 'object') as ArtifactRef[])
    : []
}

function buildSummary(
  bundle: EnrichedStringBundle,
  functionContexts: ReturnType<typeof buildFunctionContextSummaries>,
  xrefStatus: 'available' | 'unavailable'
): string {
  const relevant = bundle.analyst_relevant_count
  const decoded = bundle.top_decoded.length
  if (xrefStatus === 'available') {
    return `Merged ${bundle.kept_records}/${bundle.total_records} normalized string record(s), retained ${relevant} analyst-relevant item(s), and correlated ${functionContexts.length} compact function context(s).${decoded > 0 ? ` Included ${decoded} top decoded-string hint(s).` : ''}`
  }
  return `Merged ${bundle.kept_records}/${bundle.total_records} normalized string record(s) and retained ${relevant} analyst-relevant item(s). Ghidra-backed function attribution is currently unavailable, so this output stays at string-level context only.`
}

export function createAnalysisContextLinkHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies: AnalysisContextLinkDependencies = {},
  jobQueue?: JobQueue,
  options: { allowDeferred?: boolean } = {}
): (args: unknown) => Promise<WorkerResult> {
  const stringsExtractHandler =
    dependencies.stringsExtract || createStringsExtractHandler(workspaceManager, database, cacheManager)
  const stringsFlossDecodeHandler =
    dependencies.stringsFlossDecode ||
    createStringsFlossDecodeHandler(workspaceManager, database, cacheManager)

  return async (args: unknown): Promise<WorkerResult> => {
    const input = analysisContextLinkInputSchema.parse(args)
    const startTime = Date.now()
    const warnings: string[] = []

    try {
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
      const sampleSizeTier = classifySampleSizeTier(sample.size)

      if (!input.force_refresh && input.reuse_cached) {
        const canonical = findCanonicalEvidence(database, {
          sample,
          evidenceFamily: 'context_link',
          backend: TOOL_NAME,
          mode: input.mode,
          args: {
            include_decoded: input.include_decoded,
            max_records: input.max_records,
            max_functions: input.max_functions,
            max_strings_per_function: input.max_strings_per_function,
            xref_depth: input.xref_depth,
            analysis_marker: buildAnalysisMarker(database, input.sample_id),
          },
        })
        if (canonical) {
          return {
            ok: true,
            data: {
              ...(canonical.result as Record<string, unknown>),
              result_mode: input.mode,
              execution_state:
                typeof (canonical.result as Record<string, unknown>)?.execution_state === 'string'
                  ? (canonical.result as Record<string, unknown>).execution_state
                  : 'completed',
              evidence_state: [buildResolvedEvidenceState({
                source: 'analysis_evidence',
                record: canonical,
              })],
            },
            warnings: buildEvidenceReuseWarnings({
              source: 'analysis_evidence',
              record: canonical,
            }),
            artifacts: canonical.artifact_refs,
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
              cached: false,
            },
          }
        }

        const artifactSelection = await loadStringXrefArtifactSelection(
          workspaceManager,
          database,
          input.sample_id,
          CONTEXT_LINK_SUMMARY_ARTIFACT_TYPE,
          {
            scope: input.session_tag ? 'session' : 'latest',
            sessionTag: input.session_tag,
          }
        )
        if (artifactSelection.latest_payload) {
          return {
            ok: true,
            data: {
              ...(artifactSelection.latest_payload as Record<string, unknown>),
              evidence_state: [
                AnalysisEvidenceStateSchema.parse({
                  evidence_family: 'context_link',
                  backend: TOOL_NAME,
                  mode: input.mode,
                  state: 'reused',
                  source: 'artifact',
                  updated_at: artifactSelection.latest_created_at || null,
                  freshness_marker: null,
                  reason: 'Reused a persisted context-link artifact selection.',
                }),
              ],
            },
            warnings: ['Reused persisted context-link artifact', artifactSelection.scope_note],
            artifacts: artifactSelection.latest_artifact ? [artifactSelection.latest_artifact] : [],
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
              cached: true,
            },
          }
        }
      }

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          mode: input.mode,
          include_decoded: input.include_decoded,
          max_records: input.max_records,
          max_functions: input.max_functions,
          max_strings_per_function: input.max_strings_per_function,
          xref_depth: input.xref_depth,
          analysis_marker: buildAnalysisMarker(database, input.sample_id),
        },
      })

      if (!input.force_refresh && input.reuse_cached) {
        const cachedLookup = await lookupCachedResult(cacheManager, cacheKey)
        if (cachedLookup) {
          return {
            ok: true,
            data: {
              ...(cachedLookup.data as Record<string, unknown>),
              result_mode: input.mode,
              execution_state: 'completed',
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
        input.mode === 'full' &&
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
          timeoutMs: 8 * 60 * 1000,
          summary:
            'Full context linking was deferred because FLOSS plus Xref correlation is too expensive for synchronous MCP use on a medium or larger sample.',
          nextTools: ['task.status', 'ghidra.analyze', 'code.xrefs.analyze'],
          nextActions: [
            'Use mode=preview for string-level context without waiting on Ghidra-backed attribution.',
            'Poll task.status with the returned job_id before requesting the same full context-link pass again.',
          ],
          metadata: {
            evidence_state: [
              buildDeferredEvidenceState({
                evidenceFamily: 'context_link',
                backend: TOOL_NAME,
                mode: input.mode,
                reason:
                  'Full context-linking was deferred because decoded-string merging plus bounded Xref correlation exceeded the synchronous preview budget.',
              }),
            ],
          },
        })
      }

      const extractResult = await stringsExtractHandler({
        sample_id: input.sample_id,
        mode: input.mode === 'preview' ? 'preview' : 'full',
        min_len: 5,
        encoding: 'all',
        max_strings: Math.max(input.max_records, 60),
        force_refresh: input.force_refresh,
        defer_if_slow: false,
        persist_artifact: input.persist_artifact,
        session_tag: input.session_tag,
        enrich_result: true,
      })
      if (!extractResult.ok) {
        return {
          ok: false,
          errors: extractResult.errors || ['strings.extract failed'],
          warnings: extractResult.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const sourceArtifacts = [...collectSourceArtifacts(extractResult)]
      const extractedStrings = collectExtractedRecords(extractResult.data)
      const extractData = extractResult.data as Record<string, unknown>
      const extractSummary =
        extractData.summary && typeof extractData.summary === 'object'
          ? (extractData.summary as Record<string, unknown>)
          : {}

      let decodedStrings: ReturnType<typeof collectDecodedRecords> = []
      if (input.include_decoded && input.mode === 'full') {
        const flossResult = await stringsFlossDecodeHandler({
          sample_id: input.sample_id,
          modes: ['decoded', 'stack', 'tight'],
          force_refresh: input.force_refresh,
          defer_if_slow: false,
          persist_artifact: input.persist_artifact,
          session_tag: input.session_tag,
          enrich_result: true,
        })
        if (flossResult.ok) {
          decodedStrings = collectDecodedRecords(flossResult.data)
          sourceArtifacts.push(...collectSourceArtifacts(flossResult))
          if (flossResult.warnings) {
            warnings.push(...flossResult.warnings)
          }
        } else if (flossResult.errors?.length) {
          warnings.push(`FLOSS decode unavailable: ${flossResult.errors.join('; ')}`)
        }
      }

      let bundle = buildEnrichedStringBundle(extractedStrings, decodedStrings, {
        maxRecords: input.max_records,
        maxHighlights: 12,
        contextWindows: Array.isArray(extractSummary.context_windows)
          ? (extractSummary.context_windows as unknown[])
          : [],
      })

      const xrefResults: Array<{
        target_type: 'string' | 'api' | 'data' | 'function'
        query: string
        inbound: XrefFunctionNode[]
        outbound?: XrefFunctionNode[]
      }> = []
      let xrefStatus: 'available' | 'unavailable' = 'unavailable'

      if (input.mode === 'full') {
        const decompilerWorker = new DecompilerWorker(database, workspaceManager)
        const analyzeCrossReferences =
          dependencies.analyzeCrossReferences ||
          ((sampleId: string, options: Parameters<DecompilerWorker['analyzeCrossReferences']>[1]) =>
            decompilerWorker.analyzeCrossReferences(sampleId, options))

        xrefStatus = 'available'
        const stringTargets = bundle.top_suspicious
          .filter((item) => !item.labels.includes('runtime_noise'))
          .map((item) => item.value)
          .slice(0, 4)
        const apiTargets = extractSuspiciousApiCandidates(bundle, 4)

        for (const target of stringTargets) {
          try {
            const result = await analyzeCrossReferences(input.sample_id, {
              targetType: 'string',
              query: target,
              depth: input.xref_depth,
              limit: input.max_functions,
              timeout: 30_000,
            })
            xrefResults.push({
              target_type: 'string',
              query: target,
              inbound: result.inbound as XrefFunctionNode[],
              outbound: result.outbound as XrefFunctionNode[],
            })
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            if (isPrerequisiteError(message)) {
              xrefStatus = 'unavailable'
              warnings.push(message)
              break
            }
            warnings.push(`string xref unavailable for ${target}: ${message}`)
          }
        }

        if (xrefStatus === 'available') {
          for (const target of apiTargets) {
            try {
              const result = await analyzeCrossReferences(input.sample_id, {
                targetType: 'api',
                query: target,
                depth: 1,
                limit: input.max_functions,
                timeout: 30_000,
              })
              xrefResults.push({
                target_type: 'api',
                query: target,
                inbound: result.inbound as XrefFunctionNode[],
                outbound: result.outbound as XrefFunctionNode[],
              })
            } catch (error) {
              const message = error instanceof Error ? error.message : String(error)
              if (isPrerequisiteError(message)) {
                xrefStatus = 'unavailable'
                warnings.push(message)
                break
              }
              warnings.push(`api xref unavailable for ${target}: ${message}`)
            }
          }
        }
      }

      bundle =
        xrefResults.length > 0
          ? attachFunctionReferencesToBundle(
              bundle,
              xrefResults
                .filter((item) => item.target_type === 'string' || item.target_type === 'data')
                .map((item) => ({
                  target_type: item.target_type as 'string' | 'data',
                  query: item.query,
                  inbound: item.inbound,
                }))
            )
          : bundle

      const functionContexts = buildFunctionContextSummaries(bundle, xrefResults, {
        maxFunctions: input.max_functions,
        maxStringsPerFunction: input.max_strings_per_function,
      })
      const chunkWarnings: string[] = []
      let boundedFunctionContexts = functionContexts
      let chunkManifest: Record<string, unknown> | undefined
      const artifacts: ArtifactRef[] = []

      if (input.mode === 'full' && functionContexts.length > chooseInlineContextLimit(sampleSizeTier)) {
        const chunked = await persistChunkedArrayArtifacts(functionContexts, {
          family: 'context_link',
          inlineLimit: chooseInlineContextLimit(sampleSizeTier),
          chunkSize: CONTEXT_CHUNK_SIZE,
          notes: [
            'Large-sample context linking retained a bounded inline digest and persisted the remaining function contexts as chunk artifacts.',
          ],
          buildLabel: (index, itemCount) => `context chunk ${index + 1} (${itemCount} functions)`,
          persistChunk: async ({ index, itemCount, items }) =>
            persistStringXrefJsonArtifact(
              workspaceManager,
              database,
              input.sample_id,
              CONTEXT_LINK_SUMMARY_ARTIFACT_TYPE,
              `context_link_chunk_${String(index + 1).padStart(3, '0')}`,
              {
                sample_id: input.sample_id,
                session_tag: input.session_tag || null,
                created_at: new Date().toISOString(),
                chunk_index: index,
                chunk_item_count: itemCount,
                total_items: functionContexts.length,
                function_contexts: items,
              },
              input.session_tag
            ),
        })
        if (chunked.manifest) {
          boundedFunctionContexts = chunked.inline_items
          chunkManifest = chunked.manifest
          artifacts.push(...chunked.chunk_artifacts)
          chunkWarnings.push(
            `Bounded inline function contexts to ${boundedFunctionContexts.length} and persisted ${chunked.chunk_artifacts.length} chunk artifact(s).`
          )
        }
      }

      let artifact: ArtifactRef | undefined
      if (input.persist_artifact !== false) {
        artifact = await persistStringXrefJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          CONTEXT_LINK_SUMMARY_ARTIFACT_TYPE,
          'context_link',
          {
            sample_id: input.sample_id,
            session_tag: input.session_tag || null,
            created_at: new Date().toISOString(),
            xref_status: xrefStatus,
            merged_strings: compactStringBundleForContext(bundle),
            function_contexts: boundedFunctionContexts,
            source_artifact_refs: sourceArtifacts,
            ...(chunkManifest ? { chunk_manifest: chunkManifest } : {}),
          },
          input.session_tag
        )
        artifacts.push(artifact)
      }

      const outputData = {
        status: xrefStatus === 'available' ? 'ready' : 'partial',
        sample_id: input.sample_id,
        xref_status: xrefStatus,
        result_mode: input.mode,
        execution_state: xrefStatus === 'available' ? 'completed' : 'partial',
        merged_strings: compactStringBundleForContext(bundle),
        function_contexts: boundedFunctionContexts,
        summary: buildSummary(bundle, functionContexts, xrefStatus),
        source_artifact_refs: sourceArtifacts,
        ...(chunkManifest ? { chunk_manifest: chunkManifest } : {}),
        evidence_state: [
          buildFreshEvidenceState({
            evidenceFamily: 'context_link',
            backend: TOOL_NAME,
            mode: input.mode,
            freshnessMarker: buildAnalysisMarker(database, input.sample_id),
          }),
        ],
        recommended_next_tools:
          xrefStatus === 'available'
            ? ['code.function.decompile', 'code.xrefs.analyze', 'workflow.reconstruct']
            : input.mode === 'preview'
              ? ['analysis.context.link', 'ghidra.analyze', 'workflow.reconstruct']
              : ['ghidra.analyze', 'code.xrefs.analyze', 'workflow.reconstruct'],
        next_actions:
          xrefStatus === 'available'
            ? [
                'Use code.function.decompile on the highest-signal returned function when you need pseudocode.',
                'Use workflow.reconstruct when these function contexts are strong enough for deeper reconstruction.',
              ]
            : input.mode === 'preview'
              ? [
                  'Preview mode is string-level only. Promote to mode=full when you need FLOSS and function-aware Xref correlation.',
                  'Run ghidra.analyze before expecting string-to-function attribution.',
                ]
            : [
                'Run ghidra.analyze first if you need string-to-function or API-to-function attribution.',
                'Retry analysis.context.link after Ghidra function_index readiness is available.',
              ],
        artifact,
      }

      await cacheManager.setCachedResult(cacheKey, outputData, CACHE_TTL_MS, sample.sha256)
      persistCanonicalEvidence(database, {
        sample,
        evidenceFamily: 'context_link',
        backend: TOOL_NAME,
        mode: input.mode,
        args: {
          include_decoded: input.include_decoded,
          max_records: input.max_records,
          max_functions: input.max_functions,
          max_strings_per_function: input.max_strings_per_function,
          xref_depth: input.xref_depth,
          analysis_marker: buildAnalysisMarker(database, input.sample_id),
        },
        result: outputData,
        artifactRefs: [...sourceArtifacts, ...artifacts],
        metadata: {
          cache_key: cacheKey,
          source_artifact_count: sourceArtifacts.length,
          sample_size_tier: sampleSizeTier,
          ...(chunkManifest ? { chunk_manifest: chunkManifest } : {}),
        },
        provenance: {
          tool: TOOL_NAME,
          tool_version: TOOL_VERSION,
          precedence: ['analysis_run_stage', 'analysis_evidence', 'artifact', 'cache'],
        },
      })

      return {
        ok: true,
        data: outputData,
        warnings:
          warnings.length > 0 || chunkWarnings.length > 0
            ? Array.from(new Set([...warnings, ...chunkWarnings]))
            : undefined,
        artifacts,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        warnings: warnings.length > 0 ? Array.from(new Set(warnings)) : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
