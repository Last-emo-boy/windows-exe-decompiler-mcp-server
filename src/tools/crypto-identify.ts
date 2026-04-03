import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { JobQueue } from '../job-queue.js'
import { generateCacheKey } from '../cache-manager.js'
import { createStringsExtractHandler } from './strings-extract.js'
import { createStringsFlossDecodeHandler } from './strings-floss-decode.js'
import { createAnalysisContextLinkHandler } from './analysis-context-link.js'
import { createPEImportsExtractHandler } from '../plugins/pe-analysis/tools/pe-imports-extract.js'
import { createStaticCapabilityTriageHandler } from './static-capability-triage.js'
import { loadDynamicTraceEvidence, type DynamicEvidenceScope, type DynamicTraceSummary } from '../dynamic-trace.js'
import { buildDeferredToolResponse, shouldDeferLargeSample } from '../nonblocking-analysis.js'
import { classifySampleSizeTier } from '../analysis-coverage.js'
import { persistChunkedArrayArtifacts } from '../chunked-analysis-evidence.js'
import {
  AnalysisEvidenceStateSchema,
  buildDeferredEvidenceState,
  buildEvidenceReuseWarnings,
  buildFreshEvidenceState,
  buildResolvedEvidenceState,
  persistCanonicalEvidence,
  resolveCanonicalEvidenceOrCache,
} from '../analysis-evidence.js'
import {
  CryptoConstantCandidateSchema,
  CryptoFindingSchema,
  buildCryptoFindings,
  collectCryptoApiNames,
  summarizeCryptoFindings,
  type BasicStringRecord,
  type FunctionContextLike,
} from '../crypto-breakpoint-analysis.js'
import {
  CRYPTO_IDENTIFICATION_ARTIFACT_TYPE,
  loadCryptoPlanningArtifactSelection,
  persistCryptoPlanningJsonArtifact,
  type CryptoPlanningArtifactScope,
} from '../crypto-planning-artifacts.js'

const TOOL_NAME = 'crypto.identify'
const TOOL_VERSION = '0.2.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000
const LARGE_SAMPLE_INLINE_CRYPTO_FINDINGS = 4
const MEDIUM_SAMPLE_INLINE_CRYPTO_FINDINGS = 6
const DEFAULT_INLINE_CRYPTO_FINDINGS = 8
const CRYPTO_FINDING_CHUNK_SIZE = 4

function chooseInlineCryptoFindingLimit(sampleSizeTier: ReturnType<typeof classifySampleSizeTier>): number {
  if (sampleSizeTier === 'large' || sampleSizeTier === 'oversized') {
    return LARGE_SAMPLE_INLINE_CRYPTO_FINDINGS
  }
  if (sampleSizeTier === 'medium') {
    return MEDIUM_SAMPLE_INLINE_CRYPTO_FINDINGS
  }
  return DEFAULT_INLINE_CRYPTO_FINDINGS
}

export const cryptoIdentifyInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  mode: z
    .enum(['preview', 'full'])
    .optional()
    .default('preview')
    .describe('preview keeps crypto identification bounded for synchronous MCP use. Start with preview on medium or larger samples. full adds heavier decoded/context correlation and may be deferred on larger samples.'),
  include_runtime_evidence: z
    .boolean()
    .optional()
    .default(true)
    .describe('Merge imported dynamic trace evidence when available'),
  runtime_evidence_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .default('latest')
    .describe('Dynamic evidence selection scope used when loading imported trace artifacts'),
  max_findings: z
    .number()
    .int()
    .min(1)
    .max(12)
    .optional()
    .default(6)
    .describe('Maximum crypto findings returned inline'),
  max_constants: z
    .number()
    .int()
    .min(0)
    .max(20)
    .optional()
    .default(8)
    .describe('Maximum candidate key, IV, S-box, or table summaries returned inline'),
  max_contexts: z
    .number()
    .int()
    .min(1)
    .max(20)
    .optional()
    .default(8)
    .describe('Maximum compact function contexts considered during localization'),
  xref_depth: z
    .number()
    .int()
    .min(1)
    .max(2)
    .optional()
    .default(1)
    .describe('Depth used when building compact string/function context'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist compact crypto-identification results as a JSON artifact'),
  reuse_cached: z
    .boolean()
    .optional()
    .default(true)
    .describe('Reuse the latest persisted crypto-identification artifact when available'),
  artifact_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .default('latest')
    .describe('Artifact selection scope used when reuse_cached=true'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass artifact reuse and recompute from current static and optional dynamic evidence'),
  defer_if_slow: z
    .boolean()
    .optional()
    .default(true)
    .describe('When true, mode=full may be deferred instead of blocking the MCP request on medium/large samples.'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag used when persisting crypto-identification artifacts'),
})

export type CryptoIdentifyInput = z.infer<typeof cryptoIdentifyInputSchema>

export const cryptoIdentifyOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'partial']),
      sample_id: z.string(),
      result_mode: z.enum(['preview', 'full']).optional(),
      execution_state: z.enum(['inline', 'queued', 'partial', 'completed']).optional(),
      job_id: z.string().optional(),
      polling_guidance: z.any().optional(),
      xref_status: z.enum(['available', 'unavailable']),
      evidence_state: z.array(AnalysisEvidenceStateSchema).optional(),
      algorithms: z.array(CryptoFindingSchema),
      candidate_constants: z.array(CryptoConstantCandidateSchema),
      runtime_observed_apis: z.array(z.string()),
      summary: z.string(),
      source_artifact_refs: z.array(z.any()),
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
    })
    .optional(),
})

export const cryptoIdentifyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Correlate imports, enriched strings, bounded xrefs, capability hints, and optional runtime evidence into compact crypto findings with typed key/table summaries. ' +
    'Use this when a sample looks crypto-heavy and you need function-localized evidence before breakpoint planning. ' +
    'Prefer mode=preview first; use mode=full only when decoded-string and deeper context correlation are worth the extra cost.',
  inputSchema: cryptoIdentifyInputSchema,
  outputSchema: cryptoIdentifyOutputSchema,
}

interface CryptoIdentifyDependencies {
  stringsExtract?: (args: unknown) => Promise<WorkerResult>
  stringsFlossDecode?: (args: unknown) => Promise<WorkerResult>
  analysisContextLink?: (args: unknown) => Promise<WorkerResult>
  peImportsExtract?: (args: unknown) => Promise<WorkerResult>
  staticCapabilityTriage?: (args: unknown) => Promise<WorkerResult>
  loadDynamicTrace?: (
    workspaceManager: WorkspaceManager,
    database: DatabaseManager,
    sampleId: string,
    options?: { evidenceScope?: DynamicEvidenceScope; sessionTag?: string }
  ) => Promise<DynamicTraceSummary | null>
}

function dedupeArtifactRefs(artifacts: ArtifactRef[]): ArtifactRef[] {
  const seen = new Set<string>()
  const output: ArtifactRef[] = []
  for (const artifact of artifacts) {
    const key = artifact.id || `${artifact.type}:${artifact.path}`
    if (!key || seen.has(key)) {
      continue
    }
    seen.add(key)
    output.push(artifact)
  }
  return output
}

function collectArtifactRefs(result: WorkerResult | undefined): ArtifactRef[] {
  if (!result) {
    return []
  }

  const refs: ArtifactRef[] = []
  if (Array.isArray(result.artifacts)) {
    refs.push(...(result.artifacts.filter((item) => item && typeof item === 'object') as ArtifactRef[]))
  }
  const data = result.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  if (data.artifact && typeof data.artifact === 'object') {
    refs.push(data.artifact as ArtifactRef)
  }
  if (Array.isArray(data.source_artifact_refs)) {
    refs.push(...(data.source_artifact_refs.filter((item) => item && typeof item === 'object') as ArtifactRef[]))
  }
  return refs
}

function collectStringRecords(result: WorkerResult | undefined): BasicStringRecord[] {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  const enriched = data.enriched && typeof data.enriched === 'object' ? (data.enriched as Record<string, unknown>) : {}
  const enrichedRecords = Array.isArray(enriched.records) ? enriched.records : []
  if (enrichedRecords.length > 0) {
    return enrichedRecords
      .map((item) => {
        const record = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
        if (typeof record.value !== 'string') {
          return null
        }
        return {
          value: record.value,
          labels: Array.isArray(record.labels) ? record.labels.map((entry) => String(entry)) : [],
          categories: Array.isArray(record.categories) ? record.categories.map((entry) => String(entry)) : [],
          function_refs: Array.isArray(record.function_refs)
            ? record.function_refs
                .map((entry) => {
                  const ref = entry && typeof entry === 'object' ? (entry as Record<string, unknown>) : {}
                  return {
                    address: typeof ref.address === 'string' ? ref.address : undefined,
                    name: typeof ref.name === 'string' ? ref.name : null,
                  }
                })
                .filter((entry) => entry.address || entry.name)
            : [],
        }
      })
      .filter(Boolean) as BasicStringRecord[]
  }

  const rawStrings = Array.isArray(data.strings)
    ? data.strings.map((item) => ({
        value: typeof (item as Record<string, unknown>)?.string === 'string'
          ? String((item as Record<string, unknown>).string)
          : '',
      }))
    : Array.isArray(data.decoded_strings)
      ? data.decoded_strings.map((item) => ({
          value: typeof (item as Record<string, unknown>)?.string === 'string'
            ? String((item as Record<string, unknown>).string)
            : '',
          labels: ['decoded_signal'],
        }))
      : []
  return rawStrings.filter((item) => item.value.length > 0) as BasicStringRecord[]
}

function mergeStringRecords(...groups: BasicStringRecord[][]): BasicStringRecord[] {
  const merged = new Map<string, BasicStringRecord>()
  for (const group of groups) {
    for (const record of group) {
      const key = `${record.value}::${(record.function_refs || []).map((item) => item.address || item.name || '').join(',')}`
      const existing = merged.get(key)
      if (!existing) {
        merged.set(key, {
          value: record.value,
          labels: [...(record.labels || [])],
          categories: [...(record.categories || [])],
          function_refs: [...(record.function_refs || [])],
        })
        continue
      }
      merged.set(key, {
        value: record.value,
        labels: Array.from(new Set([...(existing.labels || []), ...(record.labels || [])])),
        categories: Array.from(new Set([...(existing.categories || []), ...(record.categories || [])])),
        function_refs: Array.from(
          new Map(
            [...(existing.function_refs || []), ...(record.function_refs || [])]
              .filter((item) => item.address || item.name)
              .map((item) => [`${item.address || ''}:${item.name || ''}`, item])
          ).values()
        ),
      })
    }
  }
  return [...merged.values()]
}

function collectFunctionContexts(result: WorkerResult | undefined): FunctionContextLike[] {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  return Array.isArray(data.function_contexts)
    ? data.function_contexts
        .map((item) => {
          const context = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
          return {
            function: typeof context.function === 'string' ? context.function : undefined,
            address: typeof context.address === 'string' ? context.address : undefined,
            top_strings: Array.isArray(context.top_strings) ? context.top_strings.map((entry) => String(entry)) : [],
            sensitive_apis: Array.isArray(context.sensitive_apis)
              ? context.sensitive_apis.map((entry) => String(entry))
              : [],
            rationale: Array.isArray(context.rationale) ? context.rationale.map((entry) => String(entry)) : [],
          }
        })
        .filter((item) => item.function || item.address)
    : []
}

function extractImportsMap(result: WorkerResult | undefined): Record<string, string[]> | undefined {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  return data.imports && typeof data.imports === 'object'
    ? Object.fromEntries(
        Object.entries(data.imports as Record<string, unknown>).map(([key, value]) => [
          key,
          Array.isArray(value) ? value.map((item) => String(item)) : [],
        ])
      )
    : undefined
}

function hasCryptoCapability(result: WorkerResult | undefined): boolean {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  const namespaces = Array.isArray(data.behavior_namespaces)
    ? data.behavior_namespaces.map((item) => String(item))
    : []
  if (namespaces.some((item) => /(crypt|aes|rsa|hash|cipher|key|decrypt|encrypt)/i.test(item))) {
    return true
  }

  const groups = data.capability_groups && typeof data.capability_groups === 'object'
    ? Object.keys(data.capability_groups as Record<string, unknown>)
    : []
  if (groups.some((item) => /(crypt|aes|rsa|hash|cipher|key|decrypt|encrypt)/i.test(item))) {
    return true
  }

  const capabilities = Array.isArray(data.capabilities) ? data.capabilities : []
  return capabilities.some((item) => {
    const capability = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
    return [capability.name, capability.namespace, capability.group]
      .map((entry) => (typeof entry === 'string' ? entry : ''))
      .some((entry) => /(crypt|aes|rsa|hash|cipher|key|decrypt|encrypt)/i.test(entry))
  })
}

function buildRecommendations(xrefStatus: 'available' | 'unavailable', findingsCount: number) {
  if (findingsCount === 0) {
    return {
      recommended_next_tools: ['analysis.context.link', 'code.xrefs.analyze', 'breakpoint.smart'],
      next_actions: [
        'Inspect compact string/Xref context first, then retry crypto.identify after stronger function attribution exists.',
        'Use breakpoint.smart only after reviewing whether the crypto evidence is strong enough to justify instrumentation.',
      ],
    }
  }

  return {
    recommended_next_tools:
      xrefStatus === 'available'
        ? ['breakpoint.smart', 'trace.condition', 'code.xrefs.analyze', 'frida.runtime.instrument']
        : ['ghidra.analyze', 'breakpoint.smart', 'trace.condition', 'code.xrefs.analyze'],
    next_actions:
      xrefStatus === 'available'
        ? [
            'Use breakpoint.smart to rank likely crypto routine or API transition breakpoints from these findings.',
            'Use trace.condition to turn a top breakpoint candidate into a bounded Frida-oriented trace plan before live instrumentation.',
          ]
        : [
            'Run ghidra.analyze first if you need stronger function-localized crypto evidence before breakpoint planning.',
            'Use breakpoint.smart only after reviewing whether sample-level crypto evidence is strong enough for manual instrumentation.',
          ],
  }
}

export function createCryptoIdentifyHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies: CryptoIdentifyDependencies = {},
  jobQueue?: JobQueue,
  options: { allowDeferred?: boolean } = {}
) {
  const stringsExtractHandler =
    dependencies.stringsExtract || createStringsExtractHandler(workspaceManager, database, cacheManager)
  const stringsFlossDecodeHandler =
    dependencies.stringsFlossDecode || createStringsFlossDecodeHandler(workspaceManager, database, cacheManager)
  const analysisContextLinkHandler =
    dependencies.analysisContextLink || createAnalysisContextLinkHandler(workspaceManager, database, cacheManager)
  const peImportsExtractHandler =
    dependencies.peImportsExtract || createPEImportsExtractHandler({ workspaceManager, database, cacheManager } as any)
  const staticCapabilityTriageHandler =
    dependencies.staticCapabilityTriage || createStaticCapabilityTriageHandler(workspaceManager, database)
  const dynamicTraceLoader = dependencies.loadDynamicTrace || loadDynamicTraceEvidence

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = cryptoIdentifyInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }
      const sampleSizeTier = classifySampleSizeTier(sample.size)
      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          mode: input.mode,
          include_runtime_evidence: input.include_runtime_evidence,
          runtime_evidence_scope: input.runtime_evidence_scope,
          max_findings: input.max_findings,
          max_constants: input.max_constants,
          max_contexts: input.max_contexts,
          xref_depth: input.xref_depth,
        },
      })

      if (!input.force_refresh) {
        const resolved = await resolveCanonicalEvidenceOrCache(database, cacheManager, cacheKey, {
          sample,
          evidenceFamily: 'crypto_identify',
          backend: TOOL_NAME,
          mode: input.mode,
          args: {
            include_runtime_evidence: input.include_runtime_evidence,
            runtime_evidence_scope: input.runtime_evidence_scope,
            max_findings: input.max_findings,
            max_constants: input.max_constants,
            max_contexts: input.max_contexts,
            xref_depth: input.xref_depth,
          },
        })
        if (resolved) {
          return {
            ok: true,
            data: {
              ...(resolved.record.result as Record<string, unknown>),
              result_mode: input.mode,
              execution_state:
                typeof (resolved.record.result as Record<string, unknown>)?.execution_state === 'string'
                  ? (resolved.record.result as Record<string, unknown>).execution_state
                  : 'completed',
              evidence_state: [buildResolvedEvidenceState(resolved)],
            },
            warnings: buildEvidenceReuseWarnings(resolved),
            artifacts: resolved.record.artifact_refs,
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
              cached: true,
            },
          }
        }
      }

      if (input.reuse_cached && !input.force_refresh) {
        const selection = await loadCryptoPlanningArtifactSelection<Record<string, unknown>>(
          workspaceManager,
          database,
          input.sample_id,
          CRYPTO_IDENTIFICATION_ARTIFACT_TYPE,
          {
            scope: input.artifact_scope as CryptoPlanningArtifactScope,
            sessionTag: input.session_tag,
          }
        )
        if (selection.latest_payload) {
          return {
            ok: true,
            data: {
              ...(selection.latest_payload as Record<string, unknown>),
              result_mode: input.mode,
              execution_state:
                typeof (selection.latest_payload as Record<string, unknown>)?.execution_state === 'string'
                  ? (selection.latest_payload as Record<string, unknown>).execution_state
                  : 'completed',
              evidence_state: [
                AnalysisEvidenceStateSchema.parse({
                  evidence_family: 'crypto_identify',
                  backend: TOOL_NAME,
                  mode: input.mode,
                  state: 'reused',
                  source: 'artifact',
                  updated_at: selection.latest_created_at || null,
                  freshness_marker: null,
                  reason: 'Reused a persisted crypto-identification artifact selection.',
                }),
              ],
            },
            warnings: [`Result from persisted artifact`, selection.scope_note],
            artifacts: selection.artifact_refs,
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
              cached: true,
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
            'Full crypto identification was deferred because full decoded-string plus context correlation is too expensive for synchronous MCP requests on a medium or larger sample.',
          nextTools: ['task.status', 'analysis.context.link', 'breakpoint.smart'],
          nextActions: [
            'Use mode=preview for a bounded crypto hint set without waiting on full decoded/context correlation.',
            'Poll task.status with the returned job_id before requesting the same full crypto-identify pass again.',
          ],
          metadata: {
            evidence_state: [
              buildDeferredEvidenceState({
                evidenceFamily: 'crypto_identify',
                backend: TOOL_NAME,
                mode: input.mode,
                reason:
                  'Full crypto identification was deferred because the requested sample size exceeds the synchronous crypto-correlation budget.',
              }),
            ],
          },
        })
      }

      const warnings: string[] = []
      const stringsResult = await stringsExtractHandler({
        sample_id: input.sample_id,
        mode: input.mode === 'preview' ? 'preview' : 'full',
        max_strings: input.mode === 'preview' ? 240 : 800,
        persist_artifact: false,
        enrich_result: true,
        force_refresh: input.force_refresh,
        defer_if_slow: false,
        session_tag: input.session_tag,
      })
      const decodedResult =
        input.mode === 'full'
          ? await stringsFlossDecodeHandler({
              sample_id: input.sample_id,
              timeout: 90,
              persist_artifact: false,
              enrich_result: true,
              force_refresh: input.force_refresh,
              defer_if_slow: false,
              session_tag: input.session_tag,
            })
          : undefined
      const contextResult = await analysisContextLinkHandler({
        sample_id: input.sample_id,
        mode: input.mode,
        include_decoded: input.mode === 'full',
        max_records: input.mode === 'preview' ? Math.min(60, input.max_findings * 10) : 90,
        max_functions: input.mode === 'preview' ? Math.min(input.max_contexts, 4) : input.max_contexts,
        xref_depth: input.xref_depth,
        persist_artifact: false,
        reuse_cached: true,
        force_refresh: input.force_refresh,
        defer_if_slow: false,
        session_tag: input.session_tag,
      })
      const importsResult = await peImportsExtractHandler({
        sample_id: input.sample_id,
        group_by_dll: true,
        force_refresh: input.force_refresh,
      })
      const capabilityResult = await staticCapabilityTriageHandler({
        sample_id: input.sample_id,
        timeout: 120,
        persist_artifact: false,
        register_analysis: false,
        session_tag: input.session_tag,
      })

      warnings.push(...(stringsResult.warnings || []))
      warnings.push(...(decodedResult?.warnings || []))
      warnings.push(...(contextResult.warnings || []))
      warnings.push(...(importsResult.warnings || []))
      warnings.push(...(capabilityResult.warnings || []))

      const dynamicEvidence =
        input.include_runtime_evidence
          ? await dynamicTraceLoader(workspaceManager, database, input.sample_id, {
              evidenceScope: input.runtime_evidence_scope,
              sessionTag: input.session_tag,
            })
          : null

      const stringRecords = mergeStringRecords(
        collectStringRecords(stringsResult),
        collectStringRecords(decodedResult)
      )
      const functionContexts = collectFunctionContexts(contextResult)
      const importsMap = extractImportsMap(importsResult)
      const xrefStatus =
        contextResult.ok &&
        contextResult.data &&
        typeof contextResult.data === 'object' &&
        (contextResult.data as Record<string, unknown>).xref_status === 'available'
          ? 'available'
          : 'unavailable'

      const built = buildCryptoFindings({
        functionContexts,
        stringRecords,
        imports: importsMap,
        dynamicEvidence,
        hasCryptoCapability: hasCryptoCapability(capabilityResult),
        maxFindings: input.max_findings,
        maxConstantsPerFinding: Math.max(1, Math.min(input.max_constants || 1, 6)),
        xrefAvailable: xrefStatus === 'available',
      })

      let algorithms = built.findings
      const candidateConstants = built.candidateConstants.slice(0, input.max_constants)
      const sourceArtifactRefs = dedupeArtifactRefs([
        ...collectArtifactRefs(stringsResult),
        ...collectArtifactRefs(decodedResult),
        ...collectArtifactRefs(contextResult),
        ...collectArtifactRefs(importsResult),
        ...collectArtifactRefs(capabilityResult),
      ])
      const recommendations = buildRecommendations(xrefStatus, algorithms.length)
      const summaryBase = summarizeCryptoFindings(algorithms)
      const summary =
        dynamicEvidence && built.dynamicApis.length > 0
          ? `${summaryBase} Runtime evidence observed ${built.dynamicApis.slice(0, 6).join(', ')}.`
          : summaryBase
      let chunkManifest: Record<string, unknown> | undefined
      const chunkWarnings: string[] = []
      let chunkArtifacts: ArtifactRef[] = []

      if (input.mode === 'full' && algorithms.length > chooseInlineCryptoFindingLimit(sampleSizeTier)) {
        const chunked = await persistChunkedArrayArtifacts(algorithms, {
          family: 'crypto_identify',
          inlineLimit: chooseInlineCryptoFindingLimit(sampleSizeTier),
          chunkSize: CRYPTO_FINDING_CHUNK_SIZE,
          notes: [
            'Large-sample crypto identification retained a bounded inline digest and persisted the remaining findings as chunk artifacts.',
          ],
          buildLabel: (index, itemCount) => `crypto chunk ${index + 1} (${itemCount} findings)`,
          persistChunk: async ({ index, itemCount, items }) =>
            persistCryptoPlanningJsonArtifact(
              workspaceManager,
              database,
              input.sample_id,
              CRYPTO_IDENTIFICATION_ARTIFACT_TYPE,
              `crypto_identification_chunk_${String(index + 1).padStart(3, '0')}`,
              {
                sample_id: input.sample_id,
                session_tag: input.session_tag || null,
                created_at: new Date().toISOString(),
                chunk_index: index,
                chunk_item_count: itemCount,
                total_items: algorithms.length,
                algorithms: items,
              },
              input.session_tag
            ),
        })
        if (chunked.manifest) {
          algorithms = chunked.inline_items
          chunkManifest = chunked.manifest
          chunkArtifacts = chunked.chunk_artifacts
          chunkWarnings.push(
            `Bounded inline crypto findings to ${algorithms.length} and persisted ${chunkArtifacts.length} chunk artifact(s).`
          )
        }
      }

      const outputData = {
        status: (xrefStatus === 'available' ? 'ready' : 'partial') as 'ready' | 'partial',
        sample_id: input.sample_id,
        result_mode: input.mode,
        execution_state: xrefStatus === 'available' ? 'completed' : 'partial',
        xref_status: xrefStatus,
        evidence_state: [
          buildFreshEvidenceState({
            evidenceFamily: 'crypto_identify',
            backend: TOOL_NAME,
            mode: input.mode,
          }),
        ],
        algorithms,
        candidate_constants: candidateConstants,
        runtime_observed_apis: collectCryptoApiNames(importsMap, dynamicEvidence),
        summary,
        source_artifact_refs: sourceArtifactRefs,
        ...(chunkManifest ? { chunk_manifest: chunkManifest } : {}),
        recommended_next_tools: recommendations.recommended_next_tools,
        next_actions: recommendations.next_actions,
      }

      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistCryptoPlanningJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          CRYPTO_IDENTIFICATION_ARTIFACT_TYPE,
          'crypto_identification',
          {
            ...outputData,
            session_tag: input.session_tag || null,
          },
          input.session_tag
        )
      }
      await cacheManager.setCachedResult(cacheKey, outputData, CACHE_TTL_MS, sample.sha256)
      persistCanonicalEvidence(database, {
        sample,
        evidenceFamily: 'crypto_identify',
        backend: TOOL_NAME,
        mode: input.mode,
        args: {
          include_runtime_evidence: input.include_runtime_evidence,
          runtime_evidence_scope: input.runtime_evidence_scope,
          max_findings: input.max_findings,
          max_constants: input.max_constants,
          max_contexts: input.max_contexts,
          xref_depth: input.xref_depth,
        },
        result: outputData,
        artifactRefs: artifact ? [...sourceArtifactRefs, ...chunkArtifacts, artifact] : [...sourceArtifactRefs, ...chunkArtifacts],
        metadata: {
          cache_key: cacheKey,
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
        data: {
          ...outputData,
          ...(artifact ? { artifact } : {}),
        },
        warnings: Array.from(
          new Set([...warnings, ...chunkWarnings].filter((item) => item.trim().length > 0))
        ),
        artifacts: artifact ? [...sourceArtifactRefs, ...chunkArtifacts, artifact] : [...sourceArtifactRefs, ...chunkArtifacts],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
