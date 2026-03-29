import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { ArtifactRef } from './types.js'
import type { AnalysisEvidence, DatabaseManager, Sample } from './database.js'
import type { CacheHitLookup, CacheManager } from './cache-manager.js'

export const ANALYSIS_EVIDENCE_VERSION = 'analysis-runtime-convergence-v1'

export const AnalysisEvidenceFamilySchema = z.enum([
  'strings',
  'binary_role',
  'context_link',
  'crypto_identify',
  'backend_preview',
  'summary',
  'unpack_plan',
  'unpack_execution',
  'debug_session',
  'analysis_diff',
])

export const ChunkedEvidenceCompletenessSchema = z.enum(['complete', 'partial'])

export const AnalysisEvidenceChunkEntrySchema = z.object({
  index: z.number().int().nonnegative(),
  item_count: z.number().int().nonnegative(),
  label: z.string(),
  artifact_ref: z.any(),
})

export const AnalysisEvidenceChunkManifestSchema = z.object({
  family: z.string(),
  total_items: z.number().int().nonnegative(),
  inline_items: z.number().int().nonnegative(),
  chunk_size: z.number().int().positive(),
  total_chunks: z.number().int().nonnegative(),
  completeness: ChunkedEvidenceCompletenessSchema,
  resume_supported: z.boolean().default(true),
  truncated_inline: z.boolean().default(false),
  chunk_artifact_refs: z.array(z.any()),
  chunks: z.array(AnalysisEvidenceChunkEntrySchema),
  notes: z.array(z.string()).optional(),
})

export const AnalysisEvidenceRecordSchema = z.object({
  evidence_id: z.string(),
  evidence_family: AnalysisEvidenceFamilySchema,
  backend: z.string(),
  mode: z.string(),
  compatibility_marker: z.string(),
  freshness_marker: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
  provenance: z.record(z.any()).optional(),
  metadata: z.record(z.any()).optional(),
  artifact_refs: z.array(z.any()),
  result: z.any(),
})

export const AnalysisEvidenceStateSchema = z.object({
  evidence_family: z.string(),
  backend: z.string(),
  mode: z.string(),
  state: z.enum(['fresh', 'reused', 'partial', 'stale', 'incompatible', 'missing', 'deferred']),
  source: z.enum(['analysis_evidence', 'cache', 'artifact', 'run_stage', 'none']),
  updated_at: z.string().nullable(),
  freshness_marker: z.string().nullable().optional(),
  reason: z.string(),
})

export type AnalysisEvidenceFamily = z.infer<typeof AnalysisEvidenceFamilySchema>
export type AnalysisEvidenceRecord = z.infer<typeof AnalysisEvidenceRecordSchema>
export type AnalysisEvidenceState = z.infer<typeof AnalysisEvidenceStateSchema>
export type AnalysisEvidenceChunkManifest = z.infer<typeof AnalysisEvidenceChunkManifestSchema>

export interface CanonicalEvidenceIdentity {
  sample: Pick<Sample, 'id' | 'sha256'>
  evidenceFamily: AnalysisEvidenceFamily
  backend: string
  mode: string
  args?: Record<string, unknown>
  freshnessMarker?: string | null
}

export interface CanonicalEvidencePersistInput extends CanonicalEvidenceIdentity {
  result: unknown
  artifactRefs?: ArtifactRef[]
  provenance?: Record<string, unknown>
  metadata?: Record<string, unknown>
}

export interface CanonicalEvidenceLookupInput extends CanonicalEvidenceIdentity {}

export interface ResolvedCanonicalEvidence {
  source: 'analysis_evidence' | 'cache'
  record: AnalysisEvidenceRecord
  cache?: CacheHitLookup
}

export interface EvidenceStateOptions {
  staleAfterMs?: number
}

export function buildAnalysisEvidenceCompatibilityMarker(input: CanonicalEvidenceIdentity): string {
  const payload = JSON.stringify({
    sample_sha256: input.sample.sha256,
    evidence_family: input.evidenceFamily,
    backend: input.backend,
    mode: input.mode,
    args: input.args || {},
    freshness_marker: input.freshnessMarker || null,
    version: ANALYSIS_EVIDENCE_VERSION,
  })
  return createHash('sha256').update(payload).digest('hex')
}

function toRow(input: CanonicalEvidencePersistInput): AnalysisEvidence {
  const compatibilityMarker = buildAnalysisEvidenceCompatibilityMarker(input)
  const now = new Date().toISOString()
  return {
    id: randomUUID(),
    sample_id: input.sample.id,
    sample_sha256: input.sample.sha256,
    evidence_family: input.evidenceFamily,
    backend: input.backend,
    mode: input.mode,
    compatibility_marker: compatibilityMarker,
    freshness_marker: input.freshnessMarker || null,
    provenance_json: JSON.stringify(input.provenance || {}),
    metadata_json: JSON.stringify(input.metadata || {}),
    result_json: JSON.stringify(input.result),
    artifact_refs_json: JSON.stringify(input.artifactRefs || []),
    created_at: now,
    updated_at: now,
    last_accessed_at: now,
  }
}

function parseJsonValue<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw || !raw.trim()) {
    return fallback
  }
  try {
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

export function buildChunkedEvidenceManifest(input: {
  family: string
  totalItems: number
  inlineItems: number
  chunkSize: number
  chunks: Array<{
    index: number
    itemCount: number
    label: string
    artifactRef: ArtifactRef
  }>
  completeness?: z.infer<typeof ChunkedEvidenceCompletenessSchema>
  notes?: string[]
}): AnalysisEvidenceChunkManifest {
  return AnalysisEvidenceChunkManifestSchema.parse({
    family: input.family,
    total_items: Math.max(0, input.totalItems),
    inline_items: Math.max(0, input.inlineItems),
    chunk_size: Math.max(1, input.chunkSize),
    total_chunks: input.chunks.length,
    completeness: input.completeness || 'complete',
    resume_supported: true,
    truncated_inline: input.totalItems > input.inlineItems,
    chunk_artifact_refs: input.chunks.map((chunk) => chunk.artifactRef),
    chunks: input.chunks.map((chunk) => ({
      index: chunk.index,
      item_count: chunk.itemCount,
      label: chunk.label,
      artifact_ref: chunk.artifactRef,
    })),
    ...(input.notes && input.notes.length > 0 ? { notes: input.notes } : {}),
  })
}

export function readChunkedEvidenceManifest(
  record: Pick<AnalysisEvidenceRecord, 'metadata'>
): AnalysisEvidenceChunkManifest | null {
  const manifest = record.metadata?.chunk_manifest
  const parsed = AnalysisEvidenceChunkManifestSchema.safeParse(manifest)
  return parsed.success ? parsed.data : null
}

export function parseAnalysisEvidenceRow(row: AnalysisEvidence): AnalysisEvidenceRecord {
  return AnalysisEvidenceRecordSchema.parse({
    evidence_id: row.id,
    evidence_family: row.evidence_family,
    backend: row.backend,
    mode: row.mode,
    compatibility_marker: row.compatibility_marker,
    freshness_marker: row.freshness_marker,
    created_at: row.created_at,
    updated_at: row.updated_at,
    provenance: parseJsonValue<Record<string, unknown>>(row.provenance_json, {}),
    metadata: parseJsonValue<Record<string, unknown>>(row.metadata_json, {}),
    artifact_refs: parseJsonValue<ArtifactRef[]>(row.artifact_refs_json, []),
    result: parseJsonValue<unknown>(row.result_json, null),
  })
}

export function persistCanonicalEvidence(
  database: DatabaseManager,
  input: CanonicalEvidencePersistInput
): AnalysisEvidenceRecord {
  const compatibilityMarker = buildAnalysisEvidenceCompatibilityMarker(input)
  const existing = database.findLatestCompatibleAnalysisEvidence(
    input.sample.id,
    input.evidenceFamily,
    compatibilityMarker
  )
  const now = new Date().toISOString()
  if (existing) {
    database.updateAnalysisEvidence(existing.id, {
      backend: input.backend,
      mode: input.mode,
      freshness_marker: input.freshnessMarker || null,
      provenance_json: JSON.stringify(input.provenance || {}),
      metadata_json: JSON.stringify(input.metadata || {}),
      result_json: JSON.stringify(input.result),
      artifact_refs_json: JSON.stringify(input.artifactRefs || []),
      updated_at: now,
      last_accessed_at: now,
    })
    return parseAnalysisEvidenceRow({
      ...existing,
      backend: input.backend,
      mode: input.mode,
      freshness_marker: input.freshnessMarker || null,
      provenance_json: JSON.stringify(input.provenance || {}),
      metadata_json: JSON.stringify(input.metadata || {}),
      result_json: JSON.stringify(input.result),
      artifact_refs_json: JSON.stringify(input.artifactRefs || []),
      updated_at: now,
      last_accessed_at: now,
    })
  }

  const row = toRow(input)
  database.insertAnalysisEvidence(row)
  return parseAnalysisEvidenceRow(row)
}

export function findCanonicalEvidence(
  database: DatabaseManager,
  input: CanonicalEvidenceLookupInput
): AnalysisEvidenceRecord | null {
  const compatibilityMarker = buildAnalysisEvidenceCompatibilityMarker(input)
  const row = database.findLatestCompatibleAnalysisEvidence(
    input.sample.id,
    input.evidenceFamily,
    compatibilityMarker
  )
  if (!row) {
    return null
  }
  const now = new Date().toISOString()
  database.updateAnalysisEvidence(row.id, {
    last_accessed_at: now,
    updated_at: row.updated_at,
  })
  return parseAnalysisEvidenceRow({
    ...row,
    last_accessed_at: now,
  })
}

export async function resolveCanonicalEvidenceOrCache(
  database: DatabaseManager,
  cacheManager: CacheManager,
  cacheKey: string,
  input: CanonicalEvidenceLookupInput
): Promise<ResolvedCanonicalEvidence | null> {
  const canonical = findCanonicalEvidence(database, input)
  if (canonical) {
    return {
      source: 'analysis_evidence',
      record: canonical,
    }
  }

  const cache = await cacheManager.getCachedResultWithMetadata(cacheKey)
  if (!cache) {
    return null
  }

  return {
    source: 'cache',
    cache,
    record: AnalysisEvidenceRecordSchema.parse({
      evidence_id: `cache:${cache.metadata.key}`,
      evidence_family: input.evidenceFamily,
      backend: input.backend,
      mode: input.mode,
      compatibility_marker: buildAnalysisEvidenceCompatibilityMarker(input),
      freshness_marker: input.freshnessMarker || null,
      created_at: cache.metadata.createdAt || cache.metadata.fetchedAt,
      updated_at: cache.metadata.fetchedAt,
      provenance: {
        source: 'cache',
        cache_tier: cache.metadata.tier,
      },
      metadata: {
        cache_key: cache.metadata.key,
      },
      artifact_refs: [],
      result: cache.data,
    }),
  }
}

export function buildEvidenceReuseWarnings(
  resolved: ResolvedCanonicalEvidence
): string[] {
  if (resolved.source === 'analysis_evidence') {
    return [
      `Reused canonical evidence (${resolved.record.evidence_family}/${resolved.record.backend}/${resolved.record.mode}).`,
    ]
  }
  return [
    'Result from cache',
  ]
}

function classifyResolvedEvidenceState(
  resolved: ResolvedCanonicalEvidence,
  options: EvidenceStateOptions = {}
): Pick<AnalysisEvidenceState, 'state' | 'reason' | 'updated_at' | 'freshness_marker'> {
  const updatedAt = resolved.record.updated_at || null
  const chunkManifest = readChunkedEvidenceManifest(resolved.record)
  if (chunkManifest?.completeness === 'partial') {
    return {
      state: 'partial',
      updated_at: updatedAt,
      freshness_marker: resolved.record.freshness_marker || null,
      reason:
        resolved.source === 'analysis_evidence'
          ? `Canonical evidence is only partially complete (${chunkManifest.total_chunks} chunk artifact(s)); resume from the persisted chunk manifest before treating it as complete.`
          : `Cached chunked evidence is only partially complete (${chunkManifest.total_chunks} chunk artifact(s)); resume from the persisted chunk manifest before treating it as complete.`,
    }
  }
  const staleAfterMs = options.staleAfterMs
  if (updatedAt && typeof staleAfterMs === 'number' && Number.isFinite(staleAfterMs) && staleAfterMs > 0) {
    const ageMs = Date.now() - new Date(updatedAt).getTime()
    if (Number.isFinite(ageMs) && ageMs > staleAfterMs) {
      return {
        state: 'stale',
        updated_at: updatedAt,
        freshness_marker: resolved.record.freshness_marker || null,
        reason:
          resolved.source === 'analysis_evidence'
            ? `Persisted canonical evidence is older than the configured freshness window (${Math.round(ageMs / 1000)}s).`
            : `Cached evidence is older than the configured freshness window (${Math.round(ageMs / 1000)}s).`,
      }
    }
  }

  return {
    state: 'reused',
    updated_at: updatedAt,
    freshness_marker: resolved.record.freshness_marker || null,
    reason:
      resolved.source === 'analysis_evidence'
        ? 'Reused compatible canonical evidence.'
        : 'Reused compatible cached evidence.',
  }
}

export function buildResolvedEvidenceState(
  resolved: ResolvedCanonicalEvidence,
  options: EvidenceStateOptions = {}
): AnalysisEvidenceState {
  const classified = classifyResolvedEvidenceState(resolved, options)
  return AnalysisEvidenceStateSchema.parse({
    evidence_family: resolved.record.evidence_family,
    backend: resolved.record.backend,
    mode: resolved.record.mode,
    state: classified.state,
    source: resolved.source,
    updated_at: classified.updated_at,
    freshness_marker: classified.freshness_marker,
    reason: classified.reason,
  })
}

export function buildFreshEvidenceState(input: {
  evidenceFamily: string
  backend: string
  mode: string
  updatedAt?: string | null
  freshnessMarker?: string | null
  reason?: string
}): AnalysisEvidenceState {
  return AnalysisEvidenceStateSchema.parse({
    evidence_family: input.evidenceFamily,
    backend: input.backend,
    mode: input.mode,
    state: 'fresh',
    source: 'analysis_evidence',
    updated_at: input.updatedAt || new Date().toISOString(),
    freshness_marker: input.freshnessMarker || null,
    reason: input.reason || 'Computed fresh evidence during this request.',
  })
}

export function buildPartialEvidenceState(input: {
  evidenceFamily: string
  backend: string
  mode: string
  updatedAt?: string | null
  freshnessMarker?: string | null
  reason: string
}): AnalysisEvidenceState {
  return AnalysisEvidenceStateSchema.parse({
    evidence_family: input.evidenceFamily,
    backend: input.backend,
    mode: input.mode,
    state: 'partial',
    source: 'analysis_evidence',
    updated_at: input.updatedAt || new Date().toISOString(),
    freshness_marker: input.freshnessMarker || null,
    reason: input.reason,
  })
}

export function buildMissingEvidenceState(input: {
  evidenceFamily: string
  backend: string
  mode: string
  reason: string
}): AnalysisEvidenceState {
  return AnalysisEvidenceStateSchema.parse({
    evidence_family: input.evidenceFamily,
    backend: input.backend,
    mode: input.mode,
    state: 'missing',
    source: 'none',
    updated_at: null,
    freshness_marker: null,
    reason: input.reason,
  })
}

export function buildDeferredEvidenceState(input: {
  evidenceFamily: string
  backend: string
  mode: string
  reason: string
}): AnalysisEvidenceState {
  return AnalysisEvidenceStateSchema.parse({
    evidence_family: input.evidenceFamily,
    backend: input.backend,
    mode: input.mode,
    state: 'deferred',
    source: 'none',
    updated_at: null,
    freshness_marker: null,
    reason: input.reason,
  })
}
