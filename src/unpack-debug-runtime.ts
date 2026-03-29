import fs from 'fs/promises'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { ArtifactRef } from './types.js'
import type { DatabaseManager, DebugSession, Sample } from './database.js'
import type { WorkspaceManager } from './workspace-manager.js'
import { deriveArtifactSessionTag } from './artifact-inventory.js'

export const PACKED_STATE_VALUES = [
  'unknown',
  'not_packed',
  'suspected_packed',
  'confirmed_packed',
] as const

export const UNPACK_STATE_VALUES = [
  'not_applicable',
  'not_started',
  'unpack_planned',
  'unpack_in_progress',
  'partially_unpacked',
  'unpacked',
  'rebuild_required',
  'unpack_failed_recoverable',
  'approval_gated',
] as const

export const DEBUG_STATE_VALUES = [
  'not_requested',
  'planned',
  'armed',
  'capturing',
  'captured',
  'correlated',
  'interrupted_recoverable',
  'approval_gated',
] as const

export const UNPACK_SAFETY_LEVEL_VALUES = [
  'preview_only',
  'dump_oriented',
  'rebuild_oriented',
  'approval_gated',
] as const

export const UNPACK_PLAN_ARTIFACT_TYPE = 'unpack_plan'
export const UNPACK_EXECUTION_ARTIFACT_TYPE = 'unpack_execution'
export const ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE = 'analysis_diff_digest'
export const DEBUG_SESSION_ARTIFACT_TYPE = 'debug_session_digest'

export type UnpackDebugArtifactType =
  | typeof UNPACK_PLAN_ARTIFACT_TYPE
  | typeof UNPACK_EXECUTION_ARTIFACT_TYPE
  | typeof ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE
  | typeof DEBUG_SESSION_ARTIFACT_TYPE

export type UnpackDebugArtifactScope = 'all' | 'latest' | 'session'

export const PackedStateSchema = z.enum(PACKED_STATE_VALUES)
export const UnpackStateSchema = z.enum(UNPACK_STATE_VALUES)
export const DebugStateSchema = z.enum(DEBUG_STATE_VALUES)
export const UnpackSafetyLevelSchema = z.enum(UNPACK_SAFETY_LEVEL_VALUES)

export const UnpackBackendRecommendationSchema = z.object({
  backend: z.string(),
  tool: z.string(),
  role: z.string(),
  ready: z.boolean(),
  approval_required: z.boolean(),
  reason: z.string(),
})

export const UnpackPlanSchema = z.object({
  plan_id: z.string(),
  sample_id: z.string(),
  packed_state: PackedStateSchema,
  unpack_state: UnpackStateSchema,
  unpack_confidence: z.number().min(0).max(1),
  safety_level: UnpackSafetyLevelSchema,
  strategy: z.enum(['none_needed', 'upx_decompress', 'guided_memory_dump', 'manual_debug_rebuild']),
  next_safe_step: z.enum(['none_needed', 'preview_only', 'dump_oriented', 'rebuild_oriented', 'approval_gated']),
  evidence: z.array(z.string()),
  proposed_backends: z.array(UnpackBackendRecommendationSchema),
  expected_artifacts: z.array(z.string()),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  session_tag: z.string().nullable().optional(),
  artifact_refs: z.array(z.any()).optional(),
})

export const UnpackExecutionSchema = z.object({
  execution_id: z.string(),
  sample_id: z.string(),
  packed_state: PackedStateSchema,
  unpack_state: UnpackStateSchema,
  unpack_confidence: z.number().min(0).max(1),
  selected_backend: z.string(),
  safe_execution_mode: z.string(),
  approval_required: z.boolean(),
  resumable: z.boolean(),
  summary: z.string(),
  unpacked_sample_id: z.string().nullable().optional(),
  unpacked_artifact: z.any().nullable().optional(),
  oep: z.string().nullable().optional(),
  import_rebuild: z
    .object({
      status: z.enum(['not_needed', 'suggested', 'required', 'partial']),
      notes: z.array(z.string()),
    })
    .optional(),
  failure_reason: z.string().nullable().optional(),
  derived_artifacts: z.array(z.any()),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const DebugSessionGuidanceSchema = z.object({
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  withheld_reasons: z.array(z.string()).optional(),
})

export const DebugSessionRecordSchema = z.object({
  session_id: z.string(),
  run_id: z.string().nullable(),
  sample_id: z.string(),
  sample_sha256: z.string(),
  status: z.enum(['planned', 'armed', 'capturing', 'captured', 'correlated', 'interrupted', 'approval_gated']),
  debug_state: DebugStateSchema,
  backend: z.string().nullable(),
  current_phase: z.string().nullable(),
  session_tag: z.string().nullable(),
  artifact_refs: z.array(z.any()),
  guidance: DebugSessionGuidanceSchema,
  metadata: z.record(z.any()).optional(),
  created_at: z.string(),
  updated_at: z.string(),
  finished_at: z.string().nullable().optional(),
})

export const AnalysisDiffDigestSchema = z.object({
  diff_id: z.string(),
  diff_type: z.enum(['packed_vs_unpacked', 'pre_vs_post_dynamic', 'pre_vs_post_trace']),
  sample_id: z.string(),
  title: z.string(),
  summary: z.string(),
  bounded: z.boolean(),
  findings: z.array(z.string()),
  before_ref: z.any().nullable().optional(),
  after_ref: z.any().nullable().optional(),
  source_artifact_refs: z.array(z.any()),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export interface UnpackPlanBuildInput {
  sample: Pick<Sample, 'id' | 'sha256'>
  allowTransformations?: boolean
  allowLiveExecution?: boolean
  packerDetected?: boolean
  packerConfidence?: number
  packerNames?: string[]
  compilerPackerNames?: string[]
  upxValidationPassed?: boolean
  upxReady?: boolean
  rizinReady?: boolean
}

export interface UnpackDebugArtifactSelectionOptions {
  scope?: UnpackDebugArtifactScope
  sessionTag?: string
}

export interface UnpackDebugArtifactSelection<TPayload = unknown> {
  artifacts: Array<{
    artifact: ArtifactRef
    created_at: string
    session_tags: string[]
    payload: TPayload
  }>
  latest_payload: TPayload | null
  latest_artifact: ArtifactRef | null
  artifact_refs: ArtifactRef[]
  session_tags: string[]
  earliest_created_at: string | null
  latest_created_at: string | null
  scope_note: string
}

const LATEST_ARTIFACT_WINDOW_MS = 10 * 1000

function sanitizePathSegment(value: string | undefined, fallback: string): string {
  const normalized = (value || fallback)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return normalized.length > 0 ? normalized.slice(0, 64) : fallback
}

function matchesSessionTag(sessionTags: string[], selector?: string | null): boolean {
  if (!selector || !selector.trim()) {
    return false
  }
  const normalized = selector.trim()
  return sessionTags.some((tag) => tag === normalized)
}

function artifactRootSegment(artifactType: UnpackDebugArtifactType): string {
  switch (artifactType) {
    case UNPACK_PLAN_ARTIFACT_TYPE:
      return 'unpack_plan'
    case UNPACK_EXECUTION_ARTIFACT_TYPE:
      return 'unpack_execution'
    case ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE:
      return 'analysis_diff'
    case DEBUG_SESSION_ARTIFACT_TYPE:
      return 'debug_session'
  }
}

export async function persistUnpackDebugJsonArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  artifactType: UnpackDebugArtifactType,
  filePrefix: string,
  payload: unknown,
  sessionTag?: string | null
): Promise<ArtifactRef> {
  const workspace = await workspaceManager.createWorkspace(sampleId)
  const sessionSegment = sanitizePathSegment(sessionTag || undefined, 'default')
  const reportDir = path.join(workspace.reports, artifactRootSegment(artifactType), sessionSegment)
  await fs.mkdir(reportDir, { recursive: true })

  const fileName = `${filePrefix}_${Date.now()}.json`
  const absolutePath = path.join(reportDir, fileName)
  const serialized = JSON.stringify(payload, null, 2)
  await fs.writeFile(absolutePath, serialized, 'utf8')

  const artifactId = randomUUID()
  const artifactSha256 = createHash('sha256').update(serialized).digest('hex')
  const relativePath = path.relative(workspace.root, absolutePath).replace(/\\/g, '/')
  const createdAt = new Date().toISOString()

  database.insertArtifact({
    id: artifactId,
    sample_id: sampleId,
    type: artifactType,
    path: relativePath,
    sha256: artifactSha256,
    mime: 'application/json',
    created_at: createdAt,
  })

  return {
    id: artifactId,
    type: artifactType,
    path: relativePath,
    sha256: artifactSha256,
    mime: 'application/json',
    metadata: {
      session_tag: sessionTag || null,
      artifact_family: artifactRootSegment(artifactType),
    },
  }
}

export async function loadUnpackDebugArtifactSelection<TPayload>(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  artifactType: UnpackDebugArtifactType,
  options: UnpackDebugArtifactSelectionOptions = {}
): Promise<UnpackDebugArtifactSelection<TPayload>> {
  const scope = options.scope || 'latest'
  const sessionTag = options.sessionTag?.trim() || null
  const artifacts = database.findArtifactsByType(sampleId, artifactType)

  if (artifacts.length === 0) {
    return {
      artifacts: [],
      latest_payload: null,
      latest_artifact: null,
      artifact_refs: [],
      session_tags: [],
      earliest_created_at: null,
      latest_created_at: null,
      scope_note:
        scope === 'session' && sessionTag
          ? `No ${artifactType} artifacts matched session selector "${sessionTag}".`
          : scope === 'latest'
            ? `No ${artifactType} artifacts matched the latest selection window.`
            : `No ${artifactType} artifacts were selected.`,
    }
  }

  const workspace = await workspaceManager.getWorkspace(sampleId)
  const loaded: Array<{
    artifact: ArtifactRef
    created_at: string
    session_tags: string[]
    payload: TPayload
  }> = []

  for (const artifact of artifacts) {
    try {
      const absolutePath = workspaceManager.normalizePath(workspace.root, artifact.path)
      const content = await fs.readFile(absolutePath, 'utf8')
      const payload = JSON.parse(content) as TPayload
      const sessionTags = Array.from(
        new Set(
          [
            deriveArtifactSessionTag(artifact.path),
            typeof (payload as { session_tag?: unknown })?.session_tag === 'string'
              ? String((payload as { session_tag?: string }).session_tag).trim()
              : null,
          ].filter((item): item is string => Boolean(item && item.trim()))
        )
      )
      loaded.push({
        artifact: {
          id: artifact.id,
          type: artifact.type,
          path: artifact.path,
          sha256: artifact.sha256,
          mime: artifact.mime || undefined,
        },
        created_at: artifact.created_at,
        session_tags: sessionTags,
        payload,
      })
    } catch {
      continue
    }
  }

  let selected = loaded
  if (scope === 'session' && sessionTag) {
    selected = loaded.filter((item) => matchesSessionTag(item.session_tags, sessionTag))
  } else if (scope === 'latest' && loaded.length > 0) {
    const latestCreated = new Date(loaded[0].created_at).getTime()
    selected = loaded.filter(
      (item) => latestCreated - new Date(item.created_at).getTime() <= LATEST_ARTIFACT_WINDOW_MS
    )
  }

  const artifactRefs = selected.map((item) => item.artifact)
  const sessionTags = Array.from(new Set(selected.flatMap((item) => item.session_tags)))
  const createdAtValues = selected.map((item) => item.created_at).filter((item) => item.length > 0)
  const latestCreatedAt = createdAtValues.length > 0 ? createdAtValues[0] : null
  const earliestCreatedAt =
    createdAtValues.length > 0 ? createdAtValues[createdAtValues.length - 1] : null
  const scopeNote =
    selected.length > 0
      ? `Selected ${selected.length} ${artifactType} artifact(s) using scope=${scope}${sessionTag ? ` selector=${sessionTag}` : ''}.`
      : scope === 'session' && sessionTag
        ? `No ${artifactType} artifacts matched session selector "${sessionTag}".`
        : scope === 'latest'
          ? `No ${artifactType} artifacts matched the latest selection window.`
          : `No ${artifactType} artifacts were selected.`

  return {
    artifacts: selected,
    latest_payload: selected.length > 0 ? selected[0].payload : null,
    latest_artifact: selected.length > 0 ? selected[0].artifact : null,
    artifact_refs: artifactRefs,
    session_tags: sessionTags,
    earliest_created_at: earliestCreatedAt,
    latest_created_at: latestCreatedAt,
    scope_note: scopeNote,
  }
}

function includesUpx(values: string[] = []): boolean {
  return values.some((value) => /(^|\b)upx(\b|$)/i.test(value))
}

export function buildUnpackPlan(input: UnpackPlanBuildInput) {
  const packerNames = Array.from(new Set([...(input.packerNames || []), ...(input.compilerPackerNames || [])]))
  const packedConfidence = Math.max(
    0,
    Math.min(
      1,
      input.upxValidationPassed
        ? 0.94
        : input.packerDetected
          ? input.packerConfidence ?? 0.72
          : packerNames.length > 0
            ? 0.64
            : 0.16
    )
  )
  const packedState =
    input.upxValidationPassed || ((input.packerDetected || false) && packedConfidence >= 0.8)
      ? 'confirmed_packed'
      : input.packerDetected || packerNames.length > 0
        ? 'suspected_packed'
        : 'not_packed'

  const upxCandidate = includesUpx(packerNames) || Boolean(input.upxValidationPassed)
  const strategy =
    packedState === 'not_packed'
      ? 'none_needed'
      : upxCandidate
        ? 'upx_decompress'
        : input.allowLiveExecution
          ? 'guided_memory_dump'
          : 'manual_debug_rebuild'
  const safetyLevel =
    packedState === 'not_packed'
      ? 'preview_only'
      : upxCandidate && input.allowTransformations
        ? 'dump_oriented'
        : upxCandidate
          ? 'preview_only'
          : input.allowLiveExecution
            ? 'rebuild_oriented'
            : 'approval_gated'
  const nextSafeStep =
    packedState === 'not_packed'
      ? 'none_needed'
      : upxCandidate && input.allowTransformations
        ? 'dump_oriented'
        : upxCandidate
          ? 'preview_only'
          : input.allowLiveExecution
            ? 'rebuild_oriented'
            : 'approval_gated'

  const evidence = [
    packedState !== 'not_packed'
      ? `Packing indicators observed: ${packerNames.slice(0, 4).join(', ') || 'heuristic packer signals'}.`
      : 'No strong packing indicators were observed in the fast profile.',
    input.upxValidationPassed ? 'UPX validation succeeded on the original sample.' : null,
    input.rizinReady ? 'Rizin preview is available for bounded structural corroboration.' : null,
  ].filter((item): item is string => Boolean(item))

  const proposedBackends = [
    {
      backend: 'upx',
      tool: 'upx.inspect',
      role: 'safe_unpack_probe',
      ready: Boolean(input.upxReady),
      approval_required: false,
      reason: upxCandidate
        ? 'UPX markers justify bounded test or decompress operations first.'
        : 'UPX is only relevant when explicit UPX-style packing indicators are present.',
    },
    {
      backend: 'rizin',
      tool: 'rizin.analyze',
      role: 'preview_structure_probe',
      ready: Boolean(input.rizinReady),
      approval_required: false,
      reason: 'Rizin remains the cheap preview backend for section and import corroboration before deeper unpack or debug work.',
    },
    {
      backend: 'sandbox',
      tool: 'sandbox.execute',
      role: 'safe_dump_or_trace_preparation',
      ready: true,
      approval_required: false,
      reason: 'Safe simulation and memory-guided dynamic helpers can collect bounded runtime clues before live debugging.',
    },
    {
      backend: 'wine',
      tool: 'wine.run',
      role: 'approval_gated_live_debug',
      ready: true,
      approval_required: true,
      reason: 'Live execution and invasive debugging stay manual-only for packed samples.',
    },
  ]

  return UnpackPlanSchema.parse({
    plan_id: randomUUID(),
    sample_id: input.sample.id,
    packed_state: packedState,
    unpack_state: packedState === 'not_packed' ? 'not_applicable' : 'unpack_planned',
    unpack_confidence: packedConfidence,
    safety_level: safetyLevel,
    strategy,
    next_safe_step: nextSafeStep,
    evidence,
    proposed_backends: proposedBackends,
    expected_artifacts:
      packedState === 'not_packed'
        ? ['fast_profile_artifacts']
        : upxCandidate
          ? ['unpacked_binary', 'unpack_execution_digest', 'packed_vs_unpacked_diff']
          : ['debug_session_plan', 'runtime_dump_or_trace_digest', 'recoverable_unpack_execution'],
    recommended_next_tools:
      packedState === 'not_packed'
        ? ['workflow.analyze.promote', 'workflow.summarize']
        : ['workflow.analyze.promote', 'workflow.analyze.status', 'upx.inspect'],
    next_actions:
      packedState === 'not_packed'
        ? ['Continue into enrich_static or function_map; no unpack branch is required right now.']
        : upxCandidate && input.allowTransformations
          ? [
              'Promote to dynamic_execute to allow a safe UPX-backed unpack attempt and persist the unpacked binary.',
              'Use workflow.analyze.status instead of repeating fast-profile analysis while unpack work is in progress.',
            ]
          : upxCandidate
            ? [
                'Preview-only unpack planning is ready. Re-run or promote with allow_transformations enabled when you want a safe decompress attempt.',
              ]
            : [
                'Keep the sample on preview-only analysis until you explicitly choose an approval-gated debug backend or manual unpack path.',
              ],
  })
}

export function createDebugSessionRecord(input: {
  runId?: string | null
  sample: Pick<Sample, 'id' | 'sha256'>
  status: z.infer<typeof DebugSessionRecordSchema.shape.status>
  debugState: z.infer<typeof DebugStateSchema>
  backend?: string | null
  currentPhase?: string | null
  sessionTag?: string | null
  artifactRefs?: ArtifactRef[]
  guidance: z.infer<typeof DebugSessionGuidanceSchema>
  metadata?: Record<string, unknown>
}): z.infer<typeof DebugSessionRecordSchema> {
  const now = new Date().toISOString()
  return DebugSessionRecordSchema.parse({
    session_id: randomUUID(),
    run_id: input.runId ?? null,
    sample_id: input.sample.id,
    sample_sha256: input.sample.sha256,
    status: input.status,
    debug_state: input.debugState,
    backend: input.backend ?? null,
    current_phase: input.currentPhase ?? null,
    session_tag: input.sessionTag ?? null,
    artifact_refs: input.artifactRefs || [],
    guidance: input.guidance,
    metadata: input.metadata || {},
    created_at: now,
    updated_at: now,
    finished_at:
      input.status === 'captured' || input.status === 'correlated' ? now : null,
  })
}

export function toDatabaseDebugSession(session: z.infer<typeof DebugSessionRecordSchema>): DebugSession {
  return {
    id: session.session_id,
    run_id: session.run_id,
    sample_id: session.sample_id,
    sample_sha256: session.sample_sha256,
    status: session.status,
    debug_state: session.debug_state,
    backend: session.backend,
    current_phase: session.current_phase,
    session_tag: session.session_tag,
    artifact_refs_json: JSON.stringify(session.artifact_refs || []),
    guidance_json: JSON.stringify(session.guidance),
    metadata_json: JSON.stringify(session.metadata || {}),
    created_at: session.created_at,
    updated_at: session.updated_at,
    finished_at: session.finished_at || null,
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

export function parseDatabaseDebugSession(session: DebugSession): z.infer<typeof DebugSessionRecordSchema> {
  return DebugSessionRecordSchema.parse({
    session_id: session.id,
    run_id: session.run_id,
    sample_id: session.sample_id,
    sample_sha256: session.sample_sha256,
    status: session.status,
    debug_state: session.debug_state,
    backend: session.backend,
    current_phase: session.current_phase,
    session_tag: session.session_tag,
    artifact_refs: parseJsonValue<ArtifactRef[]>(session.artifact_refs_json, []),
    guidance: parseJsonValue<z.infer<typeof DebugSessionGuidanceSchema>>(session.guidance_json, {
      recommended_next_tools: [],
      next_actions: [],
    }),
    metadata: parseJsonValue<Record<string, unknown>>(session.metadata_json, {}),
    created_at: session.created_at,
    updated_at: session.updated_at,
    finished_at: session.finished_at,
  })
}

export function buildPackedVsUnpackedDiffDigest(input: {
  sampleId: string
  beforeRef?: ArtifactRef | null
  afterRef?: ArtifactRef | null
  sizeBefore?: number | null
  sizeAfter?: number | null
  importsBefore?: string[]
  importsAfter?: string[]
  stringsBefore?: string[]
  stringsAfter?: string[]
  sectionCountBefore?: number | null
  sectionCountAfter?: number | null
  sourceArtifactRefs?: ArtifactRef[]
}): z.infer<typeof AnalysisDiffDigestSchema> {
  const beforeImports = new Set(input.importsBefore || [])
  const afterImports = new Set(input.importsAfter || [])
  const beforeStrings = new Set(input.stringsBefore || [])
  const afterStrings = new Set(input.stringsAfter || [])
  const newImports = Array.from(afterImports).filter((item) => !beforeImports.has(item)).slice(0, 8)
  const newStrings = Array.from(afterStrings).filter((item) => !beforeStrings.has(item)).slice(0, 8)
  const findings = [
    input.sizeBefore != null && input.sizeAfter != null
      ? `File size changed from ${input.sizeBefore} bytes to ${input.sizeAfter} bytes.`
      : null,
    input.sectionCountBefore != null && input.sectionCountAfter != null
      ? `Section count changed from ${input.sectionCountBefore} to ${input.sectionCountAfter}.`
      : null,
    newImports.length > 0 ? `New imports became visible after unpacking: ${newImports.join(', ')}.` : null,
    newStrings.length > 0 ? `New preview strings became visible after unpacking.` : null,
  ].filter((item): item is string => Boolean(item))
  return AnalysisDiffDigestSchema.parse({
    diff_id: randomUUID(),
    diff_type: 'packed_vs_unpacked',
    sample_id: input.sampleId,
    title: 'Packed versus unpacked diff digest',
    summary:
      findings[0] ||
      'Packed-versus-unpacked comparison completed; inspect linked artifacts for the bounded structural delta.',
    bounded: true,
    findings,
    before_ref: input.beforeRef || null,
    after_ref: input.afterRef || null,
    source_artifact_refs: input.sourceArtifactRefs || [],
    recommended_next_tools: ['workflow.analyze.start', 'workflow.analyze.promote', 'artifact.read'],
    next_actions: [
      'Use the unpacked sample_id or artifact as the preferred input for deeper function_map and reconstruct stages.',
      'Read the persisted diff artifact for bounded before/after context instead of reopening raw dumps inline.',
    ],
  })
}

export function buildDynamicBehaviorDiffDigest(input: {
  sampleId: string
  diffType: 'pre_vs_post_dynamic' | 'pre_vs_post_trace'
  beforeSummary?: {
    observed_apis?: string[]
    stages?: string[]
    risk_hints?: string[]
  } | null
  afterSummary?: {
    observed_apis?: string[]
    stages?: string[]
    risk_hints?: string[]
    summary?: string
  } | null
  sourceArtifactRefs?: ArtifactRef[]
}): z.infer<typeof AnalysisDiffDigestSchema> {
  const beforeApis = new Set(input.beforeSummary?.observed_apis || [])
  const afterApis = new Set(input.afterSummary?.observed_apis || [])
  const beforeStages = new Set(input.beforeSummary?.stages || [])
  const afterStages = new Set(input.afterSummary?.stages || [])
  const newApis = Array.from(afterApis).filter((item) => !beforeApis.has(item)).slice(0, 10)
  const newStages = Array.from(afterStages).filter((item) => !beforeStages.has(item)).slice(0, 8)
  const newHints = (input.afterSummary?.risk_hints || [])
    .filter((item) => !(input.beforeSummary?.risk_hints || []).includes(item))
    .slice(0, 6)
  const findings = [
    newApis.length > 0 ? `New runtime-observed APIs: ${newApis.join(', ')}.` : null,
    newStages.length > 0 ? `New runtime stages became visible: ${newStages.join(', ')}.` : null,
    newHints.length > 0 ? `New runtime risk hints: ${newHints.join(' | ')}.` : null,
  ].filter((item): item is string => Boolean(item))
  return AnalysisDiffDigestSchema.parse({
    diff_id: randomUUID(),
    diff_type: input.diffType,
    sample_id: input.sampleId,
    title:
      input.diffType === 'pre_vs_post_trace'
        ? 'Pre/post trace diff digest'
        : 'Pre/post dynamic diff digest',
    summary:
      findings[0] ||
      input.afterSummary?.summary ||
      'Dynamic behavior diff completed; inspect linked trace artifacts for bounded follow-up detail.',
    bounded: true,
    findings,
    before_ref: null,
    after_ref: null,
    source_artifact_refs: input.sourceArtifactRefs || [],
    recommended_next_tools: ['workflow.summarize', 'report.summarize', 'artifact.read'],
    next_actions: [
      'Use the persisted diff digest as the summary input for dynamic behavior changes.',
      'Inspect linked trace or session artifacts only when the bounded digest is insufficient.',
    ],
  })
}
