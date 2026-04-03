import fs from 'fs'
import path from 'path'
import { randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolArgs, ToolDefinition, ToolResult, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { AnalysisRun, DatabaseManager, Sample } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { JobQueue, JobResult } from '../job-queue.js'
import { JobPriority } from '../job-queue.js'
import type { PolicyGuard } from '../policy-guard.js'
import type { MCPServer } from '../server.js'
import {
  AnalysisIntentDepthSchema,
  AnalysisIntentGoalSchema,
  BackendPolicySchema,
  BackendRoutingMetadataSchema,
  buildIntentBackendPlan,
  mergeRoutingMetadata,
} from '../intent-routing.js'
import {
  CoverageEnvelopeSchema,
  buildCoverageEnvelope,
  buildBudgetDowngradeReasons,
  classifySampleSizeTier,
  deriveAnalysisBudgetProfile,
  mergeCoverageEnvelope,
} from '../analysis-coverage.js'
import {
  AnalysisPipelineStageSchema,
  AnalysisRunSummarySchema,
  RecoverableStageSchema,
  appendAnalysisRunArtifactRefs,
  buildStagePlan,
  createOrReuseAnalysisRun,
  getAnalysisRunSummary,
  upsertAnalysisRunStage,
  type AnalysisPipelineStage,
} from '../analysis-run-state.js'
import {
  ExplanationGraphDigestSchema,
  buildRuntimeStageExplanationGraph,
} from '../explanation-graphs.js'
import { buildSchedulerExecutionPlan } from '../analysis-budget-scheduler.js'
import { resolveAnalysisBackends } from '../static-backend-discovery.js'
import { AnalysisEvidenceStateSchema } from '../analysis-evidence.js'
import { createPEFingerprintHandler } from '../plugins/pe-analysis/tools/pe-fingerprint.js'
import { createRuntimeDetectHandler } from '../tools/runtime-detect.js'
import { createPEImportsExtractHandler } from '../plugins/pe-analysis/tools/pe-imports-extract.js'
import { createStringsExtractHandler } from '../tools/strings-extract.js'
import { createStringsFlossDecodeHandler } from '../tools/strings-floss-decode.js'
import { createYaraScanHandler } from '../tools/yara-scan.js'
import { createPackerDetectHandler } from '../tools/packer-detect.js'
import { createCompilerPackerDetectHandler } from '../tools/compiler-packer-detect.js'
import { createBinaryRoleProfileHandler } from '../tools/binary-role-profile.js'
import { createStaticCapabilityTriageHandler } from '../tools/static-capability-triage.js'
import { createPEStructureAnalyzeHandler } from '../plugins/pe-analysis/tools/pe-structure-analyze.js'
import { createElfStructureAnalyzeHandler } from '../tools/elf-structure-analyze.js'
import { createMachoStructureAnalyzeHandler } from '../tools/macho-structure-analyze.js'
import { createAnalysisContextLinkHandler } from '../tools/analysis-context-link.js'
import { createCryptoIdentifyHandler } from '../tools/crypto-identify.js'
import { createRustBinaryAnalyzeHandler } from '../tools/rust-binary-analyze.js'
import { createDynamicDependenciesHandler } from '../tools/dynamic-dependencies.js'
import { createBreakpointSmartHandler } from '../tools/breakpoint-smart.js'
import { createTraceConditionHandler } from '../tools/trace-condition.js'
import { createSandboxExecuteHandler } from '../tools/sandbox-execute.js'
import { createWorkflowSummarizeHandler } from './summarize.js'
import { createReconstructWorkflowHandler } from './reconstruct.js'
import { createGhidraAnalyzeHandler } from '../plugins/ghidra/tools/ghidra-analyze.js'
import {
  createAngrAnalyzeHandler,
  createPandaInspectHandler,
  createQilingInspectHandler,
  createRetDecDecompileHandler,
  createRizinAnalyzeHandler,
  createUPXInspectHandler,
  createYaraXScanHandler,
} from '../tools/docker-backend-tools.js'
import { buildPollingGuidance } from '../polling-guidance.js'
import { loadDynamicTraceEvidence } from '../dynamic-trace.js'
import { createSampleFinalizationService } from '../sample-finalization.js'
import { persistCanonicalEvidence } from '../analysis-evidence.js'
import {
  ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE,
  AnalysisDiffDigestSchema,
  buildDynamicBehaviorDiffDigest,
  buildPackedVsUnpackedDiffDigest,
  buildUnpackPlan,
  createDebugSessionRecord,
  DEBUG_SESSION_ARTIFACT_TYPE,
  DebugSessionGuidanceSchema,
  DebugSessionRecordSchema,
  DebugStateSchema,
  loadUnpackDebugArtifactSelection,
  PackedStateSchema,
  parseDatabaseDebugSession,
  persistUnpackDebugJsonArtifact,
  toDatabaseDebugSession,
  UNPACK_EXECUTION_ARTIFACT_TYPE,
  UNPACK_PLAN_ARTIFACT_TYPE,
  UnpackExecutionSchema,
  UnpackPlanSchema,
  UnpackStateSchema,
} from '../unpack-debug-runtime.js'

const TOOL_NAME_START = 'workflow.analyze.start'
const TOOL_NAME_STATUS = 'workflow.analyze.status'
const TOOL_NAME_PROMOTE = 'workflow.analyze.promote'
export const ANALYSIS_STAGE_JOB_TOOL = 'workflow.analyze.stage'

const FAST_PROFILE_STAGE = 'fast_profile'
const FAST_PROFILE_TIMEOUT_MS = 90_000
const ENRICH_STAGE_TIMEOUT_MS = 10 * 60 * 1000
const FUNCTION_MAP_TIMEOUT_MS = 20 * 60 * 1000
const RECONSTRUCT_TIMEOUT_MS = 30 * 60 * 1000
const DYNAMIC_PLAN_TIMEOUT_MS = 5 * 60 * 1000
const SUMMARIZE_TIMEOUT_MS = 5 * 60 * 1000
const YARA_DEFAULT_RULE_SET = 'malware_families'

const suspiciousImportNames = [
  'createremotethread',
  'virtualallocex',
  'writeprocessmemory',
  'getprocaddress',
  'winexec',
  'shellexecute',
  'cryptencrypt',
  'cryptdecrypt',
  'internetopen',
  'internetconnect',
  'httpsendrequest',
]

const suspiciousStringPatterns = [
  /powershell/i,
  /cmd\.exe/i,
  /https?:\/\//i,
  /regsvr32/i,
  /schtasks/i,
  /services\\/i,
  /currentcontrolset\\/i,
  /mutex/i,
  /aes/i,
  /rc4/i,
]

const analyzeStartInputSchema = z.object({
  sample_id: z.string(),
  goal: AnalysisIntentGoalSchema.default('triage'),
  depth: AnalysisIntentDepthSchema.default('balanced'),
  backend_policy: BackendPolicySchema.default('auto'),
  allow_transformations: z.boolean().default(false),
  allow_live_execution: z.boolean().default(false),
  force_refresh: z.boolean().default(false),
})

const analyzeStatusInputSchema = z.object({
  run_id: z.string(),
})

const analyzePromoteInputSchema = z.object({
  run_id: z.string(),
  stages: z.array(AnalysisPipelineStageSchema).optional(),
  through_stage: AnalysisPipelineStageSchema.optional(),
  force_refresh: z.boolean().default(false),
})

const DeferredJobArraySchema = z.array(
  z.object({
    stage: AnalysisPipelineStageSchema,
    job_id: z.string(),
    status: z.string(),
    progress: z.number().optional(),
    tool: z.string().nullable().optional(),
    execution_bucket: z.string().nullable().optional(),
    cost_class: z.string().nullable().optional(),
    worker_family: z.string().nullable().optional(),
    budget_deferral_reason: z.string().nullable().optional(),
    warm_reuse: z.boolean().optional(),
    cold_start: z.boolean().optional(),
  })
)

const ProvenanceVisibilitySchema = z.object({
  evidence_counts: z.object({
    fresh: z.number().int().nonnegative(),
    reused: z.number().int().nonnegative(),
    partial: z.number().int().nonnegative(),
    stale: z.number().int().nonnegative(),
    incompatible: z.number().int().nonnegative(),
    missing: z.number().int().nonnegative(),
    deferred: z.number().int().nonnegative(),
  }),
  reused_stage_count: z.number().int().nonnegative(),
  recoverable_stage_count: z.number().int().nonnegative(),
  deferred_stage_count: z.number().int().nonnegative(),
  omitted_backend_reasons: z.array(z.string()),
  deferred_domains: z.array(z.string()),
})

const UnpackDebugEnvelopeSchema = z.object({
  packed_state: PackedStateSchema.optional(),
  unpack_state: UnpackStateSchema.optional(),
  unpack_confidence: z.number().min(0).max(1).optional(),
  unpack_plan: UnpackPlanSchema.optional(),
  unpack_execution: UnpackExecutionSchema.optional(),
  debug_state: DebugStateSchema.optional(),
  debug_session: DebugSessionRecordSchema.optional(),
  diff_digests: z.array(AnalysisDiffDigestSchema).optional(),
})

const runEnvelopeSchema = z.object({
  run_id: z.string(),
  reused: z.boolean(),
  execution_state: z.enum(['inline', 'queued', 'reused', 'partial', 'completed']),
  current_stage: AnalysisPipelineStageSchema,
  run: AnalysisRunSummarySchema,
  recovery_state: z.enum(['none', 'interrupted', 'recoverable']).optional(),
  recoverable_stages: z.array(RecoverableStageSchema).optional(),
  stage_result: z.any().optional(),
  evidence_state: z.array(AnalysisEvidenceStateSchema).optional(),
  provenance_visibility: ProvenanceVisibilitySchema.optional(),
  runtime_explanation_graph: ExplanationGraphDigestSchema.optional(),
  deferred_jobs: DeferredJobArraySchema,
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
}).merge(UnpackDebugEnvelopeSchema)

export const analyzeWorkflowStartOutputSchema = z.object({
  ok: z.boolean(),
  data: runEnvelopeSchema
    .extend(CoverageEnvelopeSchema.shape)
    .extend(BackendRoutingMetadataSchema.shape)
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({
    elapsed_ms: z.number(),
    tool: z.string(),
  }).optional(),
})

export const analyzeWorkflowStatusOutputSchema = analyzeWorkflowStartOutputSchema
export const analyzeWorkflowPromoteOutputSchema = analyzeWorkflowStartOutputSchema

export const analyzeWorkflowStartToolDefinition: ToolDefinition = {
  name: TOOL_NAME_START,
  description:
    'Start or reuse a persisted nonblocking staged analysis run. Only the fast preview profile executes inline; heavier stages are promoted later. Use this directly for medium/large samples or whenever you expect queued work instead of one-shot synchronous analysis.',
  inputSchema: analyzeStartInputSchema,
  outputSchema: analyzeWorkflowStartOutputSchema,
}

export const analyzeWorkflowStatusToolDefinition: ToolDefinition = {
  name: TOOL_NAME_STATUS,
  description:
    'Read aggregate status for a persisted staged analysis run, including deferred jobs, completed stages, and reusable artifact refs. This is the primary follow-up for medium/large samples after workflow.analyze.start or workflow.analyze.promote.',
  inputSchema: analyzeStatusInputSchema,
  outputSchema: analyzeWorkflowStatusOutputSchema,
}

export const analyzeWorkflowPromoteToolDefinition: ToolDefinition = {
  name: TOOL_NAME_PROMOTE,
  description:
    'Promote a persisted staged analysis run to one or more deeper stages without rerunning the existing preview profile. Use this after inspecting workflow.analyze.status when you need enrich_static, function_map, reconstruct, or summarize boundaries.',
  inputSchema: analyzePromoteInputSchema,
  outputSchema: analyzeWorkflowPromoteOutputSchema,
}

export interface AnalyzePipelineDependencies {
  peFingerprint?: (args: ToolArgs) => Promise<WorkerResult>
  runtimeDetect?: (args: ToolArgs) => Promise<WorkerResult>
  peImportsExtract?: (args: ToolArgs) => Promise<WorkerResult>
  stringsExtract?: (args: ToolArgs) => Promise<WorkerResult>
  stringsFlossDecode?: (args: ToolArgs) => Promise<WorkerResult>
  yaraScan?: (args: ToolArgs) => Promise<WorkerResult>
  packerDetect?: (args: ToolArgs) => Promise<WorkerResult>
  compilerPackerDetect?: (args: ToolArgs) => Promise<WorkerResult>
  binaryRoleProfile?: (args: ToolArgs) => Promise<WorkerResult>
  staticCapabilityTriage?: (args: ToolArgs) => Promise<WorkerResult>
  peStructureAnalyze?: (args: ToolArgs) => Promise<WorkerResult>
  elfStructureAnalyze?: (args: ToolArgs) => Promise<WorkerResult>
  machoStructureAnalyze?: (args: ToolArgs) => Promise<WorkerResult>
  analysisContextLink?: (args: ToolArgs) => Promise<WorkerResult>
  cryptoIdentify?: (args: ToolArgs) => Promise<WorkerResult>
  rustBinaryAnalyze?: (args: ToolArgs) => Promise<WorkerResult>
  dynamicDependencies?: (args: ToolArgs) => Promise<WorkerResult>
  breakpointSmart?: (args: ToolArgs) => Promise<WorkerResult>
  traceCondition?: (args: ToolArgs) => Promise<WorkerResult>
  sandboxExecute?: (args: ToolArgs) => Promise<WorkerResult>
  workflowSummarize?: (args: ToolArgs) => Promise<WorkerResult>
  reconstructWorkflow?: (args: ToolArgs) => Promise<WorkerResult>
  ghidraAnalyze?: (args: ToolArgs) => Promise<ToolResult | WorkerResult>
  rizinAnalyze?: (args: ToolArgs) => Promise<WorkerResult>
  yaraXScan?: (args: ToolArgs) => Promise<WorkerResult>
  upxInspect?: (args: ToolArgs) => Promise<WorkerResult>
  qilingInspect?: (args: ToolArgs) => Promise<WorkerResult>
  pandaInspect?: (args: ToolArgs) => Promise<WorkerResult>
  angrAnalyze?: (args: ToolArgs) => Promise<WorkerResult>
  retdecDecompile?: (args: ToolArgs) => Promise<WorkerResult>
  resolveBackends?: typeof resolveAnalysisBackends
}

interface StageExecutionContext {
  workspaceManager: WorkspaceManager
  database: DatabaseManager
  cacheManager: CacheManager
  policyGuard: PolicyGuard
  server?: MCPServer
  dependencies: AnalyzePipelineDependencies
}

function dedupeStrings(values: Array<string | null | undefined>, limit = 12): string[] {
  return Array.from(
    new Set(
      values.filter((value): value is string => Boolean(value && value.trim().length > 0))
    )
  ).slice(0, limit)
}

function collectArtifactsFromResult(result: WorkerResult | undefined): ArtifactRef[] {
  if (!result) {
    return []
  }
  const refs: ArtifactRef[] = []
  if (Array.isArray(result.artifacts)) {
    refs.push(...(result.artifacts.filter((item) => item && typeof item === 'object') as ArtifactRef[]))
  }
  const data = result.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  if (Array.isArray(data.artifact_refs)) {
    refs.push(...(data.artifact_refs.filter((item) => item && typeof item === 'object') as ArtifactRef[]))
  }
  if (data.artifact && typeof data.artifact === 'object') {
    refs.push(data.artifact as ArtifactRef)
  }
  return refs
}

function collectEvidenceStatesFromPayload(
  payload: unknown,
  output: z.infer<typeof AnalysisEvidenceStateSchema>[] = [],
  seen = new Set<unknown>()
): z.infer<typeof AnalysisEvidenceStateSchema>[] {
  if (!payload || typeof payload !== 'object') {
    return output
  }
  if (seen.has(payload)) {
    return output
  }
  seen.add(payload)

  if (Array.isArray(payload)) {
    for (const item of payload) {
      collectEvidenceStatesFromPayload(item, output, seen)
    }
    return output
  }

  const record = payload as Record<string, unknown>
  if (Array.isArray(record.evidence_state)) {
    for (const candidate of record.evidence_state) {
      const parsed = AnalysisEvidenceStateSchema.safeParse(candidate)
      if (parsed.success) {
        output.push(parsed.data)
      }
    }
  }

  for (const value of Object.values(record)) {
    if (value && typeof value === 'object') {
      collectEvidenceStatesFromPayload(value, output, seen)
    }
  }

  return output
}

function uniqueEvidenceStates(states: z.infer<typeof AnalysisEvidenceStateSchema>[]) {
  const seen = new Set<string>()
  const output: z.infer<typeof AnalysisEvidenceStateSchema>[] = []
  for (const state of states) {
    const key = [
      state.evidence_family,
      state.backend,
      state.mode,
      state.state,
      state.source,
      state.updated_at || '',
    ].join(':')
    if (seen.has(key)) {
      continue
    }
    seen.add(key)
    output.push(state)
  }
  return output
}

function buildProvenanceVisibility(
  runSummary: z.infer<typeof AnalysisRunSummarySchema>,
  routing: z.infer<typeof BackendRoutingMetadataSchema>,
  coverage: z.infer<typeof CoverageEnvelopeSchema>,
  evidenceState: z.infer<typeof AnalysisEvidenceStateSchema>[]
) {
  const evidenceCounts = {
    fresh: 0,
    reused: 0,
    partial: 0,
    stale: 0,
    incompatible: 0,
    missing: 0,
    deferred: 0,
  }
  for (const state of evidenceState) {
    evidenceCounts[state.state] += 1
  }

  return ProvenanceVisibilitySchema.parse({
    evidence_counts: evidenceCounts,
    reused_stage_count: runSummary.stages.filter((stage) => stage.execution_state === 'reused').length,
    recoverable_stage_count: runSummary.recoverable_stages.length,
    deferred_stage_count: runSummary.deferred_jobs.length,
    omitted_backend_reasons: routing.omitted_backend_reasons,
    deferred_domains: coverage.coverage_gaps
      .filter((gap) => gap.status === 'queued' || gap.status === 'missing')
      .map((gap) => `${gap.domain}: ${gap.reason}`),
  })
}

function normalizeToolLikeResult(result: WorkerResult | ToolResult): WorkerResult {
  if (!('content' in result)) {
    return result
  }

  const structured = result.structuredContent
  if (structured && typeof structured === 'object') {
    const payload = structured as Record<string, unknown>
    return {
      ok: Boolean(payload.ok ?? !result.isError),
      data: payload.data,
      errors: Array.isArray(payload.errors) ? (payload.errors as string[]) : undefined,
      warnings: Array.isArray(payload.warnings) ? (payload.warnings as string[]) : undefined,
      metrics:
        payload.metrics && typeof payload.metrics === 'object'
          ? (payload.metrics as Record<string, unknown>)
          : undefined,
    }
  }

  const text = result.content.find((item) => item.type === 'text')?.text
  if (!text) {
    return {
      ok: !result.isError,
      errors: result.isError ? ['Delegated tool returned no structured payload.'] : undefined,
    }
  }

  try {
    const payload = JSON.parse(text) as Record<string, unknown>
    return {
      ok: Boolean(payload.ok ?? !result.isError),
      data: payload.data,
      errors: Array.isArray(payload.errors) ? (payload.errors as string[]) : undefined,
      warnings: Array.isArray(payload.warnings) ? (payload.warnings as string[]) : undefined,
      metrics:
        payload.metrics && typeof payload.metrics === 'object'
          ? (payload.metrics as Record<string, unknown>)
          : undefined,
    }
  } catch {
    return {
      ok: !result.isError,
      errors: result.isError ? ['Delegated tool returned non-JSON output.'] : undefined,
    }
  }
}

function extractImportsMap(result: WorkerResult | undefined): Record<string, string[]> {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  if (data.imports && typeof data.imports === 'object') {
    return data.imports as Record<string, string[]>
  }
  return {}
}

function extractPreviewStrings(result: WorkerResult | undefined): string[] {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  if (!Array.isArray(data.strings)) {
    return []
  }
  return dedupeStrings(
    data.strings.map((item) =>
      typeof (item as Record<string, unknown>)?.string === 'string'
        ? String((item as Record<string, unknown>).string)
        : null
    ),
    32
  )
}

function extractPackerNames(result: WorkerResult | undefined): string[] {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  if (!Array.isArray(data.detections)) {
    return []
  }
  return dedupeStrings(
    (data.detections as Array<Record<string, unknown>>).map((item) =>
      typeof item.name === 'string' ? item.name : null
    ),
    12
  )
}

function extractCompilerPackerNames(result: WorkerResult | undefined): string[] {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  if (!Array.isArray(data.packer_findings)) {
    return []
  }
  return dedupeStrings(
    (data.packer_findings as Array<Record<string, unknown>>).map((item) =>
      typeof item.name === 'string' ? item.name : null
    ),
    12
  )
}

function extractSectionCount(result: WorkerResult | undefined): number | null {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  const summary = data.summary && typeof data.summary === 'object' ? (data.summary as Record<string, unknown>) : {}
  if (typeof summary.section_count === 'number') {
    return summary.section_count
  }
  if (Array.isArray(data.sections)) {
    return data.sections.length
  }
  return null
}

function safeParseOptional<T>(schema: z.ZodType<T>, value: unknown): T | undefined {
  const parsed = schema.safeParse(value)
  return parsed.success ? parsed.data : undefined
}

function extractUnpackDebugEnvelope(
  stageResult: unknown,
  runSummary: z.infer<typeof AnalysisRunSummarySchema>
): z.infer<typeof UnpackDebugEnvelopeSchema> {
  const candidates = [
    stageResult,
    ...runSummary.stages
      .slice()
      .reverse()
      .map((stage) => stage.result),
  ]

  const diffDigests: z.infer<typeof AnalysisDiffDigestSchema>[] = []
  let packedState: z.infer<typeof PackedStateSchema> | undefined
  let unpackState: z.infer<typeof UnpackStateSchema> | undefined
  let unpackConfidence: number | undefined
  let unpackPlan: z.infer<typeof UnpackPlanSchema> | undefined
  let unpackExecution: z.infer<typeof UnpackExecutionSchema> | undefined
  let debugState: z.infer<typeof DebugStateSchema> | undefined
  let debugSession: z.infer<typeof DebugSessionRecordSchema> | undefined

  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== 'object') {
      continue
    }
    const record = candidate as Record<string, unknown>
    packedState ||= safeParseOptional(PackedStateSchema, record.packed_state)
    unpackState ||= safeParseOptional(UnpackStateSchema, record.unpack_state)
    if (unpackConfidence === undefined && typeof record.unpack_confidence === 'number') {
      unpackConfidence = Math.max(0, Math.min(1, record.unpack_confidence))
    }
    unpackPlan ||= safeParseOptional(UnpackPlanSchema, record.unpack_plan)
    unpackExecution ||= safeParseOptional(UnpackExecutionSchema, record.unpack_execution)
    debugState ||= safeParseOptional(DebugStateSchema, record.debug_state)
    debugSession ||= safeParseOptional(DebugSessionRecordSchema, record.debug_session)
    if (Array.isArray(record.diff_digests)) {
      for (const item of record.diff_digests) {
        const parsed = safeParseOptional(AnalysisDiffDigestSchema, item)
        if (parsed) {
          diffDigests.push(parsed)
        }
      }
    }
  }

  const uniqueDiffs = diffDigests.filter((item, index, array) =>
    array.findIndex((candidate) => candidate.diff_id === item.diff_id) === index
  )

  return UnpackDebugEnvelopeSchema.parse({
    ...(packedState ? { packed_state: packedState } : {}),
    ...(unpackState ? { unpack_state: unpackState } : {}),
    ...(typeof unpackConfidence === 'number' ? { unpack_confidence: unpackConfidence } : {}),
    ...(unpackPlan ? { unpack_plan: unpackPlan } : {}),
    ...(unpackExecution ? { unpack_execution: unpackExecution } : {}),
    ...(debugState ? { debug_state: debugState } : {}),
    ...(debugSession ? { debug_session: debugSession } : {}),
    ...(uniqueDiffs.length > 0 ? { diff_digests: uniqueDiffs } : {}),
  })
}

function findSuspiciousImports(importsMap: Record<string, string[]>): string[] {
  const matches: string[] = []
  for (const [dll, functions] of Object.entries(importsMap)) {
    for (const func of functions || []) {
      const lowered = func.toLowerCase()
      if (suspiciousImportNames.some((name) => lowered.includes(name))) {
        matches.push(`${dll}!${func}`)
      }
    }
  }
  return dedupeStrings(matches, 20)
}

function findSuspiciousStrings(strings: string[]): string[] {
  return dedupeStrings(
    strings.filter((value) => suspiciousStringPatterns.some((pattern) => pattern.test(value))),
    20
  )
}

function findUrls(strings: string[]): string[] {
  return dedupeStrings(strings.filter((value) => /^https?:\/\//i.test(value)), 12)
}

function findIpAddresses(strings: string[]): string[] {
  return dedupeStrings(
    strings.filter((value) => /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(value)),
    12
  )
}

function resolveDefaultYaraXRulesPath(): string | null {
  const candidates = [
    process.env.YARA_X_RULES_PATH,
    path.join(process.cwd(), 'rules', 'default.yarx'),
    path.join(process.cwd(), 'rules', 'yara_x', 'default.yarx'),
  ].filter((item): item is string => Boolean(item && item.trim().length > 0))

  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) {
        return candidate
      }
    } catch {
      continue
    }
  }
  return null
}

function buildFastThreatLevel(input: {
  yaraMatches: number
  suspiciousImports: number
  suspiciousStrings: number
  packed: boolean
}): { threatLevel: 'clean' | 'suspicious' | 'malicious' | 'unknown'; confidence: number } {
  const score =
    (input.yaraMatches > 0 ? 2 : 0) +
    (input.suspiciousImports > 0 ? 1 : 0) +
    (input.suspiciousStrings > 0 ? 1 : 0) +
    (input.packed ? 1 : 0)
  if (score >= 4) {
    return { threatLevel: 'malicious', confidence: 0.86 }
  }
  if (score >= 2) {
    return { threatLevel: 'suspicious', confidence: 0.68 }
  }
  if (score === 1) {
    return { threatLevel: 'unknown', confidence: 0.5 }
  }
  return { threatLevel: 'clean', confidence: 0.42 }
}

function buildCoverageForRun(
  sample: Sample,
  depth: z.infer<typeof AnalysisIntentDepthSchema>,
  completionState: 'bounded' | 'partial' | 'queued' | 'completed',
  extraGaps: Array<{ domain: string; status: 'missing' | 'skipped' | 'queued' | 'degraded' | 'blocked'; reason: string }>
) {
  const sampleSizeTier = classifySampleSizeTier(sample.size)
  const analysisBudgetProfile = deriveAnalysisBudgetProfile(depth, sampleSizeTier)
  return buildCoverageEnvelope({
    coverageLevel: 'quick',
    completionState,
    sampleSizeTier,
    analysisBudgetProfile,
    downgradeReasons: buildBudgetDowngradeReasons({
      requestedDepth: depth,
      sampleSizeTier,
      analysisBudgetProfile,
    }),
    coverageGaps: extraGaps,
    unverifiedAreas: [
      'Function-level attribution remains unverified until the function_map stage completes.',
      'Dynamic behavior remains unverified until a dynamic stage executes.',
    ],
    upgradePaths: [
      {
        tool: 'workflow.analyze.promote',
        purpose: 'Promote this persisted run to deeper static, function-map, reconstruct, or summary stages.',
        closes_gaps: ['function_attribution', 'reconstruction_export', 'dynamic_behavior'],
        expected_coverage_gain: 'Queues deeper stages without rerunning the existing preview profile.',
        cost_tier: 'medium',
      },
    ],
  })
}

function parseJsonRecord<T>(value: string | null | undefined, fallback: T): T {
  if (!value || !value.trim()) {
    return fallback
  }
  try {
    return JSON.parse(value) as T
  } catch {
    return fallback
  }
}

function dedupeArtifactRefsById(artifacts: ArtifactRef[]): ArtifactRef[] {
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

function readExecutionPolicy(run: AnalysisRun) {
  const metadata = parseJsonRecord<Record<string, unknown>>(run.metadata_json, {})
  return {
    allowTransformations: Boolean(metadata.allow_transformations),
    allowLiveExecution: Boolean(metadata.allow_live_execution),
  }
}

function createOrReuseDebugSessionForRun(
  database: DatabaseManager,
  input: {
    runId: string
    sample: Sample
    status: z.infer<typeof DebugSessionRecordSchema.shape.status>
    debugState: z.infer<typeof DebugStateSchema>
    backend?: string | null
    currentPhase?: string | null
    sessionTag?: string | null
    artifactRefs?: ArtifactRef[]
    guidance: z.infer<typeof DebugSessionGuidanceSchema>
    metadata?: Record<string, unknown>
  }
) {
  const existing = database.findLatestDebugSessionByRun(input.runId)
  if (existing) {
    const mergedArtifacts = dedupeArtifactRefsById([
      ...parseJsonRecord<ArtifactRef[]>(existing.artifact_refs_json, []),
      ...(input.artifactRefs || []),
    ])
    database.updateDebugSession(existing.id, {
      status: input.status,
      debug_state: input.debugState,
      backend: input.backend ?? null,
      current_phase: input.currentPhase ?? null,
      session_tag: input.sessionTag ?? existing.session_tag ?? null,
      artifact_refs_json: JSON.stringify(mergedArtifacts),
      guidance_json: JSON.stringify(input.guidance),
      metadata_json: JSON.stringify({
        ...parseJsonRecord<Record<string, unknown>>(existing.metadata_json, {}),
        ...(input.metadata || {}),
      }),
      updated_at: new Date().toISOString(),
      finished_at:
        input.status === 'captured' || input.status === 'correlated'
          ? new Date().toISOString()
          : null,
    })
    return parseDatabaseDebugSession(database.findDebugSession(existing.id)!)
  }

  const session = createDebugSessionRecord({
    runId: input.runId,
    sample: input.sample,
    status: input.status,
    debugState: input.debugState,
    backend: input.backend,
    currentPhase: input.currentPhase,
    sessionTag: input.sessionTag,
    artifactRefs: input.artifactRefs,
    guidance: input.guidance,
    metadata: input.metadata,
  })
  database.insertDebugSession(toDatabaseDebugSession(session))
  return session
}

function createDependencies(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  policyGuard: PolicyGuard,
  server?: MCPServer,
  dependencies: AnalyzePipelineDependencies = {},
  jobQueue?: JobQueue
): AnalyzePipelineDependencies {
  return {
    peFingerprint:
      dependencies.peFingerprint ||
      createPEFingerprintHandler({ workspaceManager, database, cacheManager } as any),
    runtimeDetect:
      dependencies.runtimeDetect ||
      createRuntimeDetectHandler(workspaceManager, database, cacheManager),
    peImportsExtract:
      dependencies.peImportsExtract ||
      createPEImportsExtractHandler({ workspaceManager, database, cacheManager } as any),
    stringsExtract:
      dependencies.stringsExtract ||
      createStringsExtractHandler(workspaceManager, database, cacheManager, jobQueue),
    stringsFlossDecode:
      dependencies.stringsFlossDecode ||
      createStringsFlossDecodeHandler(workspaceManager, database, cacheManager, jobQueue),
    yaraScan:
      dependencies.yaraScan ||
      createYaraScanHandler(workspaceManager, database, cacheManager),
    packerDetect:
      dependencies.packerDetect ||
      createPackerDetectHandler(workspaceManager, database, cacheManager),
    compilerPackerDetect:
      dependencies.compilerPackerDetect ||
      createCompilerPackerDetectHandler(workspaceManager, database),
    binaryRoleProfile:
      dependencies.binaryRoleProfile ||
      createBinaryRoleProfileHandler(workspaceManager, database, cacheManager, undefined, jobQueue),
    staticCapabilityTriage:
      dependencies.staticCapabilityTriage ||
      createStaticCapabilityTriageHandler(workspaceManager, database),
    peStructureAnalyze:
      dependencies.peStructureAnalyze ||
      createPEStructureAnalyzeHandler({ workspaceManager, database } as any),
    elfStructureAnalyze:
      dependencies.elfStructureAnalyze ||
      createElfStructureAnalyzeHandler(workspaceManager, database),
    machoStructureAnalyze:
      dependencies.machoStructureAnalyze ||
      createMachoStructureAnalyzeHandler(workspaceManager, database),
    analysisContextLink:
      dependencies.analysisContextLink ||
      createAnalysisContextLinkHandler(workspaceManager, database, cacheManager, {}, jobQueue),
    cryptoIdentify:
      dependencies.cryptoIdentify ||
      createCryptoIdentifyHandler(workspaceManager, database, cacheManager, {}, jobQueue),
    rustBinaryAnalyze:
      dependencies.rustBinaryAnalyze ||
      createRustBinaryAnalyzeHandler(workspaceManager, database, cacheManager),
    dynamicDependencies:
      dependencies.dynamicDependencies ||
      createDynamicDependenciesHandler(workspaceManager, database),
    breakpointSmart:
      dependencies.breakpointSmart ||
      createBreakpointSmartHandler(workspaceManager, database, cacheManager),
    traceCondition:
      dependencies.traceCondition ||
      createTraceConditionHandler(workspaceManager, database, cacheManager),
    sandboxExecute:
      dependencies.sandboxExecute ||
      createSandboxExecuteHandler(workspaceManager, database, policyGuard),
    workflowSummarize:
      dependencies.workflowSummarize ||
      createWorkflowSummarizeHandler(workspaceManager, database, cacheManager, server),
    reconstructWorkflow:
      dependencies.reconstructWorkflow ||
      createReconstructWorkflowHandler(workspaceManager, database, cacheManager),
    ghidraAnalyze:
      dependencies.ghidraAnalyze ||
      (createGhidraAnalyzeHandler({ workspaceManager, database } as any) as any),
    rizinAnalyze:
      dependencies.rizinAnalyze ||
      createRizinAnalyzeHandler(workspaceManager, database),
    yaraXScan:
      dependencies.yaraXScan ||
      createYaraXScanHandler(workspaceManager, database),
    upxInspect:
      dependencies.upxInspect ||
      createUPXInspectHandler(workspaceManager, database),
    qilingInspect:
      dependencies.qilingInspect ||
      createQilingInspectHandler(workspaceManager, database),
    pandaInspect:
      dependencies.pandaInspect ||
      createPandaInspectHandler(workspaceManager, database),
    angrAnalyze:
      dependencies.angrAnalyze ||
      createAngrAnalyzeHandler(workspaceManager, database),
    retdecDecompile:
      dependencies.retdecDecompile ||
      createRetDecDecompileHandler(workspaceManager, database),
    resolveBackends: dependencies.resolveBackends || resolveAnalysisBackends,
  }
}

async function buildFastProfileStage(
  context: StageExecutionContext,
  runId: string,
  sample: Sample,
  input: z.infer<typeof analyzeStartInputSchema>
): Promise<{ result: Record<string, unknown>; artifacts: ArtifactRef[] }> {
  const deps = context.dependencies
  const readiness = (deps.resolveBackends || resolveAnalysisBackends)()
  const defaultYaraXRulesPath = resolveDefaultYaraXRulesPath()
  const sampleSizeTier = classifySampleSizeTier(sample.size)
  const boundedPreview =
    sampleSizeTier === 'large' || sampleSizeTier === 'oversized'
      ? { maxStrings: 72, binaryMode: 'fast' as const }
      : sampleSizeTier === 'medium'
        ? { maxStrings: 96, binaryMode: 'fast' as const }
        : { maxStrings: 120, binaryMode: 'fast' as const }

  const [
    fingerprintResult,
    runtimeResult,
    importsResult,
    stringsResult,
    yaraResult,
    packerResult,
    compilerPackerResult,
    binaryRoleResult,
    rizinResult,
  ] = await Promise.all([
    deps.peFingerprint!({ sample_id: sample.id, force_refresh: input.force_refresh }),
    deps.runtimeDetect!({ sample_id: sample.id, force_refresh: input.force_refresh }),
    deps.peImportsExtract!({
      sample_id: sample.id,
      group_by_dll: true,
      force_refresh: input.force_refresh,
    }),
    deps.stringsExtract!({
      sample_id: sample.id,
      mode: 'preview',
      max_strings: boundedPreview.maxStrings,
      force_refresh: input.force_refresh,
      defer_if_slow: false,
    }),
    deps.yaraScan!({
      sample_id: sample.id,
      rule_set: YARA_DEFAULT_RULE_SET,
      rule_tier: 'production',
      force_refresh: input.force_refresh,
    }),
    deps.packerDetect!({ sample_id: sample.id, force_refresh: input.force_refresh }),
    deps.compilerPackerDetect!({ sample_id: sample.id }),
    deps.binaryRoleProfile!({
      sample_id: sample.id,
      mode: boundedPreview.binaryMode,
      force_refresh: input.force_refresh,
      defer_if_slow: false,
    }),
    readiness.rizin.available
      ? deps.rizinAnalyze!({
          sample_id: sample.id,
          operation: 'info',
          timeout_sec: 20,
          persist_artifact: true,
        })
      : Promise.resolve({ ok: false, warnings: ['rizin unavailable'] } as WorkerResult),
  ])

  let yaraXResult: WorkerResult | undefined
  if (readiness.yara_x.available && defaultYaraXRulesPath) {
    yaraXResult = await deps.yaraXScan!({
      sample_id: sample.id,
      rules_path: defaultYaraXRulesPath,
      timeout_sec: 20,
      persist_artifact: true,
    })
  }

  const packerHint =
    Boolean((packerResult.data as Record<string, unknown> | undefined)?.packed) ||
    Boolean((compilerPackerResult.data as Record<string, unknown> | undefined)?.summary)
  let upxResult: WorkerResult | undefined
  if (packerHint && readiness.upx.available) {
    upxResult = await deps.upxInspect!({
      sample_id: sample.id,
      operation: 'test',
      timeout_sec: 15,
      persist_artifact: true,
    })
  }

  const importsMap = extractImportsMap(importsResult)
  const previewStrings = extractPreviewStrings(stringsResult)
  const suspiciousImports = findSuspiciousImports(importsMap)
  const suspiciousStrings = findSuspiciousStrings(previewStrings)
  const urls = findUrls(previewStrings)
  const ipAddresses = findIpAddresses(previewStrings)
  const yaraMatches =
    Array.isArray((yaraResult.data as Record<string, unknown> | undefined)?.matches)
      ? ((yaraResult.data as Record<string, unknown>).matches as Array<Record<string, unknown>>).map((item) =>
          String(item.rule || '')
        )
      : []
  const threat = buildFastThreatLevel({
    yaraMatches: yaraMatches.length,
    suspiciousImports: suspiciousImports.length,
    suspiciousStrings: suspiciousStrings.length,
    packed: packerHint,
  })

  const routingMetadata = buildIntentBackendPlan({
    goal: input.goal,
    depth: input.depth,
    backendPolicy: input.backend_policy,
    allowTransformations: input.allow_transformations,
    allowLiveExecution: input.allow_live_execution,
    readiness,
    signals: {
      packer_suspected: packerHint,
      legacy_yara_weak: yaraMatches.length === 0,
      degraded_structure: !fingerprintResult.ok,
      import_parsing_weak: !importsResult.ok,
      yara_x_rules_ready: Boolean(defaultYaraXRulesPath),
      large_sample_preview:
        sampleSizeTier === 'large' || sampleSizeTier === 'oversized',
      },
  })

  const packerData =
    packerResult.data && typeof packerResult.data === 'object'
      ? (packerResult.data as Record<string, unknown>)
      : {}
  const compilerPackerData =
    compilerPackerResult.data && typeof compilerPackerResult.data === 'object'
      ? (compilerPackerResult.data as Record<string, unknown>)
      : {}
  const unpackPlan = buildUnpackPlan({
    sample,
    allowTransformations: input.allow_transformations,
    allowLiveExecution: input.allow_live_execution,
    packerDetected: Boolean(packerData.packed),
    packerConfidence:
      typeof packerData.confidence === 'number' ? packerData.confidence : undefined,
    packerNames: extractPackerNames(packerResult),
    compilerPackerNames: extractCompilerPackerNames(compilerPackerResult),
    upxValidationPassed:
      typeof (upxResult?.data as Record<string, unknown> | undefined)?.exit_code === 'number' &&
      Number((upxResult?.data as Record<string, unknown>).exit_code) === 0,
    upxReady: readiness.upx.available,
    rizinReady: readiness.rizin.available,
  })
  const unpackPlanArtifact = await persistUnpackDebugJsonArtifact(
    context.workspaceManager,
    context.database,
    sample.id,
    UNPACK_PLAN_ARTIFACT_TYPE,
    'unpack_plan',
    unpackPlan,
    `analysis/${runId}`
  )
  persistCanonicalEvidence(context.database, {
    sample,
    evidenceFamily: 'unpack_plan',
    backend: 'runtime',
    mode: 'planned',
    args: {
      run_id: runId,
      allow_transformations: input.allow_transformations,
      allow_live_execution: input.allow_live_execution,
    },
    result: unpackPlan,
    artifactRefs: [unpackPlanArtifact],
    provenance: {
      sources: ['packer.detect', 'compiler.packer.detect', 'upx.inspect', 'rizin.analyze'],
    },
    metadata: {
      packed_state: unpackPlan.packed_state,
      safety_level: unpackPlan.safety_level,
      strategy: unpackPlan.strategy,
    },
  })

  const evidence = dedupeStrings([
    suspiciousImports.length > 0 ? `Detected ${suspiciousImports.length} suspicious import(s).` : null,
    suspiciousStrings.length > 0 ? `Detected ${suspiciousStrings.length} suspicious preview string(s).` : null,
    yaraMatches.length > 0 ? `Legacy YARA matched ${yaraMatches.join(', ')}.` : null,
    packerHint ? 'Packing or protector indicators were observed in the fast profile.' : null,
    readiness.rizin.available && rizinResult.ok ? 'Rizin fast-path corroboration completed.' : null,
    yaraXResult?.ok ? 'YARA-X corroboration completed.' : null,
    upxResult?.ok ? 'UPX validation completed.' : null,
  ])

  const artifacts = [
    ...collectArtifactsFromResult(stringsResult),
    ...collectArtifactsFromResult(yaraResult),
    ...collectArtifactsFromResult(binaryRoleResult),
    ...collectArtifactsFromResult(rizinResult),
    ...collectArtifactsFromResult(yaraXResult),
    ...collectArtifactsFromResult(upxResult),
    unpackPlanArtifact,
  ]

  const coverageEnvelope = buildCoverageForRun(sample, input.depth, 'bounded', [
    {
      domain: 'function_attribution',
      status: 'missing',
      reason: 'Fast profile does not run Ghidra or Xref correlation.',
    },
    {
      domain: 'deep_static_enrichment',
      status: 'queued',
      reason: 'Static enrichment remains a later promote stage so the first request stays nonblocking.',
    },
    ...(sampleSizeTier === 'large' || sampleSizeTier === 'oversized'
      ? [
          {
            domain: 'large_sample_bounded_preview',
            status: 'degraded' as const,
            reason:
              'Large samples stay on a bounded Rizin plus preview-backed first pass; deeper attribution and full correlation are promoted later to preserve memory headroom.',
          },
        ]
      : []),
    ...(unpackPlan.packed_state !== 'not_packed'
      ? [
          {
            domain: 'packed_sample_unresolved',
            status: 'queued' as const,
            reason:
              'Packing was detected or suspected. Follow the unpack plan before assuming deeper static attribution on the original binary is representative.',
          },
        ]
      : []),
  ])

  return {
    result: mergeRoutingMetadata(
      mergeCoverageEnvelope(
        {
          run_id: runId,
          sample_id: sample.id,
          stage: FAST_PROFILE_STAGE,
          status: 'ready',
          execution_state: 'inline',
          summary:
            `Fast profile completed with ${suspiciousImports.length} suspicious import(s), ${suspiciousStrings.length} suspicious preview string(s), and ${yaraMatches.length} YARA hit(s).` +
            (sampleSizeTier === 'large' || sampleSizeTier === 'oversized'
              ? ' Large-sample bounds remained active; deeper stages stay queued until explicitly promoted.'
              : ''),
          confidence: threat.confidence,
          threat_level: threat.threatLevel,
          iocs: {
            suspicious_imports: suspiciousImports,
            suspicious_strings: suspiciousStrings,
            yara_matches: yaraMatches,
            urls,
            ip_addresses: ipAddresses,
          },
          evidence,
          evidence_state: uniqueEvidenceStates(
            collectEvidenceStatesFromPayload([stringsResult.data, binaryRoleResult.data])
          ),
          packed_state: unpackPlan.packed_state,
          unpack_state: unpackPlan.unpack_state,
          unpack_confidence: unpackPlan.unpack_confidence,
          unpack_plan: {
            ...unpackPlan,
            artifact_refs: [unpackPlanArtifact],
          },
          debug_state: 'not_requested',
          recommendation:
            'Use workflow.analyze.promote to queue enrich_static or function_map stages instead of rerunning the fast profile.',
          raw_results: {
            fingerprint: fingerprintResult.data || null,
            runtime: runtimeResult.data || null,
            imports: importsResult.data || null,
            strings: stringsResult.data || null,
            yara: yaraResult.data || null,
            packer: packerResult.data || null,
            compiler_packer: compilerPackerResult.data || null,
            binary_role: binaryRoleResult.data || null,
            backend_enrichments: {
              ...(rizinResult.ok && rizinResult.data ? { rizin: rizinResult.data } : {}),
              ...(yaraXResult?.ok && yaraXResult.data ? { yara_x: yaraXResult.data } : {}),
              ...(upxResult?.ok && upxResult.data ? { upx: upxResult.data } : {}),
            },
          },
          result_mode: 'quick_profile',
          recommended_next_tools:
            unpackPlan.packed_state !== 'not_packed'
              ? ['workflow.analyze.promote', 'workflow.analyze.status', 'upx.inspect']
              : ['workflow.analyze.promote', 'workflow.analyze.status'],
          next_actions: [
            'Promote to enrich_static when you need FLOSS, PE structure, capability triage, crypto correlation, or full binary role profiling.',
            'Promote to function_map when you need Ghidra-backed function attribution.',
            ...(unpackPlan.packed_state !== 'not_packed'
              ? [
                  'Treat this packed sample as unpack-plan-first. Promote to dynamic_plan or dynamic_execute instead of jumping straight to reconstruct.',
                ]
              : []),
            ...(sampleSizeTier === 'large' || sampleSizeTier === 'oversized'
              ? [
                  'Keep this run in preview-first mode for large samples; inspect workflow.analyze.status before requesting heavier stages.',
                ]
              : []),
          ],
          artifact_refs: artifacts,
        },
        coverageEnvelope
      ),
      routingMetadata
    ),
    artifacts,
  }
}

async function runEnrichStaticStage(
  context: StageExecutionContext,
  sampleId: string,
  forceRefresh: boolean
): Promise<{ result: Record<string, unknown>; artifacts: ArtifactRef[] }> {
  const deps = context.dependencies

  // Format-aware structural analysis: route to the correct tool based on file_type
  const sample = context.database.findSample(sampleId)
  const fileType = sample?.file_type ?? 'PE'
  let structureAnalyzePromise: Promise<WorkerResult>
  if (fileType === 'ELF' && deps.elfStructureAnalyze) {
    structureAnalyzePromise = deps.elfStructureAnalyze({ sample_id: sampleId })
  } else if ((fileType === 'Mach-O' || fileType === 'Mach-O-Fat') && deps.machoStructureAnalyze) {
    structureAnalyzePromise = deps.machoStructureAnalyze({ sample_id: sampleId })
  } else {
    structureAnalyzePromise = deps.peStructureAnalyze!({ sample_id: sampleId })
  }

  const [stringsResult, flossResult, binaryRoleResult, capabilityResult, peStructureResult, contextLinkResult, cryptoResult, rustResult] = await Promise.all([
    deps.stringsExtract!({ sample_id: sampleId, mode: 'full', force_refresh: forceRefresh, defer_if_slow: false }),
    deps.stringsFlossDecode!({ sample_id: sampleId, force_refresh: forceRefresh, defer_if_slow: false }),
    deps.binaryRoleProfile!({ sample_id: sampleId, mode: 'full', force_refresh: forceRefresh, defer_if_slow: false }),
    deps.staticCapabilityTriage!({ sample_id: sampleId }),
    structureAnalyzePromise,
    deps.analysisContextLink!({ sample_id: sampleId, mode: 'full', force_refresh: forceRefresh, defer_if_slow: false }),
    deps.cryptoIdentify!({ sample_id: sampleId, mode: 'full', force_refresh: forceRefresh, defer_if_slow: false }),
    deps.rustBinaryAnalyze!({ sample_id: sampleId, force_refresh: forceRefresh }),
  ])

  const artifacts = [
    ...collectArtifactsFromResult(stringsResult),
    ...collectArtifactsFromResult(flossResult),
    ...collectArtifactsFromResult(binaryRoleResult),
    ...collectArtifactsFromResult(capabilityResult),
    ...collectArtifactsFromResult(peStructureResult),
    ...collectArtifactsFromResult(contextLinkResult),
    ...collectArtifactsFromResult(cryptoResult),
    ...collectArtifactsFromResult(rustResult),
  ]

  return {
    result: {
      stage: 'enrich_static',
      status: 'ready',
      execution_state: 'completed',
      summary: 'Static enrichment completed using full strings, FLOSS, role profiling, PE structure, capability triage, context-linking, crypto identification, and Rust-aware analysis.',
      evidence_state: uniqueEvidenceStates(
        collectEvidenceStatesFromPayload([
          stringsResult.data,
          flossResult.data,
          binaryRoleResult.data,
          contextLinkResult.data,
          cryptoResult.data,
        ])
      ),
      stage_outputs: {
        strings: stringsResult.data || null,
        floss: flossResult.data || null,
        binary_role: binaryRoleResult.data || null,
        static_capability: capabilityResult.data || null,
        pe_structure: peStructureResult.data || null,
        analysis_context: contextLinkResult.data || null,
        crypto: cryptoResult.data || null,
        rust: rustResult.data || null,
      },
      recommended_next_tools: ['workflow.analyze.promote', 'workflow.analyze.status'],
      next_actions: [
        'Promote to function_map for Ghidra-backed function attribution and code navigation.',
        'Use persisted artifacts instead of repeating heavy full-string and context-link passes.',
      ],
      artifact_refs: artifacts,
    },
    artifacts,
  }
}

async function runFunctionMapStage(
  context: StageExecutionContext,
  sampleId: string
): Promise<{ result: Record<string, unknown>; artifacts: ArtifactRef[] }> {
  const ghidraResult = normalizeToolLikeResult(
    await context.dependencies.ghidraAnalyze!({
      sample_id: sampleId,
      options: {
        timeout: 900,
        max_cpu: '2',
      },
    })
  )
  const rizinFunctions = await context.dependencies.rizinAnalyze!({
    sample_id: sampleId,
    operation: 'functions',
    max_items: 64,
    timeout_sec: 30,
    persist_artifact: true,
  })
  const artifacts = [
    ...collectArtifactsFromResult(ghidraResult),
    ...collectArtifactsFromResult(rizinFunctions),
  ]
  return {
    result: {
      stage: 'function_map',
      status: ghidraResult.ok ? 'ready' : 'partial',
      execution_state: ghidraResult.ok ? 'completed' : 'partial',
      summary:
        ghidraResult.ok
          ? 'Function-map stage completed with Ghidra-backed analysis and Rizin corroboration.'
          : 'Function-map stage completed partially; inspect the persisted function-map artifacts and warnings.',
      stage_outputs: {
        ghidra: ghidraResult.data || null,
        rizin: rizinFunctions.data || null,
      },
      recommended_next_tools: ['workflow.analyze.promote', 'workflow.reconstruct', 'code.function.decompile'],
      next_actions: [
        'Promote to reconstruct when you need source-like export or backend fallback decompilation.',
        'Use code.function.decompile or code.function.cfg on the now-attributed function set before going broader.',
      ],
      artifact_refs: artifacts,
    },
    artifacts,
  }
}

async function runReconstructStage(
  context: StageExecutionContext,
  sampleId: string
): Promise<{ result: Record<string, unknown>; artifacts: ArtifactRef[] }> {
  const reconstructResult = await context.dependencies.reconstructWorkflow!({
    sample_id: sampleId,
    path: 'auto',
    topk: 12,
    allow_partial: true,
    include_plan: true,
    include_preflight: true,
  })
  const angrResult = await context.dependencies.angrAnalyze!({
    sample_id: sampleId,
    analysis: 'cfg_fast',
    persist_artifact: true,
  })
  const retdecResult = await context.dependencies.retdecDecompile!({
    sample_id: sampleId,
    output_format: 'plain',
    persist_artifact: true,
  })
  const artifacts = [
    ...collectArtifactsFromResult(reconstructResult),
    ...collectArtifactsFromResult(angrResult),
    ...collectArtifactsFromResult(retdecResult),
  ]

  return {
    result: {
      stage: 'reconstruct',
      status: reconstructResult.ok ? 'ready' : 'partial',
      execution_state: reconstructResult.ok ? 'completed' : 'partial',
      summary:
        'Reconstruction stage completed using the primary reconstruct workflow plus optional angr and RetDec corroboration artifacts.',
      stage_outputs: {
        reconstruct: reconstructResult.data || null,
        angr: angrResult.data || null,
        retdec: retdecResult.data || null,
      },
      recommended_next_tools: ['workflow.analyze.promote', 'workflow.summarize', 'artifact.read'],
      next_actions: [
        'Promote to summarize when you want a compact persisted summary without rerunning earlier stages.',
        'Read the emitted reconstruction artifacts instead of repeating heavy reconstruct passes.',
      ],
      artifact_refs: artifacts,
    },
    artifacts,
  }
}

async function runDynamicPlanStage(
  context: StageExecutionContext,
  runId: string,
  sampleId: string
): Promise<{ result: Record<string, unknown>; artifacts: ArtifactRef[] }> {
  const sample = context.database.findSample(sampleId)
  const run = context.database.findAnalysisRun(runId)
  if (!sample || !run) {
    throw new Error(`Analysis run context not found for dynamic_plan: ${runId}`)
  }

  const executionPolicy = readExecutionPolicy(run)
  const debugSessionTag = `debug/${runId}`
  const unpackSelection = await loadUnpackDebugArtifactSelection<z.infer<typeof UnpackPlanSchema>>(
    context.workspaceManager,
    context.database,
    sampleId,
    UNPACK_PLAN_ARTIFACT_TYPE,
    {
      scope: 'latest',
      sessionTag: `analysis/${runId}`,
    }
  )
  const unpackPlan = unpackSelection.latest_payload

  const [dependenciesResult, qilingResult, pandaResult, breakpointResult] = await Promise.all([
    context.dependencies.dynamicDependencies!({ sample_id: sampleId }),
    context.dependencies.qilingInspect!({ sample_id: sampleId, operation: 'preflight' }),
    context.dependencies.pandaInspect!({ sample_id: sampleId }),
    context.dependencies.breakpointSmart!({ sample_id: sampleId, session_tag: debugSessionTag }),
  ])
  const tracePlanResult = await context.dependencies.traceCondition!({
    sample_id: sampleId,
    reuse_cached: true,
    artifact_scope: 'session',
    session_tag: debugSessionTag,
  })
  const artifacts = [
    ...collectArtifactsFromResult(dependenciesResult),
    ...collectArtifactsFromResult(qilingResult),
    ...collectArtifactsFromResult(pandaResult),
    ...collectArtifactsFromResult(breakpointResult),
    ...collectArtifactsFromResult(tracePlanResult),
  ]
  const withheldReasons = !executionPolicy.allowLiveExecution
    ? ['Live debug backends remain approval-gated until allow_live_execution=true is present on the run.']
    : []
  const sessionGuidance = {
    recommended_next_tools: ['workflow.analyze.promote', 'workflow.analyze.status', 'sandbox.execute'],
    next_actions: [
      'Use dynamic_execute to continue through the persisted debug session instead of chaining loose one-off tools.',
      ...(unpackPlan?.packed_state && unpackPlan.packed_state !== 'not_packed'
        ? ['This sample still appears packed; prefer safe dump-oriented steps before deep static reconstruction.']
        : []),
    ],
    ...(withheldReasons.length > 0 ? { withheld_reasons: withheldReasons } : {}),
  }
  const debugSession = createOrReuseDebugSessionForRun(context.database, {
    runId,
    sample,
    status: executionPolicy.allowLiveExecution ? 'armed' : 'planned',
    debugState: executionPolicy.allowLiveExecution ? 'armed' : 'planned',
    backend: executionPolicy.allowLiveExecution ? 'sandbox.execute' : 'planning_only',
    currentPhase: 'debug_prepare',
    sessionTag: debugSessionTag,
    artifactRefs: artifacts,
    guidance: sessionGuidance,
    metadata: {
      unpack_strategy: unpackPlan?.strategy || null,
      packed_state: unpackPlan?.packed_state || 'unknown',
      approval_gated: !executionPolicy.allowLiveExecution,
    },
  })
  const debugSessionArtifact = await persistUnpackDebugJsonArtifact(
    context.workspaceManager,
    context.database,
    sampleId,
    DEBUG_SESSION_ARTIFACT_TYPE,
    'debug_session_plan',
    debugSession,
    debugSessionTag
  )
  const allArtifacts = dedupeArtifactRefsById([...artifacts, debugSessionArtifact])
  persistCanonicalEvidence(context.database, {
    sample,
    evidenceFamily: 'debug_session',
    backend: 'runtime',
    mode: 'planned',
    args: { run_id: runId, phase: 'dynamic_plan' },
    result: debugSession,
    artifactRefs: allArtifacts,
    metadata: {
      debug_state: debugSession.debug_state,
      backend: debugSession.backend,
    },
    provenance: {
      sources: ['dynamic.dependencies', 'qiling.inspect', 'panda.inspect', 'breakpoint.smart', 'trace.condition'],
    },
  })
  return {
    result: {
      stage: 'dynamic_plan',
      status: 'ready',
      execution_state: 'completed',
      summary:
        'Dynamic-plan stage completed using readiness probes and planning-only breakpoint analysis; no live execution was started.',
      packed_state: unpackPlan?.packed_state || 'unknown',
      unpack_state: unpackPlan?.unpack_state || 'not_started',
      unpack_confidence: unpackPlan?.unpack_confidence,
      ...(unpackPlan ? { unpack_plan: unpackPlan } : {}),
      debug_state: debugSession.debug_state,
      debug_session: debugSession,
      stage_outputs: {
        dependencies: dependenciesResult.data || null,
        qiling: qilingResult.data || null,
        panda: pandaResult.data || null,
        breakpoint_plan: breakpointResult.data || null,
        trace_plan: tracePlanResult.data || null,
      },
      recommended_next_tools: sessionGuidance.recommended_next_tools,
      next_actions: [
        ...sessionGuidance.next_actions,
        ...(withheldReasons.length > 0 ? withheldReasons : []),
      ],
      artifact_refs: allArtifacts,
    },
    artifacts: allArtifacts,
  }
}

async function runDynamicExecuteStage(
  context: StageExecutionContext,
  runId: string,
  sampleId: string
): Promise<{ result: Record<string, unknown>; artifacts: ArtifactRef[] }> {
  const sample = context.database.findSample(sampleId)
  const run = context.database.findAnalysisRun(runId)
  if (!sample || !run) {
    throw new Error(`Analysis run context not found for dynamic_execute: ${runId}`)
  }

  const executionPolicy = readExecutionPolicy(run)
  const debugSessionTag = context.database.findLatestDebugSessionByRun(runId)?.session_tag || `debug/${runId}`
  const unpackSelection = await loadUnpackDebugArtifactSelection<z.infer<typeof UnpackPlanSchema>>(
    context.workspaceManager,
    context.database,
    sampleId,
    UNPACK_PLAN_ARTIFACT_TYPE,
    {
      scope: 'latest',
      sessionTag: `analysis/${runId}`,
    }
  )
  const unpackPlan = unpackSelection.latest_payload
  const artifacts: ArtifactRef[] = []
  const diffDigests: Array<z.infer<typeof AnalysisDiffDigestSchema>> = []
  const beforeDynamicEvidence = await loadDynamicTraceEvidence(
    context.workspaceManager,
    context.database,
    sampleId,
    {
      evidenceScope: 'latest',
      sessionTag: debugSessionTag,
    }
  )

  let unpackExecution: z.infer<typeof UnpackExecutionSchema> | undefined
  let unpackedSampleId: string | null = null

  if (unpackPlan?.strategy === 'upx_decompress' && executionPolicy.allowTransformations) {
    const upxDecompressResult = await context.dependencies.upxInspect!({
      sample_id: sampleId,
      operation: 'decompress',
      timeout_sec: 30,
      persist_artifact: true,
      session_tag: debugSessionTag,
    })
    artifacts.push(...collectArtifactsFromResult(upxDecompressResult))

    const unpackedArtifact =
      collectArtifactsFromResult(upxDecompressResult).find((artifact) => artifact.type === 'upx_decompress') ||
      collectArtifactsFromResult(upxDecompressResult)[0] ||
      null

    if (unpackedArtifact) {
      const workspace = await context.workspaceManager.getWorkspace(sampleId)
      const unpackedPath = context.workspaceManager.normalizePath(workspace.root, unpackedArtifact.path)
      const unpackedBytes = await fs.promises.readFile(unpackedPath)
      const finalizer = createSampleFinalizationService(
        context.workspaceManager,
        context.database,
        context.policyGuard
      )
      const finalized = await finalizer.finalizeBuffer({
        data: unpackedBytes,
        filename: path.basename(unpackedPath),
        source: 'unpack:upx',
        auditOperation: 'workflow.analyze.stage',
      })
      unpackedSampleId = finalized.sample_id

      const [unpackedImports, unpackedStrings, unpackedStructure] = await Promise.all([
        context.dependencies.peImportsExtract!({
          sample_id: unpackedSampleId,
          group_by_dll: true,
          force_refresh: false,
        }),
        context.dependencies.stringsExtract!({
          sample_id: unpackedSampleId,
          mode: 'preview',
          max_strings: 96,
          force_refresh: false,
          defer_if_slow: false,
        }),
        // Format-aware: route unpacked sample to correct structural analysis
        (() => {
          const unpackedSample = context.database.findSample(unpackedSampleId!)
          const ft = unpackedSample?.file_type ?? 'PE'
          if (ft === 'ELF' && context.dependencies.elfStructureAnalyze) {
            return context.dependencies.elfStructureAnalyze({ sample_id: unpackedSampleId! })
          }
          if ((ft === 'Mach-O' || ft === 'Mach-O-Fat') && context.dependencies.machoStructureAnalyze) {
            return context.dependencies.machoStructureAnalyze({ sample_id: unpackedSampleId! })
          }
          return context.dependencies.peStructureAnalyze!({ sample_id: unpackedSampleId! })
        })(),
      ])
      const packedDiff = buildPackedVsUnpackedDiffDigest({
        sampleId,
        beforeRef: unpackSelection.latest_artifact,
        afterRef: unpackedArtifact,
        sizeBefore: sample.size,
        sizeAfter: finalized.size,
        importsBefore: Object.values(
          extractImportsMap(
            normalizeToolLikeResult({
              ok: true,
              data:
                safeParseOptional(
                  z.object({
                    raw_results: z.object({
                      imports: z.any().optional(),
                    }).optional(),
                  }),
                  context.database.findAnalysisRunStage(runId, FAST_PROFILE_STAGE)?.result_json
                    ? JSON.parse(context.database.findAnalysisRunStage(runId, FAST_PROFILE_STAGE)!.result_json || 'null')
                    : null
                )?.raw_results?.imports
                  ? {
                      imports:
                        safeParseOptional(
                          z.object({
                            raw_results: z.object({
                              imports: z.any().optional(),
                            }).optional(),
                          }),
                          context.database.findAnalysisRunStage(runId, FAST_PROFILE_STAGE)?.result_json
                            ? JSON.parse(context.database.findAnalysisRunStage(runId, FAST_PROFILE_STAGE)!.result_json || 'null')
                            : null
                        )?.raw_results?.imports,
                    }
                  : null,
            }) as WorkerResult
          )
        ).flat(),
        importsAfter: Object.values(extractImportsMap(unpackedImports)).flat(),
        stringsBefore: extractPreviewStrings(
          normalizeToolLikeResult({
            ok: true,
            data:
              safeParseOptional(
                z.object({
                  raw_results: z.object({
                    strings: z.any().optional(),
                  }).optional(),
                }),
                context.database.findAnalysisRunStage(runId, FAST_PROFILE_STAGE)?.result_json
                  ? JSON.parse(context.database.findAnalysisRunStage(runId, FAST_PROFILE_STAGE)!.result_json || 'null')
                  : null
              )?.raw_results?.strings
                ? {
                    strings:
                      safeParseOptional(
                        z.object({
                          raw_results: z.object({
                            strings: z.any().optional(),
                          }).optional(),
                        }),
                        context.database.findAnalysisRunStage(runId, FAST_PROFILE_STAGE)?.result_json
                          ? JSON.parse(context.database.findAnalysisRunStage(runId, FAST_PROFILE_STAGE)!.result_json || 'null')
                          : null
                      )?.raw_results?.strings,
                  }
                : null,
          }) as WorkerResult
        ),
        stringsAfter: extractPreviewStrings(unpackedStrings),
        sectionCountBefore: null,
        sectionCountAfter: extractSectionCount(unpackedStructure),
        sourceArtifactRefs: dedupeArtifactRefsById([
          ...(unpackSelection.artifact_refs || []),
          unpackedArtifact,
          ...collectArtifactsFromResult(unpackedImports),
          ...collectArtifactsFromResult(unpackedStrings),
          ...collectArtifactsFromResult(unpackedStructure),
        ]),
      })
      const packedDiffArtifact = await persistUnpackDebugJsonArtifact(
        context.workspaceManager,
        context.database,
        sampleId,
        ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE,
        'packed_vs_unpacked_diff',
        packedDiff,
        debugSessionTag
      )
      diffDigests.push({
        ...packedDiff,
        source_artifact_refs: dedupeArtifactRefsById([
          ...packedDiff.source_artifact_refs,
          packedDiffArtifact,
        ]),
      })
      artifacts.push(
        ...collectArtifactsFromResult(unpackedImports),
        ...collectArtifactsFromResult(unpackedStrings),
        ...collectArtifactsFromResult(unpackedStructure),
        packedDiffArtifact
      )

      unpackExecution = UnpackExecutionSchema.parse({
        execution_id: randomUUID(),
        sample_id: sampleId,
        packed_state: unpackPlan.packed_state,
        unpack_state: 'unpacked',
        unpack_confidence: Math.max(unpackPlan.unpack_confidence, 0.9),
        selected_backend: 'upx.inspect',
        safe_execution_mode: 'decompress',
        approval_required: false,
        resumable: true,
        summary: 'UPX-backed unpack attempt completed and produced a reusable unpacked sample.',
        unpacked_sample_id: unpackedSampleId,
        unpacked_artifact: unpackedArtifact,
        oep: null,
        import_rebuild: {
          status: 'not_needed',
          notes: ['UPX decompress completed without a separate import rebuild step.'],
        },
        failure_reason: null,
        derived_artifacts: dedupeArtifactRefsById([unpackedArtifact, packedDiffArtifact]),
        recommended_next_tools: ['workflow.analyze.start', 'workflow.analyze.promote', 'workflow.summarize'],
        next_actions: [
          'Continue deeper static analysis on the unpacked sample_id instead of the original packed input where practical.',
          'Use the persisted packed-vs-unpacked diff digest to understand what became visible after decompressing.',
        ],
      })
      const unpackExecutionArtifact = await persistUnpackDebugJsonArtifact(
        context.workspaceManager,
        context.database,
        sampleId,
        UNPACK_EXECUTION_ARTIFACT_TYPE,
        'unpack_execution',
        unpackExecution,
        debugSessionTag
      )
      artifacts.push(unpackExecutionArtifact)
      persistCanonicalEvidence(context.database, {
        sample,
        evidenceFamily: 'unpack_execution',
        backend: 'upx',
        mode: 'decompress',
        args: { run_id: runId },
        result: unpackExecution,
        artifactRefs: dedupeArtifactRefsById([unpackExecutionArtifact, ...(unpackExecution.derived_artifacts as ArtifactRef[])]),
        metadata: {
          unpack_state: unpackExecution.unpack_state,
          unpacked_sample_id: unpackedSampleId,
        },
        provenance: {
          sources: ['upx.inspect', 'pe.imports.extract', 'strings.extract', 'pe.structure.analyze'],
        },
      })
      persistCanonicalEvidence(context.database, {
        sample,
        evidenceFamily: 'analysis_diff',
        backend: 'runtime',
        mode: 'packed_vs_unpacked',
        args: { run_id: runId },
        result: packedDiff,
        artifactRefs: [packedDiffArtifact],
        metadata: {
          diff_type: packedDiff.diff_type,
        },
        provenance: {
          sources: ['upx.inspect', 'workflow.analyze.stage'],
        },
      })
    } else {
      unpackExecution = UnpackExecutionSchema.parse({
        execution_id: randomUUID(),
        sample_id: sampleId,
        packed_state: unpackPlan.packed_state,
        unpack_state: 'unpack_failed_recoverable',
        unpack_confidence: unpackPlan.unpack_confidence,
        selected_backend: 'upx.inspect',
        safe_execution_mode: 'decompress',
        approval_required: false,
        resumable: true,
        summary: 'UPX-backed unpack attempt did not produce a persisted unpacked binary.',
        failure_reason: 'UPX decompression returned no reusable artifact.',
        derived_artifacts: [],
        recommended_next_tools: ['workflow.analyze.promote', 'workflow.analyze.status', 'wine.run'],
        next_actions: [
          'Keep the run recoverable and continue through bounded debug planning or an approval-gated manual backend.',
        ],
      })
    }
  } else if (unpackPlan?.packed_state && unpackPlan.packed_state !== 'not_packed') {
    unpackExecution = UnpackExecutionSchema.parse({
      execution_id: randomUUID(),
      sample_id: sampleId,
      packed_state: unpackPlan.packed_state,
      unpack_state: executionPolicy.allowLiveExecution ? 'rebuild_required' : 'approval_gated',
      unpack_confidence: unpackPlan.unpack_confidence,
      selected_backend: 'planning_only',
      safe_execution_mode: 'none',
      approval_required: !executionPolicy.allowLiveExecution,
      resumable: true,
      summary:
        executionPolicy.allowLiveExecution
          ? 'Packed sample still requires guided memory dump or rebuild-oriented debugging.'
          : 'Packed sample remains approval-gated for live unpack or debug execution.',
      failure_reason: executionPolicy.allowLiveExecution ? null : 'approval_required',
      derived_artifacts: [],
      recommended_next_tools: ['workflow.analyze.status', 'workflow.analyze.promote', 'wine.run'],
      next_actions: [
        executionPolicy.allowLiveExecution
          ? 'Continue with session-aware dynamic capture or a manual debugger-backed dump path.'
          : 'Enable allow_live_execution on a future run before attempting live unpack or debugger-backed capture.',
      ],
    })
  }

  const sandboxResult = await context.dependencies.sandboxExecute!({
    sample_id: sampleId,
    mode: unpackPlan?.packed_state && unpackPlan.packed_state !== 'not_packed' ? 'memory_guided' : 'safe_simulation',
    approved: false,
    persist_artifact: true,
  })
  artifacts.push(...collectArtifactsFromResult(sandboxResult))
  const afterDynamicEvidence = await loadDynamicTraceEvidence(
    context.workspaceManager,
    context.database,
    sampleId,
    {
      evidenceScope: 'latest',
      sessionTag: undefined,
    }
  )
  const dynamicDiff = buildDynamicBehaviorDiffDigest({
    sampleId,
    diffType: 'pre_vs_post_dynamic',
    beforeSummary: beforeDynamicEvidence,
    afterSummary: afterDynamicEvidence,
    sourceArtifactRefs: dedupeArtifactRefsById([
      ...collectArtifactsFromResult(sandboxResult),
      ...artifacts,
    ]),
  })
  const dynamicDiffArtifact = await persistUnpackDebugJsonArtifact(
    context.workspaceManager,
    context.database,
    sampleId,
    ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE,
    'dynamic_behavior_diff',
    dynamicDiff,
    debugSessionTag
  )
  artifacts.push(dynamicDiffArtifact)
  diffDigests.push(dynamicDiff)

  const guidance = {
    recommended_next_tools:
      unpackedSampleId
        ? ['workflow.analyze.start', 'workflow.analyze.promote', 'workflow.summarize']
        : ['workflow.analyze.status', 'workflow.summarize', 'artifact.read'],
    next_actions:
      unpackedSampleId
        ? [
            'Use the unpacked sample_id for deeper function_map or reconstruct stages.',
            'Keep the original run for unpack/debug provenance and diff history.',
          ]
        : [
            'Consume the bounded dynamic diff digest and session artifact before escalating to manual live execution.',
            'Use workflow.analyze.status to inspect recoverable packed/debug state instead of replaying dynamic_execute blindly.',
          ],
    ...(executionPolicy.allowLiveExecution
      ? {}
      : {
          withheld_reasons: [
            'Live execution and debugger-backed backends remain approval-gated in this bounded dynamic execute stage.',
          ],
        }),
  }
  const debugSession = createOrReuseDebugSessionForRun(context.database, {
    runId,
    sample,
    status: afterDynamicEvidence ? 'correlated' : 'captured',
    debugState: afterDynamicEvidence ? 'correlated' : 'captured',
    backend: 'sandbox.execute',
    currentPhase: afterDynamicEvidence ? 'correlate' : 'capture',
    sessionTag: debugSessionTag,
    artifactRefs: dedupeArtifactRefsById(artifacts),
    guidance,
    metadata: {
      packed_state: unpackPlan?.packed_state || 'unknown',
      unpacked_sample_id: unpackedSampleId,
      unpack_strategy: unpackPlan?.strategy || null,
    },
  })
  const debugSessionArtifact = await persistUnpackDebugJsonArtifact(
    context.workspaceManager,
    context.database,
    sampleId,
    DEBUG_SESSION_ARTIFACT_TYPE,
    'debug_session_capture',
    debugSession,
    debugSessionTag
  )
  artifacts.push(debugSessionArtifact)
  persistCanonicalEvidence(context.database, {
    sample,
    evidenceFamily: 'debug_session',
    backend: 'runtime',
    mode: 'captured',
    args: { run_id: runId, phase: 'dynamic_execute' },
    result: debugSession,
    artifactRefs: dedupeArtifactRefsById([...artifacts, debugSessionArtifact]),
    metadata: {
      debug_state: debugSession.debug_state,
    },
    provenance: {
      sources: ['sandbox.execute', 'workflow.analyze.stage'],
    },
  })
  persistCanonicalEvidence(context.database, {
    sample,
    evidenceFamily: 'analysis_diff',
    backend: 'runtime',
    mode: 'pre_vs_post_dynamic',
    args: { run_id: runId },
    result: dynamicDiff,
    artifactRefs: [dynamicDiffArtifact],
    metadata: {
      diff_type: dynamicDiff.diff_type,
    },
    provenance: {
      sources: ['sandbox.execute', 'dynamic_trace_json'],
    },
  })

  const finalArtifacts = dedupeArtifactRefsById(artifacts)
  return {
    result: {
      stage: 'dynamic_execute',
      status:
        unpackExecution?.unpack_state === 'unpacked' || afterDynamicEvidence
          ? 'ready'
          : 'partial',
      execution_state:
        unpackExecution?.unpack_state === 'unpacked' || afterDynamicEvidence
          ? 'completed'
          : 'partial',
      summary:
        unpackedSampleId
          ? 'Dynamic execute completed a bounded unpack/debug pass, persisted an unpacked sample, and recorded compact pre/post diff artifacts.'
          : 'Dynamic execute remained bounded to safe simulation and persisted session-linked diff artifacts; live backends remain approval-gated.',
      packed_state: unpackPlan?.packed_state || 'unknown',
      unpack_state: unpackExecution?.unpack_state || unpackPlan?.unpack_state || 'not_started',
      unpack_confidence: unpackExecution?.unpack_confidence || unpackPlan?.unpack_confidence,
      ...(unpackPlan ? { unpack_plan: unpackPlan } : {}),
      ...(unpackExecution ? { unpack_execution: unpackExecution } : {}),
      debug_state: debugSession.debug_state,
      debug_session: debugSession,
      diff_digests: diffDigests,
      stage_outputs: {
        sandbox: sandboxResult.data || null,
        dynamic_diff: dynamicDiff,
      },
      recommended_next_tools: guidance.recommended_next_tools,
      next_actions: guidance.next_actions,
      artifact_refs: finalArtifacts,
    },
    artifacts: finalArtifacts,
  }
}

async function runSummarizeStage(
  context: StageExecutionContext,
  sampleId: string
): Promise<{ result: Record<string, unknown>; artifacts: ArtifactRef[] }> {
  const summarizeResult = await context.dependencies.workflowSummarize!({
    sample_id: sampleId,
    through_stage: 'final',
    synthesis_mode: 'deterministic',
  })
  const artifacts = collectArtifactsFromResult(summarizeResult)
  return {
    result: {
      stage: 'summarize',
      status: summarizeResult.ok ? 'ready' : 'partial',
      execution_state: summarizeResult.ok ? 'completed' : 'partial',
      summary:
        'Summary stage completed using the persisted staged summary workflow rather than rerunning earlier heavy analysis.',
      stage_outputs: {
        summarize: summarizeResult.data || null,
      },
      recommended_next_tools: ['artifact.read', 'report.summarize'],
      next_actions: [
        'Read the persisted summary artifacts when you need more detail than the compact synthesis payload.',
      ],
      artifact_refs: artifacts,
    },
    artifacts,
  }
}

export async function executeQueuedAnalysisStage(
  context: StageExecutionContext,
  input: {
    run_id: string
    stage: AnalysisPipelineStage
    force_refresh?: boolean
  }
): Promise<JobResult> {
  const startTime = Date.now()
  const run = context.database.findAnalysisRun(input.run_id)
  if (!run) {
    return {
      jobId: input.run_id,
      ok: false,
      errors: [`Analysis run not found: ${input.run_id}`],
      warnings: [],
      artifacts: [],
      metrics: { elapsedMs: Date.now() - startTime, peakRssMb: 0 },
    }
  }

  upsertAnalysisRunStage(context.database, {
    runId: run.id,
    stage: input.stage,
    status: 'running',
    executionState: 'queued',
    tool: ANALYSIS_STAGE_JOB_TOOL,
    startedAt: new Date().toISOString(),
    metadata: { force_refresh: Boolean(input.force_refresh) },
  })

  try {
    const runner = (() => {
      switch (input.stage) {
        case 'enrich_static':
          return runEnrichStaticStage(context, run.sample_id, Boolean(input.force_refresh))
        case 'function_map':
          return runFunctionMapStage(context, run.sample_id)
        case 'reconstruct':
          return runReconstructStage(context, run.sample_id)
        case 'dynamic_plan':
          return runDynamicPlanStage(context, run.id, run.sample_id)
        case 'dynamic_execute':
          return runDynamicExecuteStage(context, run.id, run.sample_id)
        case 'summarize':
          return runSummarizeStage(context, run.sample_id)
        case 'fast_profile':
        default:
          return buildFastProfileStage(
            context,
            run.id,
            context.database.findSample(run.sample_id)!,
            {
              sample_id: run.sample_id,
              goal: run.goal as z.infer<typeof AnalysisIntentGoalSchema>,
              depth: run.depth as z.infer<typeof AnalysisIntentDepthSchema>,
              backend_policy: run.backend_policy as z.infer<typeof BackendPolicySchema>,
              allow_transformations: false,
              allow_live_execution: false,
              force_refresh: Boolean(input.force_refresh),
            }
          )
      }
    })()

    const stageOutput = await runner
    appendAnalysisRunArtifactRefs(context.database, run.id, stageOutput.artifacts)
    upsertAnalysisRunStage(context.database, {
      runId: run.id,
      stage: input.stage,
      status: 'completed',
      executionState: 'completed',
      tool: ANALYSIS_STAGE_JOB_TOOL,
      result: stageOutput.result,
      artifactRefs: stageOutput.artifacts,
      finishedAt: new Date().toISOString(),
    })

    return {
      jobId: run.id,
      ok: true,
      data: stageOutput.result,
      errors: [],
      warnings: [],
      artifacts: stageOutput.artifacts,
      metrics: { elapsedMs: Date.now() - startTime, peakRssMb: 0 },
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    const memoryRelated = /oom|out of memory|memory|allocation|killed/i.test(message)
    upsertAnalysisRunStage(context.database, {
      runId: run.id,
      stage: input.stage,
      status: memoryRelated ? 'recoverable' : 'failed',
      executionState: 'partial',
      tool: ANALYSIS_STAGE_JOB_TOOL,
      result: { error: message },
      metadata: memoryRelated
        ? {
            recovery_state: 'recoverable',
            recovery_reason:
              'The queued stage stopped under memory pressure. Re-promote it after headroom recovers or continue from earlier bounded artifacts.',
            interruption_cause: 'memory_pressure',
          }
        : {
            interruption_cause: 'tool_error',
          },
      finishedAt: new Date().toISOString(),
    })
    return {
      jobId: run.id,
      ok: false,
      data: undefined,
      errors: [message],
      warnings: [],
      artifacts: [],
      metrics: { elapsedMs: Date.now() - startTime, peakRssMb: 0 },
    }
  }
}

function buildRunEnvelope(
  runSummary: z.infer<typeof AnalysisRunSummarySchema>,
  stageResult: unknown,
  coverage: z.infer<typeof CoverageEnvelopeSchema>,
  routing: z.infer<typeof BackendRoutingMetadataSchema>,
  reused: boolean,
  executionState: 'inline' | 'queued' | 'reused' | 'partial' | 'completed'
) {
  const evidenceState = uniqueEvidenceStates(
    collectEvidenceStatesFromPayload([
      stageResult,
      ...runSummary.stages.map((stage) => stage.result),
    ])
  )
  const provenanceVisibility = buildProvenanceVisibility(
    runSummary,
    routing,
    coverage,
    evidenceState
  )
  const unpackDebugEnvelope = extractUnpackDebugEnvelope(stageResult, runSummary)
  const runtimeExplanationGraph = buildRuntimeStageExplanationGraph({
    sample_id: runSummary.sample_id,
    completed_stages: runSummary.stages
      .filter((stage) => stage.status === 'completed')
      .map((stage) => stage.stage),
    deferred_requirements: runSummary.recoverable_stages
      .filter((stage) => typeof stage.reason === 'string')
      .map((stage) => stage.reason),
    recoverable_stages: runSummary.recoverable_stages.reduce<
      Array<{ stage: string; reason: string }>
    >((acc, stage) => {
      if (
        stage &&
        typeof stage.stage === 'string' &&
        typeof stage.reason === 'string'
      ) {
        acc.push({
          stage: stage.stage,
          reason: stage.reason,
        })
      }
      return acc
    }, []),
    recommended_next_tools:
      executionState === 'queued'
        ? ['workflow.analyze.status', 'workflow.analyze.promote']
        : ['workflow.analyze.promote', 'workflow.analyze.status'],
    stage_plan: runSummary.stage_plan,
    coverage_gaps: (coverage.coverage_gaps || []).reduce<
      Array<{ domain: string; status: string; reason: string }>
    >((acc, gap) => {
      if (
        gap &&
        typeof gap.domain === 'string' &&
        typeof gap.status === 'string' &&
        typeof gap.reason === 'string'
      ) {
        acc.push({
          domain: gap.domain,
          status: gap.status,
          reason: gap.reason,
        })
      }
      return acc
    }, []),
  })
  const queuedPreferredTools =
    unpackDebugEnvelope.packed_state && unpackDebugEnvelope.packed_state !== 'not_packed'
      ? ['workflow.analyze.status', 'workflow.analyze.promote', 'upx.inspect']
      : ['workflow.analyze.status', 'task.status']
  const completedPreferredTools =
    unpackDebugEnvelope.packed_state && unpackDebugEnvelope.packed_state !== 'not_packed'
      ? ['workflow.analyze.promote', 'workflow.analyze.status', 'workflow.summarize']
      : ['workflow.analyze.promote', 'workflow.analyze.status']
  const queuedNextActions =
    unpackDebugEnvelope.packed_state && unpackDebugEnvelope.packed_state !== 'not_packed'
      ? ['Use workflow.analyze.status to monitor unpack/debug progression instead of repeating the same start or promote call.']
      : ['Use workflow.analyze.status to monitor the persisted run instead of repeating the same start call.']
  const completedNextActions =
    unpackDebugEnvelope.packed_state && unpackDebugEnvelope.packed_state !== 'not_packed'
      ? ['Promote the persisted run through unpack/debug-aware stages before assuming the original packed binary is ready for deep reconstruction.']
      : ['Promote the persisted run instead of repeating fast-profile analysis when you need deeper stages.']
  return mergeRoutingMetadata(
    mergeCoverageEnvelope(
      {
        run_id: runSummary.run_id,
        reused,
        execution_state: executionState,
        current_stage: (runSummary.latest_stage || FAST_PROFILE_STAGE) as AnalysisPipelineStage,
        // Strip raw_results from historical stage results to keep response
        // within LLM token budgets. The current stage_result (below) retains
        // its own raw_results so the caller still gets full detail for the
        // most recent stage.
        run: {
          ...runSummary,
          stages: runSummary.stages.map((stage) => {
            if (
              stage.result &&
              typeof stage.result === 'object' &&
              !Array.isArray(stage.result) &&
              'raw_results' in (stage.result as Record<string, unknown>)
            ) {
              const { raw_results: _stripped, ...rest } = stage.result as Record<string, unknown>
              return { ...stage, result: rest }
            }
            return stage
          }),
        },
        recovery_state: runSummary.recovery_state,
        recoverable_stages: runSummary.recoverable_stages,
        stage_result: stageResult,
        evidence_state: evidenceState.length > 0 ? evidenceState : undefined,
        provenance_visibility: provenanceVisibility,
        runtime_explanation_graph: ExplanationGraphDigestSchema.parse(runtimeExplanationGraph),
        deferred_jobs: runSummary.deferred_jobs,
        ...unpackDebugEnvelope,
        recommended_next_tools:
          executionState === 'queued'
            ? queuedPreferredTools
            : completedPreferredTools,
        next_actions:
          executionState === 'queued'
            ? queuedNextActions
            : completedNextActions,
      },
      coverage
    ),
    routing
  )
}

function queueStage(
  database: DatabaseManager,
  jobQueue: JobQueue,
  runId: string,
  stage: AnalysisPipelineStage,
  sampleId: string,
  forceRefresh: boolean
) {
  const timeout =
    stage === 'enrich_static'
      ? ENRICH_STAGE_TIMEOUT_MS
      : stage === 'function_map'
        ? FUNCTION_MAP_TIMEOUT_MS
        : stage === 'reconstruct'
          ? RECONSTRUCT_TIMEOUT_MS
          : stage === 'summarize'
            ? SUMMARIZE_TIMEOUT_MS
            : stage === 'fast_profile'
              ? FAST_PROFILE_TIMEOUT_MS
              : DYNAMIC_PLAN_TIMEOUT_MS

  const jobId = jobQueue.enqueue({
    type: stage === 'function_map' || stage === 'reconstruct' ? 'decompile' : 'static',
    tool: ANALYSIS_STAGE_JOB_TOOL,
    sampleId,
    args: {
      run_id: runId,
      stage,
      force_refresh: forceRefresh,
      sample_size_tier:
        database.findAnalysisRun(runId)?.sample_size_tier || null,
    },
    priority:
      stage === 'function_map' || stage === 'reconstruct'
        ? JobPriority.HIGH
        : JobPriority.NORMAL,
    timeout,
  })

  const executionPlan = buildSchedulerExecutionPlan({
    tool: ANALYSIS_STAGE_JOB_TOOL,
    args: {
      stage,
      sample_size_tier: database.findAnalysisRun(runId)?.sample_size_tier || null,
    },
  })

  upsertAnalysisRunStage(database, {
    runId,
    stage,
    status: 'queued',
    executionState: 'queued',
    tool: ANALYSIS_STAGE_JOB_TOOL,
    jobId,
    metadata: {
      timeout_ms: timeout,
      execution_bucket: executionPlan.execution_bucket,
      cost_class: executionPlan.cost_class,
      worker_family: executionPlan.worker_family,
    },
  })
  return jobId
}

export function createAnalyzeWorkflowStartHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  policyGuard: PolicyGuard,
  server?: MCPServer,
  dependencies: AnalyzePipelineDependencies = {},
  jobQueue?: JobQueue
) {
  const deps = createDependencies(
    workspaceManager,
    database,
    cacheManager,
    policyGuard,
    server,
    dependencies,
    jobQueue
  )
  const stageContext: StageExecutionContext = {
    workspaceManager,
    database,
    cacheManager,
    policyGuard,
    server,
    dependencies: deps,
  }

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = analyzeStartInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME_START },
        }
      }

      const runState = createOrReuseAnalysisRun(database, {
        sample,
        goal: input.goal,
        depth: input.depth,
        backendPolicy: input.backend_policy,
        forceRefresh: input.force_refresh,
        metadata: {
          allow_transformations: input.allow_transformations,
          allow_live_execution: input.allow_live_execution,
        },
      })

      const existingFastProfile = database.findAnalysisRunStage(runState.run.id, FAST_PROFILE_STAGE)
      let stageResult: unknown = existingFastProfile
        ? JSON.parse(existingFastProfile.result_json || 'null')
        : null
      let artifacts: ArtifactRef[] = existingFastProfile
        ? JSON.parse(existingFastProfile.artifact_refs_json || '[]')
        : []

      if (!existingFastProfile || input.force_refresh) {
        const built = await buildFastProfileStage(stageContext, runState.run.id, sample, input)
        stageResult = built.result
        artifacts = built.artifacts
        appendAnalysisRunArtifactRefs(database, runState.run.id, artifacts)
        upsertAnalysisRunStage(database, {
          runId: runState.run.id,
          stage: FAST_PROFILE_STAGE,
          status: 'completed',
          executionState: 'completed',
          tool: TOOL_NAME_START,
          result: stageResult,
          artifactRefs: artifacts,
          startedAt: new Date(startTime).toISOString(),
          finishedAt: new Date().toISOString(),
        })
      } else {
        upsertAnalysisRunStage(database, {
          runId: runState.run.id,
          stage: FAST_PROFILE_STAGE,
          status: 'completed',
          executionState: 'reused',
          tool: TOOL_NAME_START,
          result: stageResult,
          artifactRefs: artifacts,
          finishedAt: new Date().toISOString(),
        })
      }

      const runSummary = getAnalysisRunSummary(database, runState.run.id, jobQueue)
      if (!runSummary) {
        throw new Error(`Failed to load persisted analysis run ${runState.run.id}`)
      }
      const coverage =
        stageResult && typeof stageResult === 'object'
          ? CoverageEnvelopeSchema.parse(stageResult)
          : buildCoverageForRun(sample, input.depth, 'bounded', [])
      const routing =
        stageResult && typeof stageResult === 'object'
          ? BackendRoutingMetadataSchema.parse(stageResult)
          : buildIntentBackendPlan({
              goal: input.goal,
              depth: input.depth,
              backendPolicy: input.backend_policy,
              allowTransformations: input.allow_transformations,
              allowLiveExecution: input.allow_live_execution,
              readiness: deps.resolveBackends!(),
            })

      return {
        ok: true,
        data: buildRunEnvelope(
          runSummary,
          stageResult,
          coverage,
          routing,
          runState.reused,
          runState.reused ? 'reused' : 'completed'
        ),
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME_START },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME_START },
      }
    }
  }
}

export function createAnalyzeWorkflowStatusHandler(
  database: DatabaseManager,
  dependencies: Pick<AnalyzePipelineDependencies, 'resolveBackends'> = {},
  jobQueue?: JobQueue
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = analyzeStatusInputSchema.parse(args)
      const runSummary = getAnalysisRunSummary(database, input.run_id, jobQueue)
      if (!runSummary) {
        return {
          ok: false,
          errors: [`Analysis run not found: ${input.run_id}`],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME_STATUS },
        }
      }
      const run = database.findAnalysisRun(input.run_id)!
      const sample = database.findSample(run.sample_id)!
      const coverage = buildCoverageForRun(
        sample,
        run.depth as z.infer<typeof AnalysisIntentDepthSchema>,
        runSummary.deferred_jobs.length > 0
          ? 'queued'
          : runSummary.recovery_state !== 'none'
            ? 'partial'
            : runSummary.status === 'completed'
              ? 'completed'
            : 'partial',
        runSummary.recoverable_stages.map((stage) => ({
          domain: stage.stage,
          status: 'degraded' as const,
          reason: stage.reason,
        }))
      )
      const unpackDebugEnvelope = extractUnpackDebugEnvelope(
        runSummary.stages.find((stage) => stage.stage === (runSummary.latest_stage || FAST_PROFILE_STAGE))?.result,
        runSummary
      )
      const routing = buildIntentBackendPlan({
        goal: run.goal as z.infer<typeof AnalysisIntentGoalSchema>,
        depth: run.depth as z.infer<typeof AnalysisIntentDepthSchema>,
        backendPolicy: run.backend_policy as z.infer<typeof BackendPolicySchema>,
        readiness: (dependencies.resolveBackends || resolveAnalysisBackends)(),
        signals: {
          large_sample_preview:
            classifySampleSizeTier(sample.size) === 'large' ||
            classifySampleSizeTier(sample.size) === 'oversized',
          packer_suspected:
            unpackDebugEnvelope.packed_state === 'suspected_packed' ||
            unpackDebugEnvelope.packed_state === 'confirmed_packed',
          packed_confirmed: unpackDebugEnvelope.packed_state === 'confirmed_packed',
          debug_requested:
            unpackDebugEnvelope.debug_state !== undefined &&
            unpackDebugEnvelope.debug_state !== 'not_requested',
        },
      })

      return {
        ok: true,
        data: buildRunEnvelope(
          runSummary,
          runSummary.stages.find((stage) => stage.stage === (runSummary.latest_stage || FAST_PROFILE_STAGE))?.result,
          coverage,
          routing,
          runSummary.reused,
          runSummary.deferred_jobs.length > 0
            ? 'queued'
            : runSummary.recovery_state !== 'none'
              ? 'partial'
              : 'completed'
        ),
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME_STATUS },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME_STATUS },
      }
    }
  }
}

export function createAnalyzeWorkflowPromoteHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  policyGuard: PolicyGuard,
  server?: MCPServer,
  dependencies: AnalyzePipelineDependencies = {},
  jobQueue?: JobQueue
) {
  const deps = createDependencies(
    workspaceManager,
    database,
    cacheManager,
    policyGuard,
    server,
    dependencies,
    jobQueue
  )
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = analyzePromoteInputSchema.parse(args)
      const run = database.findAnalysisRun(input.run_id)
      if (!run) {
        return {
          ok: false,
          errors: [`Analysis run not found: ${input.run_id}`],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME_PROMOTE },
        }
      }
      if (!jobQueue) {
        return {
          ok: false,
          errors: ['Job queue is not available; queued stage promotion is disabled in this environment.'],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME_PROMOTE },
        }
      }

      const stagePlan = buildStagePlan(run.goal as z.infer<typeof AnalysisIntentGoalSchema>)
      const targetStages = input.stages?.length
        ? input.stages
        : input.through_stage
          ? stagePlan.slice(0, stagePlan.indexOf(input.through_stage) + 1)
          : [stagePlan[Math.min(stagePlan.length - 1, 1)]]

      const queuedStages: string[] = []
      for (const stage of targetStages) {
        if (stage === FAST_PROFILE_STAGE) {
          continue
        }
        const existing = database.findAnalysisRunStage(run.id, stage)
        if (!input.force_refresh && existing && (existing.status === 'completed' || existing.status === 'queued' || existing.status === 'running')) {
          continue
        }
        queueStage(database, jobQueue, run.id, stage, run.sample_id, input.force_refresh)
        queuedStages.push(stage)
      }

      const runSummary = getAnalysisRunSummary(database, run.id, jobQueue)
      if (!runSummary) {
        throw new Error(`Failed to load persisted analysis run ${run.id}`)
      }
      const sample = database.findSample(run.sample_id)!
      const coverage = buildCoverageForRun(
        sample,
        run.depth as z.infer<typeof AnalysisIntentDepthSchema>,
        'queued',
        queuedStages.map((stage) => ({
          domain: stage,
          status: 'queued' as const,
          reason: `${stage} was queued as a promoted stage for this persisted run.`,
        }))
      )
      const unpackDebugEnvelope = extractUnpackDebugEnvelope(
        runSummary.stages.find((stage) => stage.stage === (runSummary.latest_stage || FAST_PROFILE_STAGE))?.result,
        runSummary
      )
      const routing = buildIntentBackendPlan({
        goal: run.goal as z.infer<typeof AnalysisIntentGoalSchema>,
        depth: run.depth as z.infer<typeof AnalysisIntentDepthSchema>,
        backendPolicy: run.backend_policy as z.infer<typeof BackendPolicySchema>,
        readiness: deps.resolveBackends!(),
        signals: {
          large_sample_preview:
            classifySampleSizeTier(sample.size) === 'large' ||
            classifySampleSizeTier(sample.size) === 'oversized',
          packer_suspected:
            unpackDebugEnvelope.packed_state === 'suspected_packed' ||
            unpackDebugEnvelope.packed_state === 'confirmed_packed',
          packed_confirmed: unpackDebugEnvelope.packed_state === 'confirmed_packed',
          debug_requested:
            unpackDebugEnvelope.debug_state !== undefined &&
            unpackDebugEnvelope.debug_state !== 'not_requested',
        },
      })

      return {
        ok: true,
        data: buildRunEnvelope(
          runSummary,
          {
            queued_stages: queuedStages,
            polling_guidance: buildPollingGuidance({
              tool: ANALYSIS_STAGE_JOB_TOOL,
              status: 'queued',
              timeout_ms: RECONSTRUCT_TIMEOUT_MS,
            }),
          },
          coverage,
          routing,
          runSummary.reused,
          'queued'
        ),
        warnings:
          queuedStages.length === 0
            ? ['Requested stages were already completed or queued; reused existing persisted run state.']
            : undefined,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME_PROMOTE },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME_PROMOTE },
      }
    }
  }
}

export function createAnalyzePipelineStageContext(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  policyGuard: PolicyGuard,
  server?: MCPServer,
  dependencies: AnalyzePipelineDependencies = {},
  jobQueue?: JobQueue
): StageExecutionContext {
  return {
    workspaceManager,
    database,
    cacheManager,
    policyGuard,
    server,
    dependencies: createDependencies(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      server,
      dependencies,
      jobQueue
    ),
  }
}
