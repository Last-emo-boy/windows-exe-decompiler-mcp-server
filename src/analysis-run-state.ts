import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type {
  AnalysisRun,
  AnalysisRunStage,
  DatabaseManager,
  Sample,
} from './database.js'
import {
  type AnalysisBudgetProfile,
  AnalysisBudgetProfileSchema,
  classifySampleSizeTier,
  type SampleSizeTier,
  SampleSizeTierSchema,
  deriveAnalysisBudgetProfile,
} from './analysis-coverage.js'
import type { ArtifactRef } from './types.js'
import type { JobQueue } from './job-queue.js'
import type {
  AnalysisIntentDepth,
  AnalysisIntentGoal,
  BackendPolicy,
} from './intent-routing.js'
import {
  AnalysisCostClassSchema,
  ExecutionBucketSchema,
} from './analysis-budget-scheduler.js'

export const ANALYSIS_PIPELINE_VERSION = 'nonblocking-unified-analysis-pipeline-v1'

export const AnalysisPipelineStageSchema = z.enum([
  'fast_profile',
  'enrich_static',
  'function_map',
  'reconstruct',
  'dynamic_plan',
  'dynamic_execute',
  'summarize',
])

export const AnalysisRunStatusSchema = z.enum([
  'created',
  'running',
  'queued',
  'partial',
  'recoverable',
  'completed',
  'failed',
])

export const AnalysisStageStatusSchema = z.enum([
  'pending',
  'queued',
  'running',
  'partial',
  'interrupted',
  'recoverable',
  'completed',
  'failed',
  'skipped',
])

export const AnalysisExecutionStateSchema = z.enum([
  'inline',
  'queued',
  'reused',
  'partial',
  'completed',
])

export const AnalysisRecoveryStateSchema = z.enum([
  'none',
  'interrupted',
  'recoverable',
])

export const DeferredJobSchema = z.object({
  stage: AnalysisPipelineStageSchema,
  job_id: z.string(),
  status: z.string(),
  progress: z.number().min(0).max(100).optional(),
  tool: z.string().nullable().optional(),
  execution_bucket: ExecutionBucketSchema.nullable().optional(),
  cost_class: AnalysisCostClassSchema.nullable().optional(),
  worker_family: z.string().nullable().optional(),
  budget_deferral_reason: z.string().nullable().optional(),
  warm_reuse: z.boolean().optional(),
  cold_start: z.boolean().optional(),
  expected_rss_mb: z.number().nullable().optional(),
  current_rss_mb: z.number().nullable().optional(),
  peak_rss_mb: z.number().nullable().optional(),
  memory_limit_mb: z.number().nullable().optional(),
  control_plane_headroom_mb: z.number().nullable().optional(),
  active_expected_rss_mb: z.number().nullable().optional(),
  latency_ms: z.number().nullable().optional(),
  interruption_cause: z.string().nullable().optional(),
})

export const AnalysisRunStageViewSchema = z.object({
  stage: AnalysisPipelineStageSchema,
  status: AnalysisStageStatusSchema,
  execution_state: AnalysisExecutionStateSchema.nullable().optional(),
  recovery_state: AnalysisRecoveryStateSchema.default('none'),
  recovery_reason: z.string().nullable().optional(),
  tool: z.string().nullable().optional(),
  job_id: z.string().nullable().optional(),
  execution_bucket: ExecutionBucketSchema.nullable().optional(),
  cost_class: AnalysisCostClassSchema.nullable().optional(),
  worker_family: z.string().nullable().optional(),
  budget_deferral_reason: z.string().nullable().optional(),
  scheduler_decision: z.string().nullable().optional(),
  warm_reuse: z.boolean().optional(),
  cold_start: z.boolean().optional(),
  expected_rss_mb: z.number().nullable().optional(),
  current_rss_mb: z.number().nullable().optional(),
  peak_rss_mb: z.number().nullable().optional(),
  memory_limit_mb: z.number().nullable().optional(),
  control_plane_headroom_mb: z.number().nullable().optional(),
  active_expected_rss_mb: z.number().nullable().optional(),
  latency_ms: z.number().nullable().optional(),
  interruption_cause: z.string().nullable().optional(),
  updated_at: z.string(),
  started_at: z.string().nullable().optional(),
  finished_at: z.string().nullable().optional(),
  artifact_refs: z.array(z.any()),
  result: z.any().optional(),
  metadata: z.record(z.any()).optional(),
})

export const RecoverableStageSchema = z.object({
  stage: AnalysisPipelineStageSchema,
  status: AnalysisStageStatusSchema,
  recovery_state: AnalysisRecoveryStateSchema,
  reason: z.string(),
  job_id: z.string().nullable().optional(),
})

export const AnalysisRunSummarySchema = z.object({
  run_id: z.string(),
  sample_id: z.string(),
  sample_sha256: z.string(),
  goal: z.string(),
  depth: z.string(),
  backend_policy: z.string(),
  pipeline_version: z.string(),
  compatibility_marker: z.string(),
  status: AnalysisRunStatusSchema,
  sample_size_tier: SampleSizeTierSchema,
  analysis_budget_profile: AnalysisBudgetProfileSchema,
  latest_stage: z.string().nullable(),
  reused: z.boolean(),
  created_at: z.string(),
  updated_at: z.string(),
  finished_at: z.string().nullable(),
  artifact_refs: z.array(z.any()),
  stage_plan: z.array(AnalysisPipelineStageSchema),
  stages: z.array(AnalysisRunStageViewSchema),
  deferred_jobs: z.array(DeferredJobSchema),
  recovery_state: AnalysisRecoveryStateSchema.default('none'),
  recoverable_stages: z.array(RecoverableStageSchema),
})

export type AnalysisPipelineStage = z.infer<typeof AnalysisPipelineStageSchema>
export type AnalysisRunStatus = z.infer<typeof AnalysisRunStatusSchema>
export type AnalysisStageStatus = z.infer<typeof AnalysisStageStatusSchema>
export type AnalysisExecutionState = z.infer<typeof AnalysisExecutionStateSchema>
export type AnalysisRecoveryState = z.infer<typeof AnalysisRecoveryStateSchema>
export type AnalysisRunSummary = z.infer<typeof AnalysisRunSummarySchema>

export interface CreateOrReuseAnalysisRunOptions {
  sample: Sample
  goal: AnalysisIntentGoal
  depth: AnalysisIntentDepth
  backendPolicy: BackendPolicy
  forceRefresh?: boolean
  metadata?: Record<string, unknown>
  stagePlan?: AnalysisPipelineStage[]
}

export interface UpsertAnalysisRunStageOptions {
  runId: string
  stage: AnalysisPipelineStage
  status: AnalysisStageStatus
  executionState?: AnalysisExecutionState | null
  tool?: string | null
  jobId?: string | null
  result?: unknown
  artifactRefs?: ArtifactRef[]
  coverage?: unknown
  metadata?: Record<string, unknown>
  startedAt?: string | null
  finishedAt?: string | null
}

function nowIso() {
  return new Date().toISOString()
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

function extractRecoveryState(metadata: Record<string, unknown>, rowStatus: string): AnalysisRecoveryState {
  if (rowStatus === 'interrupted') {
    return 'interrupted'
  }
  if (rowStatus === 'recoverable') {
    return 'recoverable'
  }
  if (metadata.recovery_state === 'interrupted' || metadata.recovery_state === 'recoverable') {
    return metadata.recovery_state
  }
  return 'none'
}

function parseSchedulerMetadata(event: { metadata_json?: string | null } | null): Record<string, unknown> {
  return parseJsonRecord<Record<string, unknown>>(event?.metadata_json, {})
}

function dedupeArtifactRefs(artifactRefs: ArtifactRef[]): ArtifactRef[] {
  const seen = new Set<string>()
  const result: ArtifactRef[] = []
  for (const artifact of artifactRefs) {
    const key = artifact.id || `${artifact.type}:${artifact.path}`
    if (seen.has(key)) {
      continue
    }
    seen.add(key)
    result.push(artifact)
  }
  return result
}

export function buildAnalysisRunCompatibilityMarker(input: {
  sampleSha256: string
  goal: AnalysisIntentGoal
  depth: AnalysisIntentDepth
  backendPolicy: BackendPolicy
  pipelineVersion?: string
}): string {
  const payload = JSON.stringify({
    sample_sha256: input.sampleSha256,
    goal: input.goal,
    depth: input.depth,
    backend_policy: input.backendPolicy,
    pipeline_version: input.pipelineVersion || ANALYSIS_PIPELINE_VERSION,
  })
  return createHash('sha256').update(payload).digest('hex')
}

export function buildStagePlan(goal: AnalysisIntentGoal): AnalysisPipelineStage[] {
  switch (goal) {
    case 'triage':
      return ['fast_profile', 'enrich_static', 'function_map', 'summarize']
    case 'static':
      return ['fast_profile', 'enrich_static', 'function_map', 'summarize']
    case 'reverse':
      return ['fast_profile', 'enrich_static', 'function_map', 'reconstruct', 'summarize']
    case 'dynamic':
      return ['fast_profile', 'dynamic_plan', 'dynamic_execute', 'summarize']
    case 'report':
      return ['fast_profile', 'enrich_static', 'function_map', 'reconstruct', 'summarize']
  }
}

function initialRunStatus(stagePlan: AnalysisPipelineStage[]): AnalysisRunStatus {
  return stagePlan.length > 1 ? 'partial' : 'created'
}

export function createOrReuseAnalysisRun(
  database: DatabaseManager,
  options: CreateOrReuseAnalysisRunOptions
): {
  run: AnalysisRun
  reused: boolean
  sampleSizeTier: SampleSizeTier
  analysisBudgetProfile: AnalysisBudgetProfile
  compatibilityMarker: string
  stagePlan: AnalysisPipelineStage[]
} {
  const sampleSizeTier = classifySampleSizeTier(options.sample.size)
  const analysisBudgetProfile = deriveAnalysisBudgetProfile(options.depth, sampleSizeTier)
  const stagePlan = options.stagePlan || buildStagePlan(options.goal)
  const compatibilityMarker = buildAnalysisRunCompatibilityMarker({
    sampleSha256: options.sample.sha256,
    goal: options.goal,
    depth: options.depth,
    backendPolicy: options.backendPolicy,
  })

  if (!options.forceRefresh) {
    const existing = database.findLatestCompatibleAnalysisRun(
      options.sample.id,
      compatibilityMarker
    )
    if (existing) {
      database.updateAnalysisRun(existing.id, {
        last_accessed_at: nowIso(),
      })
      return {
        run: {
          ...existing,
          last_accessed_at: nowIso(),
        },
        reused: true,
        sampleSizeTier,
        analysisBudgetProfile,
        compatibilityMarker,
        stagePlan: parseJsonRecord<AnalysisPipelineStage[]>(
          existing.stage_plan_json,
          stagePlan
        ),
      }
    }
  }

  const createdAt = nowIso()
  const run: AnalysisRun = {
    id: randomUUID(),
    sample_id: options.sample.id,
    sample_sha256: options.sample.sha256,
    goal: options.goal,
    depth: options.depth,
    backend_policy: options.backendPolicy,
    compatibility_marker: compatibilityMarker,
    pipeline_version: ANALYSIS_PIPELINE_VERSION,
    sample_size_tier: sampleSizeTier,
    analysis_budget_profile: analysisBudgetProfile,
    status: initialRunStatus(stagePlan),
    latest_stage: null,
    stage_plan_json: JSON.stringify(stagePlan),
    artifact_refs_json: JSON.stringify([]),
    metadata_json: JSON.stringify(options.metadata || {}),
    created_at: createdAt,
    updated_at: createdAt,
    finished_at: null,
    reused_from_run_id: null,
    last_accessed_at: createdAt,
  }
  database.insertAnalysisRun(run)

  return {
    run,
    reused: false,
    sampleSizeTier,
    analysisBudgetProfile,
    compatibilityMarker,
    stagePlan,
  }
}

export function parseRunArtifactRefs(run: AnalysisRun): ArtifactRef[] {
  return parseJsonRecord<ArtifactRef[]>(run.artifact_refs_json, [])
}

export function appendAnalysisRunArtifactRefs(
  database: DatabaseManager,
  runId: string,
  artifactRefs: ArtifactRef[]
): ArtifactRef[] {
  const run = database.findAnalysisRun(runId)
  if (!run) {
    return artifactRefs
  }
  const merged = dedupeArtifactRefs([...parseRunArtifactRefs(run), ...artifactRefs])
  database.updateAnalysisRun(runId, {
    artifact_refs_json: JSON.stringify(merged),
    updated_at: nowIso(),
  })
  return merged
}

export function upsertAnalysisRunStage(
  database: DatabaseManager,
  options: UpsertAnalysisRunStageOptions
): AnalysisRunStage {
  const existing = database.findAnalysisRunStage(options.runId, options.stage)
  const createdAt = existing?.created_at || nowIso()
  const updatedAt = nowIso()
  const stage: AnalysisRunStage = {
    run_id: options.runId,
    stage: options.stage,
    status: options.status,
    execution_state: options.executionState || null,
    tool: options.tool || null,
    job_id: options.jobId || null,
    result_json:
      options.result !== undefined
        ? JSON.stringify(options.result)
        : existing?.result_json || null,
    artifact_refs_json: JSON.stringify(options.artifactRefs || parseJsonRecord(existing?.artifact_refs_json, [])),
    coverage_json:
      options.coverage !== undefined
        ? JSON.stringify(options.coverage)
        : existing?.coverage_json || null,
    metadata_json:
      options.metadata !== undefined
        ? JSON.stringify(options.metadata)
        : existing?.metadata_json || null,
    created_at: createdAt,
    updated_at: updatedAt,
    started_at:
      options.startedAt !== undefined
        ? options.startedAt
        : existing?.started_at || null,
    finished_at:
      options.finishedAt !== undefined
        ? options.finishedAt
        : existing?.finished_at || null,
  }
  database.upsertAnalysisRunStage(stage)

  const finishedAt = stage.status === 'completed' || stage.status === 'failed' ? updatedAt : null
  database.updateAnalysisRun(options.runId, {
    latest_stage: options.stage,
    status:
      stage.status === 'failed'
        ? 'failed'
        : stage.status === 'interrupted' || stage.status === 'recoverable'
          ? 'recoverable'
        : stage.status === 'completed'
          ? 'running'
          : stage.status === 'queued'
            ? 'queued'
            : 'partial',
    updated_at: updatedAt,
    finished_at: finishedAt,
  })

  const artifactRefs = parseJsonRecord<ArtifactRef[]>(stage.artifact_refs_json, [])
  if (artifactRefs.length > 0) {
    appendAnalysisRunArtifactRefs(database, options.runId, artifactRefs)
  }

  return stage
}

function toStageView(
  row: AnalysisRunStage,
  database: DatabaseManager,
  jobQueue?: JobQueue
): z.infer<typeof AnalysisRunStageViewSchema> {
  const artifactRefs = parseJsonRecord<ArtifactRef[]>(row.artifact_refs_json, [])
  const metadata = parseJsonRecord<Record<string, unknown>>(row.metadata_json, {})
  const jobStatus = row.job_id ? jobQueue?.getStatus(row.job_id) : undefined
  const schedulerEvent = row.job_id ? database.findLatestSchedulerEventForJob(row.job_id) : null
  const schedulerMetadata = parseSchedulerMetadata(schedulerEvent)
  const status = (
    row.status === 'interrupted' || row.status === 'recoverable'
      ? row.status
      : jobStatus?.status || row.status
  ) as AnalysisStageStatus
  const memoryDeferred =
    schedulerEvent?.decision === 'deferred' &&
    typeof schedulerEvent.reason === 'string' &&
    schedulerEvent.reason.includes('memory_headroom_guard')
  const recoveryState =
    memoryDeferred && status === 'queued'
      ? 'recoverable'
      : extractRecoveryState(metadata, status)
  return {
    stage: row.stage as AnalysisPipelineStage,
    status,
    execution_state: (row.execution_state || null) as AnalysisExecutionState | null,
    recovery_state: recoveryState,
    recovery_reason:
      typeof metadata.recovery_reason === 'string'
        ? metadata.recovery_reason
        : memoryDeferred
          ? 'Stage admission was deferred to preserve control-plane memory headroom; retry after earlier heavy work finishes or promote later.'
          : null,
    tool: row.tool,
    job_id: row.job_id,
    execution_bucket: (schedulerEvent?.execution_bucket || null) as
      | z.infer<typeof ExecutionBucketSchema>
      | null,
    cost_class: (schedulerEvent?.cost_class || null) as
      | z.infer<typeof AnalysisCostClassSchema>
      | null,
    worker_family: schedulerEvent?.worker_family || null,
    budget_deferral_reason: schedulerEvent?.decision === 'deferred' ? schedulerEvent.reason : null,
    scheduler_decision: schedulerEvent?.decision || null,
    warm_reuse:
      typeof schedulerEvent?.warm_reuse === 'number'
        ? schedulerEvent.warm_reuse === 1
        : undefined,
    cold_start:
      typeof schedulerEvent?.cold_start === 'number'
        ? schedulerEvent.cold_start === 1
        : undefined,
    expected_rss_mb:
      typeof schedulerMetadata.expected_rss_mb === 'number'
        ? schedulerMetadata.expected_rss_mb
        : null,
    current_rss_mb:
      typeof schedulerMetadata.current_rss_mb === 'number'
        ? schedulerMetadata.current_rss_mb
        : null,
    peak_rss_mb:
      typeof schedulerMetadata.peak_rss_mb === 'number'
        ? schedulerMetadata.peak_rss_mb
        : null,
    memory_limit_mb:
      typeof schedulerMetadata.memory_limit_mb === 'number'
        ? schedulerMetadata.memory_limit_mb
        : null,
    control_plane_headroom_mb:
      typeof schedulerMetadata.control_plane_headroom_mb === 'number'
        ? schedulerMetadata.control_plane_headroom_mb
        : null,
    active_expected_rss_mb:
      typeof schedulerMetadata.active_expected_rss_mb === 'number'
        ? schedulerMetadata.active_expected_rss_mb
        : null,
    latency_ms:
      typeof schedulerMetadata.latency_ms === 'number'
        ? schedulerMetadata.latency_ms
        : null,
    interruption_cause:
      typeof schedulerMetadata.interruption_cause === 'string'
        ? schedulerMetadata.interruption_cause
        : null,
    updated_at: row.updated_at,
    started_at: row.started_at,
    finished_at: row.finished_at,
    artifact_refs: artifactRefs,
    result: parseJsonRecord<unknown>(row.result_json, undefined),
    metadata:
      Object.keys(metadata).length > 0 || jobStatus?.progress !== undefined
        ? {
            ...metadata,
            ...(jobStatus?.progress !== undefined ? { progress: jobStatus.progress } : {}),
          }
        : undefined,
  }
}

function deriveRunStatus(stageViews: Array<z.infer<typeof AnalysisRunStageViewSchema>>): AnalysisRunStatus {
  if (stageViews.some((stage) => stage.status === 'failed')) {
    return 'failed'
  }
  if (stageViews.some((stage) => stage.status === 'interrupted' || stage.status === 'recoverable')) {
    return 'recoverable'
  }
  if (stageViews.some((stage) => stage.status === 'running')) {
    return 'running'
  }
  if (stageViews.some((stage) => stage.status === 'queued')) {
    return 'queued'
  }
  if (stageViews.length > 0 && stageViews.every((stage) => stage.status === 'completed' || stage.status === 'skipped')) {
    return 'completed'
  }
  if (stageViews.some((stage) => stage.status === 'completed' || stage.status === 'partial')) {
    return 'partial'
  }
  return 'created'
}

export function reconcileAnalysisRunRuntime(
  database: DatabaseManager,
  runId: string,
  jobQueue?: JobQueue
): Array<z.infer<typeof RecoverableStageSchema>> {
  const rows = database.findAnalysisRunStages(runId)
  const reconciled: Array<z.infer<typeof RecoverableStageSchema>> = []

  for (const row of rows) {
    if (row.status !== 'queued' && row.status !== 'running') {
      continue
    }

    const activeJob = row.job_id ? jobQueue?.getStatus(row.job_id) : undefined
    if (activeJob) {
      continue
    }

    const persistedJob = row.job_id ? database.findJob(row.job_id) : null
    const persistedStatus =
      persistedJob && typeof persistedJob.status === 'string' ? String(persistedJob.status) : null
    if (
      persistedStatus &&
      persistedStatus !== 'queued' &&
      persistedStatus !== 'running'
    ) {
      continue
    }

    const interrupted = row.status === 'running'
    const recoveryState: AnalysisRecoveryState = interrupted ? 'interrupted' : 'recoverable'
    const recoveryReason = interrupted
      ? `Stage ${row.stage} was interrupted before completion and must be re-promoted to finish.`
      : `Queued stage ${row.stage} lost its worker context and is recoverable through promotion.`
    const metadata = parseJsonRecord<Record<string, unknown>>(row.metadata_json, {})
    const now = nowIso()

    if (row.job_id) {
      database.markJobInterrupted(row.job_id, recoveryReason, {
        run_id: runId,
        stage: row.stage,
        recovery_state: recoveryState,
      })
    }

    database.upsertAnalysisRunStage({
      ...row,
      status: recoveryState,
      metadata_json: JSON.stringify({
        ...metadata,
        recovery_state: recoveryState,
        recovery_reason: recoveryReason,
        recovery_reconciled_at: now,
        prior_status: row.status,
      }),
      updated_at: now,
      finished_at: row.finished_at || now,
    })

    reconciled.push({
      stage: row.stage as AnalysisPipelineStage,
      status: recoveryState,
      recovery_state: recoveryState,
      reason: recoveryReason,
      job_id: row.job_id,
    })
  }

  return reconciled
}

export function getAnalysisRunSummary(
  database: DatabaseManager,
  runId: string,
  jobQueue?: JobQueue
): AnalysisRunSummary | null {
  const run = database.findAnalysisRun(runId)
  if (!run) {
    return null
  }
  reconcileAnalysisRunRuntime(database, runId, jobQueue)
  const stagePlan = parseJsonRecord<AnalysisPipelineStage[]>(
    run.stage_plan_json,
    buildStagePlan(run.goal as AnalysisIntentGoal)
  )
  const stages = database.findAnalysisRunStages(runId).map((stage) => toStageView(stage, database, jobQueue))
  const deferredJobs = stages
    .filter((stage) => stage.job_id && (stage.status === 'queued' || stage.status === 'running'))
    .map((stage) => {
      const jobStatus = stage.job_id ? jobQueue?.getStatus(stage.job_id) : undefined
      return {
        stage: stage.stage,
        job_id: stage.job_id!,
        status: jobStatus?.status || stage.status,
        ...(jobStatus?.progress !== undefined ? { progress: jobStatus.progress } : {}),
        tool: stage.tool || null,
        execution_bucket: stage.execution_bucket || null,
        cost_class: stage.cost_class || null,
        worker_family: stage.worker_family || null,
        budget_deferral_reason: stage.budget_deferral_reason || null,
        ...(typeof stage.warm_reuse === 'boolean' ? { warm_reuse: stage.warm_reuse } : {}),
        ...(typeof stage.cold_start === 'boolean' ? { cold_start: stage.cold_start } : {}),
        ...(typeof stage.expected_rss_mb === 'number' ? { expected_rss_mb: stage.expected_rss_mb } : {}),
        ...(typeof stage.current_rss_mb === 'number' ? { current_rss_mb: stage.current_rss_mb } : {}),
        ...(typeof stage.peak_rss_mb === 'number' ? { peak_rss_mb: stage.peak_rss_mb } : {}),
        ...(typeof stage.memory_limit_mb === 'number' ? { memory_limit_mb: stage.memory_limit_mb } : {}),
        ...(typeof stage.control_plane_headroom_mb === 'number'
          ? { control_plane_headroom_mb: stage.control_plane_headroom_mb }
          : {}),
        ...(typeof stage.active_expected_rss_mb === 'number'
          ? { active_expected_rss_mb: stage.active_expected_rss_mb }
          : {}),
        ...(typeof stage.latency_ms === 'number' ? { latency_ms: stage.latency_ms } : {}),
        ...(typeof stage.interruption_cause === 'string'
          ? { interruption_cause: stage.interruption_cause }
          : {}),
      }
    })
  const recoverableStages = stages
    .filter((stage) => stage.recovery_state !== 'none')
    .map((stage) => ({
      stage: stage.stage,
      status: stage.status,
      recovery_state: stage.recovery_state,
      reason:
        stage.recovery_reason ||
        (stage.recovery_state === 'interrupted'
          ? `Stage ${stage.stage} was interrupted before completion.`
          : `Stage ${stage.stage} is recoverable and can be promoted again.`),
      job_id: stage.job_id || null,
    }))

  const status = deriveRunStatus(stages)
  if (status !== run.status) {
    database.updateAnalysisRun(runId, {
      status,
      updated_at: nowIso(),
      ...(status === 'completed' || status === 'failed' ? { finished_at: nowIso() } : {}),
    })
  }

  return {
    run_id: run.id,
    sample_id: run.sample_id,
    sample_sha256: run.sample_sha256,
    goal: run.goal,
    depth: run.depth,
    backend_policy: run.backend_policy,
    pipeline_version: run.pipeline_version,
    compatibility_marker: run.compatibility_marker,
    status,
    sample_size_tier: (run.sample_size_tier || classifySampleSizeTier(0)) as SampleSizeTier,
    analysis_budget_profile:
      (run.analysis_budget_profile || 'quick') as AnalysisBudgetProfile,
    latest_stage: run.latest_stage,
    reused: Boolean(run.reused_from_run_id) || stages.some((stage) => stage.execution_state === 'reused'),
    created_at: run.created_at,
    updated_at: run.updated_at,
    finished_at: run.finished_at,
    artifact_refs: parseRunArtifactRefs(run),
    stage_plan: stagePlan,
    stages,
    deferred_jobs: deferredJobs,
    recovery_state: recoverableStages.length > 0 ? 'recoverable' : 'none',
    recoverable_stages: recoverableStages,
  }
}
