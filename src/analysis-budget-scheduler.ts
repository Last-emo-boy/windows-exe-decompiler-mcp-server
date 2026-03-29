import fs from 'fs'
import { randomUUID } from 'crypto'
import { z } from 'zod'
import type { DatabaseManager } from './database.js'
import type { Job, JobQueue } from './job-queue.js'
import type { SampleSizeTier } from './analysis-coverage.js'
import type { AnalysisPipelineStage } from './analysis-run-state.js'

export const ExecutionBucketSchema = z.enum([
  'preview-static',
  'enrich-static',
  'deep-attribution',
  'dynamic-plan',
  'dynamic-execute',
  'manual-execution',
  'artifact-only',
])

export const AnalysisCostClassSchema = z.enum([
  'cheap',
  'moderate',
  'expensive',
  'manual-only',
])

export const SchedulerDecisionSchema = z.enum([
  'admitted',
  'deferred',
  'completed',
  'interrupted',
])

export const WorkerFamilySchema = z.string().min(1)

export type ExecutionBucket = z.infer<typeof ExecutionBucketSchema>
export type AnalysisCostClass = z.infer<typeof AnalysisCostClassSchema>
export type SchedulerDecision = z.infer<typeof SchedulerDecisionSchema>

export interface SchedulerExecutionPlan {
  execution_bucket: ExecutionBucket
  cost_class: AnalysisCostClass
  worker_family: string
  expected_rss_mb: number
  manual_only: boolean
  stage: AnalysisPipelineStage | null
  sample_size_tier: SampleSizeTier | null
}

export interface SchedulerQueueJobView {
  id: string
  tool: string
  sampleId: string
  args: Record<string, unknown>
  priority: number
  timeout: number
  createdAt: string
  status?: string
}

export interface SchedulerSelection {
  job: Job
  plan: SchedulerExecutionPlan
}

function bucketPriority(bucket: ExecutionBucket): number {
  switch (bucket) {
    case 'preview-static':
      return 0
    case 'artifact-only':
      return 1
    case 'enrich-static':
      return 2
    case 'dynamic-plan':
      return 3
    case 'deep-attribution':
      return 4
    case 'dynamic-execute':
      return 5
    case 'manual-execution':
    default:
      return 6
  }
}

function extractStage(args: Record<string, unknown>): AnalysisPipelineStage | null {
  const stage = args?.stage
  if (
    stage === 'fast_profile' ||
    stage === 'enrich_static' ||
    stage === 'function_map' ||
    stage === 'reconstruct' ||
    stage === 'dynamic_plan' ||
    stage === 'dynamic_execute' ||
    stage === 'summarize'
  ) {
    return stage
  }
  return null
}

function inferSampleTier(args: Record<string, unknown>): SampleSizeTier | null {
  const tier = args?.sample_size_tier
  if (
    tier === 'small' ||
    tier === 'medium' ||
    tier === 'large' ||
    tier === 'oversized'
  ) {
    return tier
  }
  return null
}

const DEFAULT_MEMORY_LIMIT_MB = 8192
const DEFAULT_CONTROL_PLANE_HEADROOM_MB = 1536
const DEFAULT_PEAK_MEMORY_MARGIN_MB = 256

const CGROUP_USAGE_PATHS = [
  '/sys/fs/cgroup/memory.current',
  '/sys/fs/cgroup/memory/memory.usage_in_bytes',
]

const CGROUP_LIMIT_PATHS = [
  '/sys/fs/cgroup/memory.max',
  '/sys/fs/cgroup/memory/memory.limit_in_bytes',
]

function parsePositiveInt(value: string | undefined): number | null {
  if (!value) {
    return null
  }
  const parsed = Number.parseInt(value, 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null
}

function readFileNumberMb(paths: string[]): number | null {
  for (const candidate of paths) {
    try {
      if (!fs.existsSync(candidate)) {
        continue
      }
      const raw = fs.readFileSync(candidate, 'utf8').trim()
      if (!raw || raw === 'max') {
        continue
      }
      const bytes = Number.parseInt(raw, 10)
      if (!Number.isFinite(bytes) || bytes <= 0) {
        continue
      }
      return Math.max(1, Math.round(bytes / (1024 * 1024)))
    } catch {
      continue
    }
  }
  return null
}

export function getRuntimeMemoryUsageMb(): number {
  return (
    readFileNumberMb(CGROUP_USAGE_PATHS) ||
    Math.max(1, Math.round(process.memoryUsage().rss / (1024 * 1024)))
  )
}

function getConfiguredMemoryLimitMb(): number {
  return (
    parsePositiveInt(process.env.ANALYSIS_RUNTIME_MEMORY_LIMIT_MB) ||
    parsePositiveInt(process.env.CONTAINER_MEMORY_MB) ||
    readFileNumberMb(CGROUP_LIMIT_PATHS) ||
    DEFAULT_MEMORY_LIMIT_MB
  )
}

function getConfiguredControlPlaneHeadroomMb(memoryLimitMb: number): number {
  return (
    parsePositiveInt(process.env.ANALYSIS_RUNTIME_CONTROL_PLANE_HEADROOM_MB) ||
    Math.min(Math.max(768, Math.round(memoryLimitMb * 0.18)), DEFAULT_CONTROL_PLANE_HEADROOM_MB)
  )
}

function scaleForSampleTier(
  baseMb: number,
  sampleSizeTier: SampleSizeTier | null,
  multipliers: Partial<Record<SampleSizeTier, number>> = {}
): number {
  const factor =
    (sampleSizeTier && multipliers[sampleSizeTier]) ||
    (sampleSizeTier === 'small'
      ? 0.8
      : sampleSizeTier === 'medium'
        ? 1
        : sampleSizeTier === 'large'
          ? 1.35
          : sampleSizeTier === 'oversized'
            ? 1.75
            : 1)
  return Math.max(96, Math.round(baseMb * factor))
}

function estimateExpectedRssMb(plan: Omit<SchedulerExecutionPlan, 'expected_rss_mb'>): number {
  if (plan.manual_only) {
    return scaleForSampleTier(1024, plan.sample_size_tier)
  }

  if (plan.worker_family === 'stage.fast_profile') {
    return scaleForSampleTier(768, plan.sample_size_tier)
  }
  if (plan.worker_family === 'stage.enrich_static') {
    return scaleForSampleTier(2048, plan.sample_size_tier)
  }
  if (plan.worker_family === 'stage.dynamic_plan') {
    return scaleForSampleTier(768, plan.sample_size_tier)
  }
  if (plan.worker_family === 'stage.summarize') {
    return scaleForSampleTier(256, plan.sample_size_tier)
  }
  if (plan.worker_family === 'stage.deep_attribution') {
    return scaleForSampleTier(3072, plan.sample_size_tier)
  }
  if (plan.worker_family === 'ghidra.deep') {
    return scaleForSampleTier(3584, plan.sample_size_tier)
  }
  if (plan.worker_family === 'retdec_decompile') {
    return scaleForSampleTier(2560, plan.sample_size_tier)
  }
  if (plan.worker_family === 'angr_analyze') {
    return scaleForSampleTier(2048, plan.sample_size_tier)
  }
  if (plan.worker_family === 'analysis_context') {
    return scaleForSampleTier(
      plan.execution_bucket === 'enrich-static' ? 1536 : 512,
      plan.sample_size_tier
    )
  }
  if (plan.worker_family === 'crypto_identify') {
    return scaleForSampleTier(
      plan.execution_bucket === 'enrich-static' ? 1024 : 384,
      plan.sample_size_tier
    )
  }
  if (plan.worker_family === 'static_python.full') {
    return scaleForSampleTier(1536, plan.sample_size_tier)
  }
  if (plan.worker_family === 'static_python.preview') {
    return scaleForSampleTier(384, plan.sample_size_tier)
  }
  if (plan.worker_family === 'rizin.preview') {
    return scaleForSampleTier(256, plan.sample_size_tier)
  }
  if (plan.execution_bucket === 'deep-attribution') {
    return scaleForSampleTier(2048, plan.sample_size_tier)
  }
  if (plan.execution_bucket === 'enrich-static') {
    return scaleForSampleTier(1024, plan.sample_size_tier)
  }
  if (plan.execution_bucket === 'artifact-only') {
    return scaleForSampleTier(192, plan.sample_size_tier)
  }
  return scaleForSampleTier(384, plan.sample_size_tier)
}

function withExpectedRss(
  plan: Omit<SchedulerExecutionPlan, 'expected_rss_mb'>
): SchedulerExecutionPlan {
  return {
    ...plan,
    expected_rss_mb: estimateExpectedRssMb(plan),
  }
}

function isHeavySingletonPlan(plan: SchedulerExecutionPlan): boolean {
  return (
    plan.cost_class === 'expensive' ||
    plan.worker_family === 'ghidra.deep' ||
    plan.worker_family === 'retdec_decompile' ||
    plan.worker_family === 'angr_analyze' ||
    plan.worker_family === 'analysis_context' ||
    plan.worker_family === 'crypto_identify' ||
    plan.worker_family === 'static_python.full'
  )
}

export function buildSchedulerExecutionPlan(input: {
  tool: string
  args?: Record<string, unknown>
  sampleSizeTier?: SampleSizeTier | null
}): SchedulerExecutionPlan {
  const args = input.args || {}
  const stage = extractStage(args)
  const sampleSizeTier = (input.sampleSizeTier ?? inferSampleTier(args) ?? null) as SampleSizeTier | null

  if (input.tool === 'workflow.analyze.stage' && stage) {
    switch (stage) {
      case 'fast_profile':
        return withExpectedRss({
          execution_bucket: 'preview-static',
          cost_class: 'cheap',
          worker_family: 'stage.fast_profile',
          manual_only: false,
          stage,
          sample_size_tier: sampleSizeTier,
        })
      case 'enrich_static':
        return withExpectedRss({
          execution_bucket: 'enrich-static',
          cost_class: sampleSizeTier === 'large' || sampleSizeTier === 'oversized' ? 'expensive' : 'moderate',
          worker_family: 'stage.enrich_static',
          manual_only: false,
          stage,
          sample_size_tier: sampleSizeTier,
        })
      case 'function_map':
      case 'reconstruct':
        return withExpectedRss({
          execution_bucket: 'deep-attribution',
          cost_class: 'expensive',
          worker_family: 'stage.deep_attribution',
          manual_only: false,
          stage,
          sample_size_tier: sampleSizeTier,
        })
      case 'dynamic_plan':
        return withExpectedRss({
          execution_bucket: 'dynamic-plan',
          cost_class: 'moderate',
          worker_family: 'stage.dynamic_plan',
          manual_only: false,
          stage,
          sample_size_tier: sampleSizeTier,
        })
      case 'dynamic_execute':
        return withExpectedRss({
          execution_bucket: 'dynamic-execute',
          cost_class: 'manual-only',
          worker_family: 'stage.dynamic_execute',
          manual_only: true,
          stage,
          sample_size_tier: sampleSizeTier,
        })
      case 'summarize':
        return withExpectedRss({
          execution_bucket: 'artifact-only',
          cost_class: 'cheap',
          worker_family: 'stage.summarize',
          manual_only: false,
          stage,
          sample_size_tier: sampleSizeTier,
        })
    }
  }

  if (input.tool === 'strings.extract') {
    return withExpectedRss({
      execution_bucket: args.mode === 'full' ? 'enrich-static' : 'preview-static',
      cost_class: args.mode === 'full' ? 'expensive' : 'cheap',
      worker_family: args.mode === 'full' ? 'static_python.full' : 'static_python.preview',
      manual_only: false,
      stage,
      sample_size_tier: sampleSizeTier,
    })
  }

  if (
    input.tool === 'pe.fingerprint' ||
    input.tool === 'pe.imports.extract' ||
    input.tool === 'pe.exports.extract' ||
    input.tool === 'runtime.detect' ||
    input.tool === 'packer.detect' ||
    input.tool === 'compiler.packer.detect' ||
    input.tool === 'yara.scan' ||
    input.tool === 'yara_x.scan' ||
    input.tool === 'upx.inspect' ||
    input.tool === 'rizin.analyze'
  ) {
    return withExpectedRss({
      execution_bucket: 'preview-static',
      cost_class: 'cheap',
      worker_family:
        input.tool === 'rizin.analyze'
          ? 'rizin.preview'
          : input.tool === 'yara_x.scan'
            ? 'yarax.preview'
            : input.tool === 'upx.inspect'
              ? 'upx.preview'
              : 'static_python.preview',
      manual_only: false,
      stage,
      sample_size_tier: sampleSizeTier,
    })
  }

  if (
    input.tool === 'strings.floss.decode' ||
    input.tool === 'binary.role.profile' ||
    input.tool === 'analysis.context.link' ||
    input.tool === 'crypto.identify' ||
    input.tool === 'rust_binary.analyze' ||
    input.tool === 'static.capability.triage' ||
    input.tool === 'pe.structure.analyze'
  ) {
    const fullMode =
      args.mode === 'full' ||
      args.result_mode === 'full' ||
      args.analysis_mode === 'full'
    const enrichPreferred =
      fullMode || input.tool === 'static.capability.triage' || input.tool === 'pe.structure.analyze'
    return withExpectedRss({
      execution_bucket: enrichPreferred ? 'enrich-static' : 'preview-static',
      cost_class: enrichPreferred ? 'expensive' : 'moderate',
      worker_family:
        input.tool === 'analysis.context.link'
          ? 'analysis_context'
          : input.tool === 'crypto.identify'
            ? 'crypto_identify'
            : 'static_python.full',
      manual_only: false,
      stage,
      sample_size_tier: sampleSizeTier,
    })
  }

  if (
    input.tool === 'ghidra.analyze' ||
    input.tool === 'workflow.deep_static' ||
    input.tool === 'workflow.reconstruct' ||
    input.tool === 'workflow.semantic_name_review' ||
    input.tool === 'workflow.function_explanation_review' ||
    input.tool === 'workflow.module_reconstruction_review' ||
    input.tool === 'retdec.decompile' ||
    input.tool === 'angr.analyze'
  ) {
    return withExpectedRss({
      execution_bucket: 'deep-attribution',
      cost_class: 'expensive',
      worker_family:
        input.tool === 'ghidra.analyze' ? 'ghidra.deep' : input.tool.replace(/\./g, '_'),
      manual_only: false,
      stage,
      sample_size_tier: sampleSizeTier,
    })
  }

  if (
    input.tool === 'dynamic.dependencies' ||
    input.tool === 'breakpoint.smart' ||
    input.tool === 'qiling.inspect' ||
    input.tool === 'panda.inspect'
  ) {
    return withExpectedRss({
      execution_bucket: 'dynamic-plan',
      cost_class: 'moderate',
      worker_family: input.tool.replace(/\./g, '_'),
      manual_only: false,
      stage,
      sample_size_tier: sampleSizeTier,
    })
  }

  if (
    input.tool === 'sandbox.execute' ||
    input.tool === 'wine.run' ||
    input.tool === 'frida.runtime.instrument' ||
    input.tool === 'frida.script.inject' ||
    input.tool === 'frida.trace.capture'
  ) {
    const manualOnly =
      input.tool === 'wine.run' ||
      input.tool === 'frida.runtime.instrument' ||
      input.tool === 'frida.script.inject' ||
      input.tool === 'frida.trace.capture'
    return withExpectedRss({
      execution_bucket: manualOnly ? 'manual-execution' : 'dynamic-execute',
      cost_class: manualOnly ? 'manual-only' : 'expensive',
      worker_family: input.tool.replace(/\./g, '_'),
      manual_only: manualOnly,
      stage,
      sample_size_tier: sampleSizeTier,
    })
  }

  if (
    input.tool === 'workflow.summarize' ||
    input.tool === 'report.summarize' ||
    input.tool === 'report.generate' ||
    input.tool === 'graphviz.render'
  ) {
    return withExpectedRss({
      execution_bucket: 'artifact-only',
      cost_class: input.tool === 'report.generate' ? 'moderate' : 'cheap',
      worker_family: input.tool.replace(/\./g, '_'),
      manual_only: false,
      stage,
      sample_size_tier: sampleSizeTier,
    })
  }

  return withExpectedRss({
    execution_bucket: 'preview-static',
    cost_class: 'moderate',
    worker_family: input.tool.replace(/\./g, '_'),
    manual_only: false,
    stage,
    sample_size_tier: sampleSizeTier,
  })
}

function buildReasonForDeferred(plan: SchedulerExecutionPlan, reason: string): string {
  if (
    (plan.execution_bucket === 'deep-attribution' || plan.execution_bucket === 'enrich-static') &&
    (plan.sample_size_tier === 'large' || plan.sample_size_tier === 'oversized')
  ) {
    return `${reason}; sample_size_tier=${plan.sample_size_tier}`
  }
  return reason
}

export interface AnalysisBudgetSchedulerOptions {
  bucketCaps?: Partial<Record<ExecutionBucket, number>>
  memoryLimitMb?: number
  controlPlaneHeadroomMb?: number
}

export class AnalysisBudgetScheduler {
  private readonly bucketCaps: Record<ExecutionBucket, number>
  private readonly memoryLimitMb: number
  private readonly controlPlaneHeadroomMb: number

  constructor(
    private readonly database: DatabaseManager,
    options: AnalysisBudgetSchedulerOptions = {}
  ) {
    this.bucketCaps = {
      'preview-static': 1,
      'enrich-static': 1,
      'deep-attribution': 1,
      'dynamic-plan': 1,
      'dynamic-execute': 1,
      'manual-execution': 0,
      'artifact-only': 1,
      ...(options.bucketCaps || {}),
    }
    this.memoryLimitMb = options.memoryLimitMb || getConfiguredMemoryLimitMb()
    this.controlPlaneHeadroomMb =
      options.controlPlaneHeadroomMb || getConfiguredControlPlaneHeadroomMb(this.memoryLimitMb)
  }

  private buildMemorySnapshot(plans: SchedulerExecutionPlan[]) {
    const currentRssMb = getRuntimeMemoryUsageMb()
    const activeExpectedRssMb = plans.reduce((sum, plan) => sum + Math.max(0, plan.expected_rss_mb || 0), 0)
    const usableBudgetMb = Math.max(0, this.memoryLimitMb - this.controlPlaneHeadroomMb)
    return {
      current_rss_mb: currentRssMb,
      memory_limit_mb: this.memoryLimitMb,
      control_plane_headroom_mb: this.controlPlaneHeadroomMb,
      active_expected_rss_mb: activeExpectedRssMb,
      usable_budget_mb: usableBudgetMb,
    }
  }

  selectNextJob(jobQueue: JobQueue): SchedulerSelection | null {
    const queuedJobs = jobQueue.listQueuedJobs()
    if (queuedJobs.length === 0) {
      return null
    }

    const previewWaiting = queuedJobs.some(
      (job) => buildSchedulerExecutionPlan({ tool: job.tool, args: job.args }).execution_bucket === 'preview-static'
    )

    const runningRows = jobQueue.listStatuses('running').map((row) => ({
      ...row,
      plan: buildSchedulerExecutionPlan({
        tool: row.tool,
        args: row.args,
      }),
    }))
    const memorySnapshot = this.buildMemorySnapshot(runningRows.map((row) => row.plan))

    const sorted = [...queuedJobs].sort((left, right) => {
      const leftPlan = buildSchedulerExecutionPlan({ tool: left.tool, args: left.args })
      const rightPlan = buildSchedulerExecutionPlan({ tool: right.tool, args: right.args })
      if (bucketPriority(leftPlan.execution_bucket) !== bucketPriority(rightPlan.execution_bucket)) {
        return bucketPriority(leftPlan.execution_bucket) - bucketPriority(rightPlan.execution_bucket)
      }
      if (left.priority !== right.priority) {
        return right.priority - left.priority
      }
      return new Date(left.createdAt).getTime() - new Date(right.createdAt).getTime()
    })

    for (const job of sorted) {
      const plan = buildSchedulerExecutionPlan({ tool: job.tool, args: job.args })

      if (plan.manual_only || this.bucketCaps[plan.execution_bucket] <= 0) {
        this.recordEvent(job, plan, 'deferred', 'manual_only_bucket_requires_explicit_approval', memorySnapshot)
        continue
      }

      if (
        previewWaiting &&
        plan.execution_bucket !== 'preview-static' &&
        plan.execution_bucket !== 'artifact-only'
      ) {
        this.recordEvent(job, plan, 'deferred', buildReasonForDeferred(plan, 'preview_lane_has_waiting_work'), memorySnapshot)
        continue
      }

      const activeInBucket = runningRows.filter(
        (row) => row.plan.execution_bucket === plan.execution_bucket
      ).length
      if (activeInBucket >= (this.bucketCaps[plan.execution_bucket] || 1)) {
        this.recordEvent(
          job,
          plan,
          'deferred',
          buildReasonForDeferred(plan, `lane_saturated:${plan.execution_bucket}`),
          memorySnapshot
        )
        continue
      }

      if (isHeavySingletonPlan(plan) && runningRows.some((row) => isHeavySingletonPlan(row.plan))) {
        this.recordEvent(
          job,
          plan,
          'deferred',
          buildReasonForDeferred(plan, 'heavy_stage_singleton_guard'),
          memorySnapshot
        )
        continue
      }

      const projectedPeakMb =
        Math.max(memorySnapshot.current_rss_mb, memorySnapshot.active_expected_rss_mb) +
        plan.expected_rss_mb +
        DEFAULT_PEAK_MEMORY_MARGIN_MB
      if (projectedPeakMb > memorySnapshot.usable_budget_mb) {
        this.recordEvent(
          job,
          plan,
          'deferred',
          buildReasonForDeferred(
            plan,
            `memory_headroom_guard:projected_peak_mb=${projectedPeakMb};usable_budget_mb=${memorySnapshot.usable_budget_mb}`
          ),
          memorySnapshot
        )
        continue
      }

      this.recordEvent(job, plan, 'admitted', undefined, memorySnapshot)
      return { job, plan }
    }

    return null
  }

  recordCompletion(input: {
    jobId?: string | null
    runId?: string | null
    sampleId?: string | null
    tool: string
    stage?: string | null
    executionBucket: ExecutionBucket
    costClass: AnalysisCostClass
    workerFamily?: string | null
    warmReuse?: boolean | null
    coldStart?: boolean | null
    peakRssMb?: number | null
    currentRssMb?: number | null
    expectedRssMb?: number | null
    latencyMs?: number | null
    interruptionCause?: string | null
  }): void {
    this.database.insertSchedulerEvent({
      id: randomUUID(),
      job_id: input.jobId || null,
      run_id: input.runId || null,
      sample_id: input.sampleId || null,
      tool: input.tool,
      stage: input.stage || null,
      execution_bucket: input.executionBucket,
      cost_class: input.costClass,
      decision: 'completed',
      reason: null,
      worker_family: input.workerFamily || null,
      warm_reuse:
        typeof input.warmReuse === 'boolean' ? (input.warmReuse ? 1 : 0) : null,
      cold_start:
        typeof input.coldStart === 'boolean' ? (input.coldStart ? 1 : 0) : null,
      metadata_json: JSON.stringify({
        ...(typeof input.peakRssMb === 'number' ? { peak_rss_mb: input.peakRssMb } : {}),
        ...(typeof input.currentRssMb === 'number' ? { current_rss_mb: input.currentRssMb } : {}),
        ...(typeof input.expectedRssMb === 'number' ? { expected_rss_mb: input.expectedRssMb } : {}),
        ...(typeof input.latencyMs === 'number' ? { latency_ms: input.latencyMs } : {}),
        ...(typeof input.interruptionCause === 'string' && input.interruptionCause.length > 0
          ? { interruption_cause: input.interruptionCause }
          : {}),
      }),
      created_at: new Date().toISOString(),
    })
  }

  recordInterruption(input: {
    jobId?: string | null
    runId?: string | null
    sampleId?: string | null
    tool: string
    stage?: string | null
    executionBucket: ExecutionBucket
    costClass: AnalysisCostClass
    workerFamily?: string | null
    reason: string
    interruptionCause?: string | null
    peakRssMb?: number | null
    currentRssMb?: number | null
    expectedRssMb?: number | null
    latencyMs?: number | null
  }): void {
    this.database.insertSchedulerEvent({
      id: randomUUID(),
      job_id: input.jobId || null,
      run_id: input.runId || null,
      sample_id: input.sampleId || null,
      tool: input.tool,
      stage: input.stage || null,
      execution_bucket: input.executionBucket,
      cost_class: input.costClass,
      decision: 'interrupted',
      reason: input.reason,
      worker_family: input.workerFamily || null,
      warm_reuse: null,
      cold_start: null,
      metadata_json: JSON.stringify({
        ...(typeof input.peakRssMb === 'number' ? { peak_rss_mb: input.peakRssMb } : {}),
        ...(typeof input.currentRssMb === 'number' ? { current_rss_mb: input.currentRssMb } : {}),
        ...(typeof input.expectedRssMb === 'number' ? { expected_rss_mb: input.expectedRssMb } : {}),
        ...(typeof input.latencyMs === 'number' ? { latency_ms: input.latencyMs } : {}),
        interruption_cause: input.interruptionCause || 'unknown',
      }),
      created_at: new Date().toISOString(),
    })
  }

  private recordEvent(
    job: SchedulerQueueJobView,
    plan: SchedulerExecutionPlan,
    decision: SchedulerDecision,
    reason?: string,
    memorySnapshot?: {
      current_rss_mb: number
      memory_limit_mb: number
      control_plane_headroom_mb: number
      active_expected_rss_mb: number
      usable_budget_mb: number
    }
  ): void {
    this.database.insertSchedulerEvent({
      id: randomUUID(),
      job_id: job.id,
      run_id:
        job.tool === 'workflow.analyze.stage' && typeof job.args.run_id === 'string'
          ? String(job.args.run_id)
          : null,
      sample_id: job.sampleId,
      tool: job.tool,
      stage: plan.stage,
      execution_bucket: plan.execution_bucket,
      cost_class: plan.cost_class,
      decision,
      reason: reason || null,
      worker_family: plan.worker_family,
      warm_reuse: null,
      cold_start: null,
      metadata_json: JSON.stringify({
        priority: job.priority,
        timeout_ms: job.timeout,
        sample_size_tier: plan.sample_size_tier,
        expected_rss_mb: plan.expected_rss_mb,
        ...(memorySnapshot || {}),
      }),
      created_at: new Date().toISOString(),
    })
  }
}

export function findWorkerReuseTelemetry(payload: unknown): {
  worker_family?: string
  warm_reuse?: boolean
  cold_start?: boolean
  compatibility_key?: string
} | null {
  if (!payload || typeof payload !== 'object') {
    return null
  }

  const visited = new Set<unknown>()
  const queue: unknown[] = [payload]

  while (queue.length > 0) {
    const current = queue.shift()
    if (!current || typeof current !== 'object' || visited.has(current)) {
      continue
    }
    visited.add(current)
    const record = current as Record<string, unknown>
    const workerPool =
      record.worker_pool && typeof record.worker_pool === 'object'
        ? (record.worker_pool as Record<string, unknown>)
        : null
    if (workerPool) {
      return {
        worker_family:
          typeof workerPool.family === 'string' ? workerPool.family : undefined,
        warm_reuse:
          typeof workerPool.warm_reuse === 'boolean' ? workerPool.warm_reuse : undefined,
        cold_start:
          typeof workerPool.cold_start === 'boolean' ? workerPool.cold_start : undefined,
        compatibility_key:
          typeof workerPool.compatibility_key === 'string'
            ? workerPool.compatibility_key
            : undefined,
      }
    }
    for (const value of Object.values(record)) {
      if (value && typeof value === 'object') {
        queue.push(value)
      }
    }
  }

  return null
}
