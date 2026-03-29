/**
 * Background runner for queued analysis jobs.
 * Current scope: execute ghidra.analyze jobs with cancellation/timeouts and stale-job reaping.
 */

import { DecompilerWorker, GhidraProcessError } from './decompiler-worker.js'
import type { DatabaseManager } from './database.js'
import type { WorkspaceManager } from './workspace-manager.js'
import type { Job, JobQueue } from './job-queue.js'
import type { CacheManager } from './cache-manager.js'
import type { JobResult } from './types.js'
import type { PolicyGuard } from './policy-guard.js'
import { logger } from './logger.js'
import { deepStaticWorkflow } from './workflows/deep-static.js'
import { createReconstructWorkflowHandler } from './workflows/reconstruct.js'
import { createSemanticNameReviewWorkflowHandler } from './workflows/semantic-name-review.js'
import { createFunctionExplanationReviewWorkflowHandler } from './workflows/function-explanation-review.js'
import { createModuleReconstructionReviewWorkflowHandler } from './workflows/module-reconstruction-review.js'
import { createStringsExtractHandler } from './tools/strings-extract.js'
import { createStringsFlossDecodeHandler } from './tools/strings-floss-decode.js'
import { createBinaryRoleProfileHandler } from './tools/binary-role-profile.js'
import { createAnalysisContextLinkHandler } from './tools/analysis-context-link.js'
import { createCryptoIdentifyHandler } from './tools/crypto-identify.js'
import {
  AnalysisBudgetScheduler,
  findWorkerReuseTelemetry,
  getRuntimeMemoryUsageMb,
} from './analysis-budget-scheduler.js'
import {
  ANALYSIS_STAGE_JOB_TOOL,
  createAnalyzePipelineStageContext,
  executeQueuedAnalysisStage,
} from './workflows/analyze-pipeline.js'

export interface AnalysisTaskRunnerOptions {
  pollIntervalMs?: number
  staleRunningMs?: number | null
}

export class AnalysisTaskRunner {
  private readonly decompilerWorker: DecompilerWorker
  private readonly pollIntervalMs: number
  private readonly staleRunningMs?: number | null
  private readonly database: DatabaseManager
  private readonly workspaceManager: WorkspaceManager
  private readonly cacheManager?: CacheManager
  private readonly policyGuard: PolicyGuard
  private readonly scheduler: AnalysisBudgetScheduler
  private timer?: NodeJS.Timeout
  private processing = false
  private activeControllers = new Map<string, AbortController>()

  constructor(
    private readonly jobQueue: JobQueue,
    database: DatabaseManager,
    workspaceManager: WorkspaceManager,
    cacheManager: CacheManager | undefined,
    policyGuard: PolicyGuard,
    options: AnalysisTaskRunnerOptions = {}
  ) {
    this.database = database
    this.workspaceManager = workspaceManager
    this.cacheManager = cacheManager
    this.policyGuard = policyGuard
    this.scheduler = new AnalysisBudgetScheduler(database)
    this.decompilerWorker = new DecompilerWorker(database, workspaceManager)
    this.pollIntervalMs = options.pollIntervalMs ?? 500
    this.staleRunningMs = options.staleRunningMs

    this.jobQueue.on('job:cancelled', (jobId: string) => {
      const controller = this.activeControllers.get(jobId)
      if (controller) {
        controller.abort()
      }
    })
  }

  start(): void {
    if (this.timer) {
      return
    }

    this.timer = setInterval(() => {
      this.reapStaleRunning()
      void this.processNext()
    }, this.pollIntervalMs)
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer)
      this.timer = undefined
    }
    for (const controller of this.activeControllers.values()) {
      controller.abort()
    }
    this.activeControllers.clear()
  }

  private reapStaleRunning(): void {
    if (
      typeof this.staleRunningMs !== 'number' ||
      !Number.isFinite(this.staleRunningMs) ||
      this.staleRunningMs <= 0
    ) {
      return
    }

    const queue = this.jobQueue as JobQueue & {
      reapStaleRunningJobs?: (maxRuntimeMs: number, nowMs?: number) => string[]
    }
    if (typeof queue.reapStaleRunningJobs !== 'function') {
      return
    }

    const reaped = queue.reapStaleRunningJobs(this.staleRunningMs)
    for (const jobId of reaped) {
      const controller = this.activeControllers.get(jobId)
      if (controller) {
        controller.abort()
      }
    }

    if (reaped.length > 0) {
      logger.warn(
        {
          reaped_count: reaped.length,
          stale_running_ms: this.staleRunningMs,
          jobs: reaped,
        },
        'Reaped stale running analysis jobs'
      )
    }
  }

  private async processNext(): Promise<void> {
    if (this.processing) {
      return
    }

    const selection = this.scheduler.selectNextJob(this.jobQueue)
    if (!selection) {
      return
    }
    const job = this.jobQueue.startQueuedJob(selection.job.id)
    if (!job) {
      return
    }

    this.processing = true
    const startTime = Date.now()
    const controller = new AbortController()
    this.activeControllers.set(job.id, controller)

    try {
      const result = await this.executeJob(job, controller.signal)
      if (typeof result.metrics.elapsedMs !== 'number' || result.metrics.elapsedMs <= 0) {
        result.metrics.elapsedMs = Date.now() - startTime
      }
      const currentRssMb = getRuntimeMemoryUsageMb()
      const workerTelemetry = findWorkerReuseTelemetry(result.data)
      this.scheduler.recordCompletion({
        jobId: job.id,
        runId:
          job.tool === ANALYSIS_STAGE_JOB_TOOL && typeof job.args?.run_id === 'string'
            ? String(job.args.run_id)
            : null,
        sampleId: job.sampleId,
        tool: job.tool,
        stage:
          job.tool === ANALYSIS_STAGE_JOB_TOOL && typeof job.args?.stage === 'string'
            ? String(job.args.stage)
            : null,
        executionBucket: selection.plan.execution_bucket,
        costClass: selection.plan.cost_class,
        workerFamily: workerTelemetry?.worker_family || selection.plan.worker_family,
        warmReuse: workerTelemetry?.warm_reuse,
        coldStart: workerTelemetry?.cold_start,
        peakRssMb:
          typeof result.metrics.peakRssMb === 'number' && result.metrics.peakRssMb > 0
            ? result.metrics.peakRssMb
            : currentRssMb,
        currentRssMb,
        expectedRssMb: selection.plan.expected_rss_mb,
        latencyMs: result.metrics.elapsedMs,
      })
      this.jobQueue.complete(job.id, result)
    } catch (error) {
      const elapsedMs = Date.now() - startTime
      const message = error instanceof Error ? error.message : String(error)
      const currentRssMb = getRuntimeMemoryUsageMb()
      const interruptionCause =
        /oom|out of memory|memory|allocation|killed/i.test(message)
          ? 'memory_pressure'
          : /cancelled|aborted/i.test(message)
            ? 'cancelled'
            : 'tool_error'
      logger.error(
        {
          job_id: job.id,
          tool: job.tool,
          sample_id: job.sampleId,
          error: message,
        },
        'Analysis task failed'
      )

      this.scheduler.recordInterruption({
        jobId: job.id,
        runId:
          job.tool === ANALYSIS_STAGE_JOB_TOOL && typeof job.args?.run_id === 'string'
            ? String(job.args.run_id)
            : null,
        sampleId: job.sampleId,
        tool: job.tool,
        stage:
          job.tool === ANALYSIS_STAGE_JOB_TOOL && typeof job.args?.stage === 'string'
            ? String(job.args.stage)
            : null,
        executionBucket: selection.plan.execution_bucket,
        costClass: selection.plan.cost_class,
        workerFamily: selection.plan.worker_family,
        reason: message,
        interruptionCause,
        peakRssMb: currentRssMb,
        currentRssMb,
        expectedRssMb: selection.plan.expected_rss_mb,
        latencyMs: elapsedMs,
      })

      const normalizedError =
        error instanceof Error ? error : new Error(message)
      this.jobQueue.complete(
        job.id,
        this.decompilerWorker.createErrorJobResult(job.id, normalizedError, elapsedMs)
      )
    } finally {
      this.activeControllers.delete(job.id)
      this.processing = false
    }
  }

  private async executeJob(job: Job, abortSignal: AbortSignal): Promise<JobResult> {
    if (job.tool === 'ghidra.analyze') {
      const options = (job.args?.options || {}) as {
        max_cpu?: string
        project_key?: string
        processor?: string
        language_id?: string
        cspec?: string
        script_paths?: string[]
      }

      try {
        const analysisResult = await this.decompilerWorker.analyze(job.sampleId, {
          analysisId: job.id,
          timeout: job.timeout,
          maxCpu: options.max_cpu || '4',
          projectKey: options.project_key,
          processor: options.processor,
          languageId: options.language_id,
          cspec: options.cspec,
          scriptPaths: options.script_paths,
          abortSignal,
          onProgress: (progress) => {
            this.jobQueue.updateProgress(job.id, progress)
          },
        })
        return this.decompilerWorker.createJobResult(analysisResult, 0)
      } catch (error) {
        if (error instanceof GhidraProcessError && error.errorCode === 'E_CANCELLED') {
          throw new Error('E_CANCELLED: analysis task cancelled')
        }
        throw error
      }
    }

    if (job.tool === 'workflow.deep_static') {
      if (!this.cacheManager) {
        throw new Error('workflow.deep_static requires cache manager for queued execution')
      }

      const options = (job.args?.options || {}) as {
        top_functions?: number
        ghidra_timeout?: number
        include_cfg?: boolean
      }

      const result = await deepStaticWorkflow(
        job.sampleId,
        this.workspaceManager,
        this.database,
        this.cacheManager,
        options,
        {
          onProgress: (progress) => {
            this.jobQueue.updateProgress(job.id, progress)
          },
        }
      )

      return {
        jobId: job.id,
        ok: result.ok,
        data: result.data,
        errors: result.errors || [],
        warnings: result.warnings || [],
        artifacts: [],
        metrics: {
          elapsedMs: 0,
          peakRssMb: 0,
        },
      }
    }

    if (job.tool === 'workflow.reconstruct') {
      if (!this.cacheManager) {
        throw new Error('workflow.reconstruct requires cache manager for queued execution')
      }

      this.jobQueue.updateProgress(job.id, 5)
      const handler = createReconstructWorkflowHandler(
        this.workspaceManager,
        this.database,
        this.cacheManager
      )
      const result = await handler(job.args || {})
      this.jobQueue.updateProgress(job.id, 100)

      return {
        jobId: job.id,
        ok: result.ok,
        data: result.data,
        errors: result.errors || [],
        warnings: result.warnings || [],
        artifacts: result.artifacts || [],
        metrics: {
          elapsedMs:
            typeof result.metrics?.elapsed_ms === 'number' ? result.metrics.elapsed_ms : 0,
          peakRssMb: 0,
        },
      }
    }

    if (job.tool === ANALYSIS_STAGE_JOB_TOOL) {
      if (!this.cacheManager) {
        throw new Error('workflow.analyze.stage requires cache manager for queued execution')
      }
      const stageContext = createAnalyzePipelineStageContext(
        this.workspaceManager,
        this.database,
        this.cacheManager,
        this.policyGuard,
        undefined,
        {},
        this.jobQueue
      )
      const input = job.args as {
        run_id: string
        stage: 'fast_profile' | 'enrich_static' | 'function_map' | 'reconstruct' | 'dynamic_plan' | 'dynamic_execute' | 'summarize'
        force_refresh?: boolean
      }
      return executeQueuedAnalysisStage(stageContext, input)
    }

    if (job.tool === 'strings.extract') {
      if (!this.cacheManager) {
        throw new Error('strings.extract requires cache manager for queued execution')
      }
      const handler = createStringsExtractHandler(
        this.workspaceManager,
        this.database,
        this.cacheManager,
        this.jobQueue,
        { allowDeferred: false }
      )
      const result = await handler(job.args || {})
      return {
        jobId: job.id,
        ok: result.ok,
        data: result.data,
        errors: result.errors || [],
        warnings: result.warnings || [],
        artifacts: result.artifacts || [],
        metrics: {
          elapsedMs: typeof result.metrics?.elapsed_ms === 'number' ? result.metrics.elapsed_ms : 0,
          peakRssMb: 0,
        },
      }
    }

    if (job.tool === 'strings.floss.decode') {
      if (!this.cacheManager) {
        throw new Error('strings.floss.decode requires cache manager for queued execution')
      }
      const handler = createStringsFlossDecodeHandler(
        this.workspaceManager,
        this.database,
        this.cacheManager,
        this.jobQueue,
        { allowDeferred: false }
      )
      const result = await handler(job.args || {})
      return {
        jobId: job.id,
        ok: result.ok,
        data: result.data,
        errors: result.errors || [],
        warnings: result.warnings || [],
        artifacts: result.artifacts || [],
        metrics: {
          elapsedMs: typeof result.metrics?.elapsed_ms === 'number' ? result.metrics.elapsed_ms : 0,
          peakRssMb: 0,
        },
      }
    }

    if (job.tool === 'binary.role.profile') {
      if (!this.cacheManager) {
        throw new Error('binary.role.profile requires cache manager for queued execution')
      }
      const handler = createBinaryRoleProfileHandler(
        this.workspaceManager,
        this.database,
        this.cacheManager,
        undefined,
        this.jobQueue,
        { allowDeferred: false }
      )
      const result = await handler(job.args || {})
      return {
        jobId: job.id,
        ok: result.ok,
        data: result.data,
        errors: result.errors || [],
        warnings: result.warnings || [],
        artifacts: result.artifacts || [],
        metrics: {
          elapsedMs: typeof result.metrics?.elapsed_ms === 'number' ? result.metrics.elapsed_ms : 0,
          peakRssMb: 0,
        },
      }
    }

    if (job.tool === 'analysis.context.link') {
      if (!this.cacheManager) {
        throw new Error('analysis.context.link requires cache manager for queued execution')
      }
      const handler = createAnalysisContextLinkHandler(
        this.workspaceManager,
        this.database,
        this.cacheManager,
        {},
        this.jobQueue,
        { allowDeferred: false }
      )
      const result = await handler(job.args || {})
      return {
        jobId: job.id,
        ok: result.ok,
        data: result.data,
        errors: result.errors || [],
        warnings: result.warnings || [],
        artifacts: result.artifacts || [],
        metrics: {
          elapsedMs: typeof result.metrics?.elapsed_ms === 'number' ? result.metrics.elapsed_ms : 0,
          peakRssMb: 0,
        },
      }
    }

    if (job.tool === 'crypto.identify') {
      if (!this.cacheManager) {
        throw new Error('crypto.identify requires cache manager for queued execution')
      }
      const handler = createCryptoIdentifyHandler(
        this.workspaceManager,
        this.database,
        this.cacheManager,
        {},
        this.jobQueue,
        { allowDeferred: false }
      )
      const result = await handler(job.args || {})
      return {
        jobId: job.id,
        ok: result.ok,
        data: result.data,
        errors: result.errors || [],
        warnings: result.warnings || [],
        artifacts: result.artifacts || [],
        metrics: {
          elapsedMs: typeof result.metrics?.elapsed_ms === 'number' ? result.metrics.elapsed_ms : 0,
          peakRssMb: 0,
        },
      }
    }

    if (job.tool === 'workflow.semantic_name_review') {
      if (!this.cacheManager) {
        throw new Error('workflow.semantic_name_review requires cache manager for queued execution')
      }

      this.jobQueue.updateProgress(job.id, 5)
      const handler = createSemanticNameReviewWorkflowHandler(
        this.workspaceManager,
        this.database,
        this.cacheManager
      )
      const result = await handler(job.args || {})
      this.jobQueue.updateProgress(job.id, 100)

      return {
        jobId: job.id,
        ok: result.ok,
        data: result.data,
        errors: result.errors || [],
        warnings: result.warnings || [],
        artifacts: result.artifacts || [],
        metrics: {
          elapsedMs:
            typeof result.metrics?.elapsed_ms === 'number' ? result.metrics.elapsed_ms : 0,
          peakRssMb: 0,
        },
      }
    }

    if (job.tool === 'workflow.function_explanation_review') {
      if (!this.cacheManager) {
        throw new Error(
          'workflow.function_explanation_review requires cache manager for queued execution'
        )
      }

      this.jobQueue.updateProgress(job.id, 5)
      const handler = createFunctionExplanationReviewWorkflowHandler(
        this.workspaceManager,
        this.database,
        this.cacheManager
      )
      const result = await handler(job.args || {})
      this.jobQueue.updateProgress(job.id, 100)

      return {
        jobId: job.id,
        ok: result.ok,
        data: result.data,
        errors: result.errors || [],
        warnings: result.warnings || [],
        artifacts: result.artifacts || [],
        metrics: {
          elapsedMs:
            typeof result.metrics?.elapsed_ms === 'number' ? result.metrics.elapsed_ms : 0,
          peakRssMb: 0,
        },
      }
    }

    if (job.tool === 'workflow.module_reconstruction_review') {
      if (!this.cacheManager) {
        throw new Error(
          'workflow.module_reconstruction_review requires cache manager for queued execution'
        )
      }

      this.jobQueue.updateProgress(job.id, 5)
      const handler = createModuleReconstructionReviewWorkflowHandler(
        this.workspaceManager,
        this.database,
        this.cacheManager
      )
      const result = await handler(job.args || {})
      this.jobQueue.updateProgress(job.id, 100)

      return {
        jobId: job.id,
        ok: result.ok,
        data: result.data,
        errors: result.errors || [],
        warnings: result.warnings || [],
        artifacts: result.artifacts || [],
        metrics: {
          elapsedMs:
            typeof result.metrics?.elapsed_ms === 'number' ? result.metrics.elapsed_ms : 0,
          peakRssMb: 0,
        },
      }
    }

    throw new Error(`Unsupported queued tool: ${job.tool}`)
  }
}
