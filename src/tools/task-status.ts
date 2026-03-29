/**
 * task.status MCP tool
 * Query analysis task queue status and optional per-job details.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolHandler, ToolResult } from '../types.js'
import type { JobQueue, JobStatusType } from '../job-queue.js'
import type { DatabaseManager } from '../database.js'
import { PollingGuidanceSchema, buildPollingGuidance } from '../polling-guidance.js'
import { TOOL_DURATION_ESTIMATES } from '../job-queue.js'
import { formatDuration } from '../async-tool-wrapper.js'
import { ANALYSIS_STAGE_JOB_TOOL } from '../workflows/analyze-pipeline.js'
import { getAnalysisRunSummary } from '../analysis-run-state.js'
import { ToolSurfaceRoleSchema } from '../tool-surface-guidance.js'

const TOOL_NAME = 'task.status'

export const taskStatusInputSchema = z.object({
  job_id: z.string().optional().describe('Optional job id for single-job lookup'),
  status: z
    .enum(['queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted'])
    .optional()
    .describe('Optional status filter'),
  include_result: z
    .boolean()
    .optional()
    .default(false)
    .describe('Include completed/failed job result payload for single-job lookup'),
  limit: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .default(100)
    .describe('Maximum number of jobs to return'),
})

export type TaskStatusInput = z.infer<typeof taskStatusInputSchema>

const TaskStatusJobSchema = z.record(z.any())

export const taskStatusOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      queue_length: z.number().int().nonnegative().optional(),
      total_jobs: z.number().int().nonnegative().optional(),
      count: z.number().int().nonnegative().optional(),
      jobs: z.array(TaskStatusJobSchema).optional(),
      job: TaskStatusJobSchema.optional(),
      result: z.any().optional(),
      polling_guidance: PollingGuidanceSchema.nullable().optional(),
      result_mode: z.enum(['queue_summary', 'job_lookup']).optional(),
      tool_surface_role: ToolSurfaceRoleSchema.optional(),
      preferred_primary_tools: z.array(z.string()).optional(),
      recommended_next_tools: z.array(z.string()).optional(),
      next_actions: z.array(z.string()).optional(),
    })
    .optional(),
  errors: z.array(z.string()).optional(),
})

export const taskStatusToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Inspect queued, running, completed, failed, or cancelled analysis jobs. ' +
    'Use this after ghidra.analyze or other queued workflows return a job_id or polling_guidance. ' +
    'Do not use this as the first reverse-engineering step; it is a follow-up queue inspection tool. ' +
    '\n\nDecision guide:\n' +
    '- Use when: a previous tool returned job_id, status=queued/running, or polling_guidance and you need raw job-state details.\n' +
    '- Do not use when: you still need to ingest a sample or start analysis.\n' +
    '- Typical next step: prefer workflow.analyze.status when you have a run_id; use task.status(job_id) only for raw queue-state detail.\n' +
    '- Common mistake: immediate repeated polling without any client-side sleep/wait.',
  inputSchema: taskStatusInputSchema,
  outputSchema: taskStatusOutputSchema,
}

export function createTaskStatusHandler(jobQueue: JobQueue, database?: DatabaseManager): ToolHandler {
  const buildJsonResult = (payload: Record<string, unknown>, isError = false): ToolResult => ({
    content: [
      {
        type: 'text',
        text: JSON.stringify(payload, null, 2),
      },
    ],
    structuredContent: payload,
    isError: isError || undefined,
  })

  const parseSchedulerMetadata = (raw: string | null | undefined): Record<string, unknown> => {
    if (!raw || !raw.trim()) {
      return {}
    }
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>
      return parsed && typeof parsed === 'object' ? parsed : {}
    } catch {
      return {}
    }
  }

  /**
   * Get friendly status message with time estimate
   * Tasks: mcp-async-job-pattern 3.2, 3.3
   */
  const getFriendlyMessage = (status: Record<string, unknown>): string => {
    const jobStatus = status.status as string
    const tool = (status.tool as string) || 'unknown'
    const progress = status.progress as number
    const startedAt = status.startedAt as string
    const estimatedDurationMs = status.estimatedDurationMs as number
    
    // Calculate elapsed time
    const elapsed = startedAt ? Date.now() - new Date(startedAt).getTime() : 0
    const estimated = estimatedDurationMs || TOOL_DURATION_ESTIMATES[tool] || TOOL_DURATION_ESTIMATES.default
    const remaining = Math.max(0, estimated - elapsed)
    
    // Friendly messages based on status
    const messages: Record<string, string> = {
      queued: 'Job queued. Waiting for worker...',
      running: `Analysis in progress. Estimated time remaining: ${formatDuration(remaining)}.`,
      completed: 'Analysis completed.',
      failed: `Analysis failed: ${status.error || 'Unknown error'}`,
      cancelled: `Analysis cancelled: ${status.cancelReason || 'User requested'}`,
      interrupted: `Analysis interrupted: ${status.error || 'Worker context was lost before completion'}`,
    }
    
    return messages[jobStatus] || `Status: ${jobStatus}`
  }

  return async (args: unknown): Promise<ToolResult> => {
    try {
      const input = taskStatusInputSchema.parse(args)
      const listStatus = (jobQueue as JobQueue & {
        listStatuses?: (status?: JobStatusType) => unknown[]
      }).listStatuses

      if (input.job_id) {
        const detailedStatuses = listStatus ? listStatus.call(jobQueue) : []
        const detailedStatus = Array.isArray(detailedStatuses)
          ? (detailedStatuses as Array<Record<string, unknown>>).find((row) => row.id === input.job_id)
          : undefined
        const persistedJob =
          !detailedStatus && database ? database.findJob(input.job_id) : null
        const status = detailedStatus || jobQueue.getStatus(input.job_id) || persistedJob
        if (!status) {
          return buildJsonResult(
            {
              ok: false,
              errors: [`Job not found: ${input.job_id}`],
            },
            true
          )
        }

        const statusRecord = status as Record<string, unknown> & {
          status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'interrupted'
          progress?: number
          tool?: string
          timeout?: number
          estimatedDurationMs?: number
        }

        // Get friendly message with time estimate
        const message = getFriendlyMessage(statusRecord)
        const stageRunId =
          typeof statusRecord.args === 'object' &&
          statusRecord.args &&
          typeof (statusRecord.args as Record<string, unknown>).run_id === 'string'
            ? String((statusRecord.args as Record<string, unknown>).run_id)
            : null
        const isAnalysisStageJob = statusRecord.tool === ANALYSIS_STAGE_JOB_TOOL
        const runSummary =
          isAnalysisStageJob && stageRunId && database
            ? getAnalysisRunSummary(database, stageRunId, jobQueue)
            : null
        const schedulerEvent = database?.findLatestSchedulerEventForJob(input.job_id) || null
        const schedulerMetadata = parseSchedulerMetadata(schedulerEvent?.metadata_json)

        // Calculate elapsed time safely
        const startedAtStr = typeof statusRecord.startedAt === 'string' ? statusRecord.startedAt : null
        const elapsed = startedAtStr ? Date.now() - new Date(startedAtStr).getTime() : 0
        const estimatedDurationMs = typeof statusRecord.estimatedDurationMs === 'number' 
          ? statusRecord.estimatedDurationMs 
          : (TOOL_DURATION_ESTIMATES[statusRecord.tool as string] || TOOL_DURATION_ESTIMATES.default)
        const remaining = Math.max(0, estimatedDurationMs - elapsed)

        return buildJsonResult({
          ok: true,
          data: {
            job: {
              ...statusRecord,
              message,
              estimated_remaining: formatDuration(remaining),
              execution_bucket: schedulerEvent?.execution_bucket || null,
              cost_class: schedulerEvent?.cost_class || null,
              worker_family: schedulerEvent?.worker_family || null,
              scheduler_decision: schedulerEvent?.decision || null,
              budget_deferral_reason:
                schedulerEvent?.decision === 'deferred' ? schedulerEvent.reason : null,
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
                  : undefined,
              current_rss_mb:
                typeof schedulerMetadata.current_rss_mb === 'number'
                  ? schedulerMetadata.current_rss_mb
                  : undefined,
              peak_rss_mb:
                typeof schedulerMetadata.peak_rss_mb === 'number'
                  ? schedulerMetadata.peak_rss_mb
                  : undefined,
              memory_limit_mb:
                typeof schedulerMetadata.memory_limit_mb === 'number'
                  ? schedulerMetadata.memory_limit_mb
                  : undefined,
              control_plane_headroom_mb:
                typeof schedulerMetadata.control_plane_headroom_mb === 'number'
                  ? schedulerMetadata.control_plane_headroom_mb
                  : undefined,
              active_expected_rss_mb:
                typeof schedulerMetadata.active_expected_rss_mb === 'number'
                  ? schedulerMetadata.active_expected_rss_mb
                  : undefined,
              latency_ms:
                typeof schedulerMetadata.latency_ms === 'number'
                  ? schedulerMetadata.latency_ms
                  : undefined,
              interruption_cause:
                typeof schedulerMetadata.interruption_cause === 'string'
                  ? schedulerMetadata.interruption_cause
                  : undefined,
              polling_guidance: buildPollingGuidance({
                tool: typeof statusRecord.tool === 'string' ? statusRecord.tool : null,
                status: statusRecord.status,
                progress: typeof statusRecord.progress === 'number' ? statusRecord.progress : null,
                timeout_ms: typeof statusRecord.timeout === 'number' ? statusRecord.timeout : null,
                }),
              analysis_run:
                    isAnalysisStageJob && stageRunId
                      ? {
                          run_id: stageRunId,
                          latest_run_status: runSummary?.status || database?.findAnalysisRun(stageRunId)?.status || null,
                          recovery_state: runSummary?.recovery_state || 'none',
                          recoverable_stages: runSummary?.recoverable_stages || [],
                    }
                  : undefined,
            },
            result: input.include_result && statusRecord.status === 'completed' ? jobQueue.getResult(input.job_id) : undefined,
            result_mode: 'job_lookup',
            tool_surface_role: 'compatibility',
            preferred_primary_tools: ['workflow.analyze.status'],
            recommended_next_tools:
              isAnalysisStageJob
                ? statusRecord.status === 'completed'
                  ? ['workflow.analyze.status', 'artifact.read', 'report.summarize']
                  : statusRecord.status === 'interrupted'
                    ? ['workflow.analyze.status', 'workflow.analyze.promote', 'task.status']
                  : ['workflow.analyze.status', 'task.status']
                : statusRecord.status === 'completed'
                  ? ['workflow.reconstruct', 'code.functions.list', 'artifact.read']
                  : ['task.status'],
            next_actions:
              statusRecord.status === 'queued' || statusRecord.status === 'running'
                ? [
                    message,
                    isAnalysisStageJob && stageRunId
                      ? `Use workflow.analyze.status with run_id=${stageRunId} as the primary staged-run view; only fall back to task.status when you need raw job state.`
                      : 'Wait for approximately the recommended polling interval before querying task.status again.',
                    'Call task.status with the same job_id until the status becomes completed, failed, or cancelled.',
                  ]
                : statusRecord.status === 'interrupted'
                  ? [
                      isAnalysisStageJob && stageRunId
                        ? `The underlying queued stage was interrupted. Inspect workflow.analyze.status for run_id=${stageRunId} and re-promote only the recoverable stages you still need.`
                        : 'This job was interrupted before completion; decide whether it should be requeued or restarted from the originating tool.',
                    ]
                : statusRecord.status === 'completed'
                  ? [
                      isAnalysisStageJob && stageRunId
                        ? `Inspect workflow.analyze.status for run_id=${stageRunId} before deciding whether to promote or summarize the persisted run.`
                        : 'Inspect the completed job result or continue with downstream analysis tools using the finished artifacts.',
                    ]
                  : [
                      'Inspect the error or cancellation reason before deciding whether to retry the originating analysis tool.',
                    ],
          },
        })
      }

      const queueRows = listStatus
        ? listStatus.call(jobQueue, input.status)
        : jobQueue.getJobsByStatus((input.status || 'queued') as JobStatusType)
      const persistedRows =
        database && input.status
          ? database.findJobsByStatus(input.status, input.limit)
          : database && !input.status
            ? database.findJobsByStatuses(['queued', 'running', 'interrupted'], input.limit)
            : []
      const mergedRows = new Map<string, any>()
      for (const row of [...persistedRows, ...queueRows]) {
        const key = typeof row?.id === 'string' ? row.id : null
        if (!key) {
          continue
        }
        mergedRows.set(key, row)
      }
      const rows = [...mergedRows.values()]
      const limitedRows = rows.slice(0, input.limit).map((row: any) => ({
        ...row,
        ...(database
          ? (() => {
              const schedulerEvent = database.findLatestSchedulerEventForJob(row.id)
              const schedulerMetadata = parseSchedulerMetadata(schedulerEvent?.metadata_json)
              return schedulerEvent
                ? {
                    execution_bucket: schedulerEvent.execution_bucket,
                    cost_class: schedulerEvent.cost_class,
                    worker_family: schedulerEvent.worker_family,
                    scheduler_decision: schedulerEvent.decision,
                    budget_deferral_reason:
                      schedulerEvent.decision === 'deferred' ? schedulerEvent.reason : null,
                    ...(typeof schedulerEvent.warm_reuse === 'number'
                      ? { warm_reuse: schedulerEvent.warm_reuse === 1 }
                      : {}),
                    ...(typeof schedulerEvent.cold_start === 'number'
                      ? { cold_start: schedulerEvent.cold_start === 1 }
                      : {}),
                    ...(typeof schedulerMetadata.expected_rss_mb === 'number'
                      ? { expected_rss_mb: schedulerMetadata.expected_rss_mb }
                      : {}),
                    ...(typeof schedulerMetadata.current_rss_mb === 'number'
                      ? { current_rss_mb: schedulerMetadata.current_rss_mb }
                      : {}),
                    ...(typeof schedulerMetadata.peak_rss_mb === 'number'
                      ? { peak_rss_mb: schedulerMetadata.peak_rss_mb }
                      : {}),
                    ...(typeof schedulerMetadata.memory_limit_mb === 'number'
                      ? { memory_limit_mb: schedulerMetadata.memory_limit_mb }
                      : {}),
                    ...(typeof schedulerMetadata.control_plane_headroom_mb === 'number'
                      ? { control_plane_headroom_mb: schedulerMetadata.control_plane_headroom_mb }
                      : {}),
                    ...(typeof schedulerMetadata.active_expected_rss_mb === 'number'
                      ? { active_expected_rss_mb: schedulerMetadata.active_expected_rss_mb }
                      : {}),
                    ...(typeof schedulerMetadata.latency_ms === 'number'
                      ? { latency_ms: schedulerMetadata.latency_ms }
                      : {}),
                    ...(typeof schedulerMetadata.interruption_cause === 'string'
                      ? { interruption_cause: schedulerMetadata.interruption_cause }
                      : {}),
                  }
                : {}
            })()
          : {}),
        polling_guidance: buildPollingGuidance({
          tool: row.tool,
          status: row.status,
          progress: row.progress,
          timeout_ms: row.timeout,
        }),
      }))
      const activeRows = limitedRows.filter(
        (row: any) => row.status === 'queued' || row.status === 'running'
      )
      const activeAnalysisRunId = activeRows.find(
        (row: any) =>
          row.tool === ANALYSIS_STAGE_JOB_TOOL &&
          row.args &&
          typeof row.args === 'object' &&
          typeof row.args.run_id === 'string'
      )?.args?.run_id
      const summaryGuidance =
        activeRows.length > 0
          ? buildPollingGuidance({
              tool: activeRows[0].tool,
              status: activeRows[0].status,
              progress: activeRows[0].progress,
              timeout_ms: activeRows[0].timeout,
            })
          : null

      return buildJsonResult({
        ok: true,
        data: {
          queue_length: jobQueue.getQueueLength(),
          total_jobs: jobQueue.getTotalJobs(),
          count: limitedRows.length,
          jobs: limitedRows,
          polling_guidance: summaryGuidance,
          result_mode: 'queue_summary',
          tool_surface_role: 'compatibility',
          preferred_primary_tools: ['workflow.analyze.status'],
          recommended_next_tools:
            activeRows.length > 0
              ? activeAnalysisRunId
                ? ['workflow.analyze.status', 'task.status']
                : ['task.status']
              : [],
          next_actions:
            activeRows.length > 0
              ? [
                  activeAnalysisRunId
                    ? `Use workflow.analyze.status with run_id=${activeAnalysisRunId} for the primary staged-run view, and poll task.status only for raw job details.`
                    : 'Use polling_guidance to wait before the next queue check.',
                  'Switch to task.status(job_id) when you want detailed state for a specific job.',
                ]
              : ['Start or inspect another analysis tool; there are no active jobs to poll right now.'],
        },
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return buildJsonResult(
        {
          ok: false,
          errors: [message],
        },
        true
      )
    }
  }
}
