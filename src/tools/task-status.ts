/**
 * task.status MCP tool
 * Query analysis task queue status and optional per-job details.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolHandler, ToolResult } from '../types.js'
import type { JobQueue, JobStatusType } from '../job-queue.js'
import { buildPollingGuidance } from '../polling-guidance.js'

const TOOL_NAME = 'task.status'

export const taskStatusInputSchema = z.object({
  job_id: z.string().optional().describe('Optional job id for single-job lookup'),
  status: z
    .enum(['queued', 'running', 'completed', 'failed', 'cancelled'])
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

export const taskStatusToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Get queue/running/completed status for analysis tasks, or inspect a specific job.',
  inputSchema: taskStatusInputSchema,
}

export function createTaskStatusHandler(jobQueue: JobQueue): ToolHandler {
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
        const status = detailedStatus || jobQueue.getStatus(input.job_id)
        if (!status) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    ok: false,
                    errors: [`Job not found: ${input.job_id}`],
                  },
                  null,
                  2
                ),
              },
            ],
            isError: true,
          }
        }

        const statusRecord = status as Record<string, unknown> & {
          status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
          progress?: number
          tool?: string
          timeout?: number
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  ok: true,
                  data: {
                    job: {
                      ...statusRecord,
                      polling_guidance: buildPollingGuidance({
                        tool: typeof statusRecord.tool === 'string' ? statusRecord.tool : null,
                        status: statusRecord.status,
                        progress: typeof statusRecord.progress === 'number' ? statusRecord.progress : null,
                        timeout_ms: typeof statusRecord.timeout === 'number' ? statusRecord.timeout : null,
                      }),
                    },
                    result: input.include_result ? jobQueue.getResult(input.job_id) : undefined,
                  },
                },
                null,
                2
              ),
            },
          ],
        }
      }

      const rows = listStatus
        ? listStatus.call(jobQueue, input.status)
        : jobQueue.getJobsByStatus(input.status || 'queued')
      const limitedRows = rows.slice(0, input.limit).map((row: any) => ({
        ...row,
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
      const summaryGuidance =
        activeRows.length > 0
          ? buildPollingGuidance({
              tool: activeRows[0].tool,
              status: activeRows[0].status,
              progress: activeRows[0].progress,
              timeout_ms: activeRows[0].timeout,
            })
          : null

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                ok: true,
                data: {
                  queue_length: jobQueue.getQueueLength(),
                  total_jobs: jobQueue.getTotalJobs(),
                  count: limitedRows.length,
                  jobs: limitedRows,
                  polling_guidance: summaryGuidance,
                },
              },
              null,
              2
            ),
          },
        ],
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                ok: false,
                errors: [message],
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      }
    }
  }
}
