/**
 * Async Tool Wrapper
 * Wraps long-running tools to return immediately with job_id
 * Tasks: mcp-async-job-pattern 2.1-2.5
 */

import type { ToolArgs, WorkerResult } from './types.js'
import type { JobQueue } from './job-queue.js'
import type { DatabaseManager } from './database.js'
import { TOOL_DURATION_ESTIMATES } from './job-queue.js'

/**
 * Create async wrapper for long-running tools
 * 
 * @param toolName - Name of the tool to wrap
 * @param handler - Original tool handler
 * @param jobQueue - Job queue instance
 * @param database - Database instance for persistence
 * @returns Wrapped handler that returns immediately with job_id
 */
export function createAsyncToolWrapper(
  toolName: string,
  handler: (args: ToolArgs) => Promise<WorkerResult>,
  jobQueue: JobQueue,
  _database: DatabaseManager
): (args: ToolArgs) => Promise<WorkerResult> {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const sampleId = (args as any).sample_id
    
    // Get estimated duration for this tool
    const estimatedDurationMs = TOOL_DURATION_ESTIMATES[toolName] || TOOL_DURATION_ESTIMATES.default
    
    // Create job in queue (the queue is responsible for any database persistence)
    const jobId = jobQueue.enqueue({
      type: 'static',
      tool: toolName,
      sampleId,
      args,
      estimatedDurationMs,
      timeout: 60 * 60 * 1000, // 1 hour timeout
      priority: 5, // Normal priority
    })
    
    // Return immediately with job_id and polling guidance
    return {
      ok: true,
      data: {
        status: 'queued',
        job_id: jobId,
        message: `${toolName} job queued. Use task.status to check progress.`,
        polling_guidance: {
          check_interval_ms: 5000,
          status_tool: 'task.status',
          estimated_duration_ms: estimatedDurationMs,
          estimated_duration_human: formatDuration(estimatedDurationMs),
        },
      },
      metrics: {
        elapsed_ms: 1, // Return immediately
        tool: toolName,
      },
    }
  }
}

/**
 * Format duration in human-readable format
 */
export function formatDuration(ms: number): string {
  const minutes = Math.ceil(ms / 60000)
  if (minutes < 1) return 'less than 1 minute'
  if (minutes < 60) return `${minutes} minute${minutes > 1 ? 's' : ''}`
  const hours = Math.ceil(minutes / 60)
  return `${hours} hour${hours > 1 ? 's' : ''}`
}

/**
 * List of long-running tools that should use async wrapper
 */
export const LONG_RUNNING_TOOLS = [
  'ghidra.analyze',
  'workflow.triage',
  'workflow.deep_static',
  'workflow.reconstruct',
  'workflow.summarize',
  'strings.floss.decode',
] as const

export type LongRunningTool = typeof LONG_RUNNING_TOOLS[number]
