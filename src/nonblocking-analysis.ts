import { buildPollingGuidance } from './polling-guidance.js'
import { classifySampleSizeTier, type SampleSizeTier } from './analysis-coverage.js'
import type { Sample } from './database.js'
import type { JobQueue } from './job-queue.js'
import { JobPriority } from './job-queue.js'
import type { WorkerResult } from './types.js'

export interface DeferredToolResponseInput {
  jobQueue: JobQueue
  tool: string
  sampleId: string
  args: Record<string, unknown>
  timeoutMs: number
  nextTools?: string[]
  nextActions?: string[]
  summary?: string
  priority?: JobPriority
  metadata?: Record<string, unknown>
}

export function getSampleSizeTier(sample: Pick<Sample, 'size'>): SampleSizeTier {
  return classifySampleSizeTier(sample.size || 0)
}

export function shouldDeferLargeSample(sample: Pick<Sample, 'size'>, mode: string): boolean {
  const tier = getSampleSizeTier(sample)
  if (mode === 'full') {
    return tier !== 'small'
  }
  return false
}

export function buildDeferredToolResponse(input: DeferredToolResponseInput): WorkerResult {
  const jobId = input.jobQueue.enqueue({
    type: 'static',
    tool: input.tool,
    sampleId: input.sampleId,
    args: input.args,
    priority: input.priority || JobPriority.NORMAL,
    timeout: input.timeoutMs,
  })
  return {
    ok: true,
    data: {
      status: 'queued',
      sample_id: input.sampleId,
      result_mode: 'full',
      execution_state: 'queued',
      job_id: jobId,
      polling_guidance: buildPollingGuidance({
        tool: input.tool,
        status: 'queued',
        timeout_ms: input.timeoutMs,
      }),
      summary:
        input.summary ||
        `${input.tool} was deferred to the background queue because the requested mode is too expensive for synchronous MCP execution.`,
      recommended_next_tools: input.nextTools || ['task.status'],
      next_actions:
        input.nextActions || [
          'Poll task.status using the returned job_id instead of repeating the same heavy tool call immediately.',
        ],
      ...(input.metadata ? { metadata: input.metadata } : {}),
    },
    warnings: [
      'Heavy analysis was deferred to a background job to keep the MCP request nonblocking.',
    ],
    metrics: {
      elapsed_ms: 0,
      tool: input.tool,
      deferred: true,
    },
  }
}
