import { z } from 'zod'

export const PollingGuidanceSchema = z.object({
  recommended_wait_ms: z.number().int().positive(),
  recommended_wait_seconds: z.number().int().positive(),
  prefer_sleep: z.boolean(),
  reason: z.string(),
  guidance: z.string(),
})

export type PollingGuidance = z.infer<typeof PollingGuidanceSchema>

const VERY_LONG_RUNNING_TOOLS = new Set([
  'workflow.deep_static',
])

const LONG_RUNNING_TOOLS = new Set([
  'ghidra.analyze',
  'workflow.reconstruct',
  'workflow.semantic_name_review',
  'workflow.function_explanation_review',
  'workflow.module_reconstruction_review',
])

function roundToWholeSeconds(ms: number): number {
  return Math.max(1, Math.ceil(ms / 1000))
}

export function buildPollingGuidance(input: {
  tool?: string | null
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress?: number | null
  timeout_ms?: number | null
}): PollingGuidance | null {
  if (input.status === 'completed' || input.status === 'failed' || input.status === 'cancelled') {
    return null
  }

  const tool = input.tool || null
  const progress = typeof input.progress === 'number' ? input.progress : null
  const timeoutMs = typeof input.timeout_ms === 'number' ? input.timeout_ms : null

  let recommendedWaitMs =
    input.status === 'queued'
      ? 10_000
      : 12_000

  let reason = 'Background analysis is still active.'

  if (tool && VERY_LONG_RUNNING_TOOLS.has(tool)) {
    recommendedWaitMs = input.status === 'queued' ? 30_000 : 30_000
    reason = 'This workflow often runs for many minutes, so sparse polling is more efficient.'
  } else if (tool && LONG_RUNNING_TOOLS.has(tool)) {
    recommendedWaitMs = input.status === 'queued' ? 20_000 : 20_000
    reason = 'This analysis usually takes long enough that immediate re-checks waste tokens.'
  }

  if (progress !== null) {
    if (progress >= 90) {
      recommendedWaitMs = Math.min(recommendedWaitMs, 5_000)
      reason = 'The job is near completion, so a shorter wait is reasonable.'
    } else if (progress >= 70) {
      recommendedWaitMs = Math.min(recommendedWaitMs, 8_000)
      reason = 'The job is in a late stage, so a shorter follow-up wait is reasonable.'
    } else if (progress >= 35) {
      recommendedWaitMs = Math.min(recommendedWaitMs, 12_000)
      reason = 'The job is already making visible progress.'
    } else if (progress <= 10 && input.status === 'queued') {
      recommendedWaitMs = Math.max(recommendedWaitMs, 20_000)
      reason = 'The job is still queued or just starting, so immediate polling is unlikely to add value.'
    }
  }

  if (timeoutMs && timeoutMs >= 45 * 60 * 1000) {
    recommendedWaitMs = Math.max(recommendedWaitMs, 30_000)
    reason = 'The configured timeout is large, which usually indicates a long-running reverse-engineering task.'
  } else if (timeoutMs && timeoutMs >= 10 * 60 * 1000) {
    recommendedWaitMs = Math.max(recommendedWaitMs, 20_000)
  }

  const recommendedWaitSeconds = roundToWholeSeconds(recommendedWaitMs)
  return {
    recommended_wait_ms: recommendedWaitMs,
    recommended_wait_seconds: recommendedWaitSeconds,
    prefer_sleep: true,
    reason,
    guidance:
      `Prefer one client-side sleep/wait for about ${recommendedWaitSeconds}s before calling task.status again, instead of repeated immediate polling.`,
  }
}
