/**
 * Auto LLM Trigger
 * Intelligently decides when to use LLM assistance
 * Tasks: llm-assisted-analysis-enhancement 1.3
 */

import { logger } from '../logger.js'

export interface TriggerDecision {
  shouldTrigger: boolean
  reason: string
  confidence: number
  suggestedTask: 'summarize' | 'explain' | 'recommend' | 'review'
}

export interface TriggerOptions {
  confidenceThreshold?: number  // Trigger if confidence < threshold (default: 0.6)
  complexityThreshold?: number  // Trigger if complexity > threshold (default: 0.8)
  userPreference?: 'always' | 'never' | 'auto'  // User preference (default: 'auto')
}

/**
 * Decide whether to trigger LLM assistance
 */
export function shouldTriggerLLM(
  context: {
    confidence?: number
    complexity?: number
    isNewPattern?: boolean
    userPreference?: 'always' | 'never' | 'auto'
  },
  options: TriggerOptions = {}
): TriggerDecision {
  const {
    confidenceThreshold = 0.6,
    complexityThreshold = 0.8,
    userPreference = 'auto',
  } = options

  // Check user preference first
  if (userPreference === 'never') {
    return {
      shouldTrigger: false,
      reason: 'User preference: LLM disabled',
      confidence: 1.0,
      suggestedTask: 'review',
    }
  }

  if (userPreference === 'always') {
    return {
      shouldTrigger: true,
      reason: 'User preference: LLM always enabled',
      confidence: 1.0,
      suggestedTask: 'review',
    }
  }

  // Auto mode: evaluate multiple factors
  const factors: Array<{ name: string; weight: number; triggered: boolean }> = []

  // Factor 1: Low confidence
  if (context.confidence !== undefined && context.confidence < confidenceThreshold) {
    factors.push({
      name: 'Low confidence',
      weight: 0.4,
      triggered: true,
    })
  }

  // Factor 2: High complexity
  if (context.complexity !== undefined && context.complexity > complexityThreshold) {
    factors.push({
      name: 'High complexity',
      weight: 0.3,
      triggered: true,
    })
  }

  // Factor 3: New pattern
  if (context.isNewPattern) {
    factors.push({
      name: 'New pattern detected',
      weight: 0.3,
      triggered: true,
    })
  }

  // Calculate decision
  const triggeredFactors = factors.filter(f => f.triggered)
  const totalWeight = factors.reduce((sum, f) => sum + f.weight, 0)
  const triggeredWeight = triggeredFactors.reduce((sum, f) => sum + f.weight, 0)
  const triggerScore = totalWeight > 0 ? triggeredWeight / totalWeight : 0

  const shouldTrigger = triggerScore >= 0.5

  // Determine suggested task
  let suggestedTask: TriggerDecision['suggestedTask'] = 'review'
  if (context.confidence !== undefined && context.confidence < 0.4) {
    suggestedTask = 'explain'  // Very low confidence: need explanation
  } else if (triggeredFactors.some(f => f.name === 'High complexity')) {
    suggestedTask = 'summarize'  // High complexity: need summary
  } else if (context.isNewPattern) {
    suggestedTask = 'recommend'  // New pattern: need recommendations
  }

  // Build reason
  const reasons = triggeredFactors.map(f => f.name)
  const reason = shouldTrigger
    ? `Triggering LLM: ${reasons.join(', ') || 'Multiple factors'}`
    : `Not triggering LLM: confidence=${context.confidence?.toFixed(2) || 'N/A'}, complexity=${context.complexity?.toFixed(2) || 'N/A'}`

  return {
    shouldTrigger,
    reason,
    confidence: triggerScore,
    suggestedTask,
  }
}

/**
 * Calculate complexity score for a function or sample
 */
export function calculateComplexity(metrics: {
  functionCount?: number
  callDepth?: number
  xrefCount?: number
  stringCount?: number
}): number {
  let score = 0

  // Function count (0-0.25)
  if (metrics.functionCount !== undefined) {
    score += Math.min(metrics.functionCount / 1000, 0.25)
  }

  // Call depth (0-0.25)
  if (metrics.callDepth !== undefined) {
    score += Math.min(metrics.callDepth / 20, 0.25)
  }

  // Cross-reference count (0-0.25)
  if (metrics.xrefCount !== undefined) {
    score += Math.min(metrics.xrefCount / 500, 0.25)
  }

  // String count (0-0.25)
  if (metrics.stringCount !== undefined) {
    score += Math.min(metrics.stringCount / 200, 0.25)
  }

  return Math.min(score, 1.0)
}

/**
 * Log trigger decision for monitoring
 */
export function logTriggerDecision(
  sampleId: string,
  decision: TriggerDecision,
  context: any
): void {
  logger.info({ sampleId, shouldTrigger: decision.shouldTrigger, reason: decision.reason }, 'LLM trigger decision')
}
