/**
 * KB Integration with LLM Review Workflows
 * Tasks: collaborative-knowledge-base 4.1-4.5
 */

import type { DatabaseManager } from '../database.js'
import { searchFunctions, type SearchFunctionsQuery } from './search-kb.js'
import { contributeFunction, type ContributeFunctionData } from './function-kb.js'

export interface KbIntegrationOptions {
  useKb?: boolean
  minConfidence?: number
  contributeAfterReview?: boolean
  userId?: string
}

export async function checkKbForFunctionNaming(
  db: DatabaseManager,
  functionData: { address: string; calledApis?: string[]; referencedStrings?: string[]; cfgHash?: string },
  options: KbIntegrationOptions = {}
): Promise<{ found: boolean; suggestions?: Array<{ name: string; confidence: number; source: string; explanation: string }> } | null> {
  const { useKb = true, minConfidence = 0.6 } = options
  if (!useKb) return null
  
  const query: SearchFunctionsQuery = { apis: functionData.calledApis, strings: functionData.referencedStrings, minConfidence, limit: 5 }
  const results = searchFunctions(db, query)
  
  if (results.total === 0) return { found: false }
  
  return {
    found: true,
    suggestions: results.results.slice(0, 3).map(r => ({ name: r.name, confidence: r.confidence, source: r.source, explanation: r.explanation })),
  }
}

export async function contributeAfterLlmReview(
  db: DatabaseManager,
  reviewResult: { address: string; name: string; explanation: string; behavior: string; calledApis?: string[]; referencedStrings?: string[]; cfgHash?: string; sampleId: string },
  options: KbIntegrationOptions = {}
): Promise<string> {
  const { contributeAfterReview = true, userId } = options
  if (!contributeAfterReview) return ''
  
  const contributionData: ContributeFunctionData = {
    address: reviewResult.address,
    name: reviewResult.name,
    explanation: reviewResult.explanation,
    behavior: reviewResult.behavior,
    source: 'llm',
    features: { apis: reviewResult.calledApis || [], strings: reviewResult.referencedStrings || [], cfg_shape: reviewResult.cfgHash || 'unknown' },
    sampleId: reviewResult.sampleId,
    userId,
  }
  
  return await contributeFunction(db, contributionData)
}

export const KB_INTEGRATION_HELP = `
This workflow integrates with the Knowledge Base (KB):
- Checks KB before LLM review for faster responses
- Contributes results back to KB after successful review
- Parameters: use_kb, min_confidence, contribute_after_review, user_id
`
