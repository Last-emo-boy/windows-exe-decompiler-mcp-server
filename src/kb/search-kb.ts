/**
 * Function Knowledge Base Search API
 * Tasks: collaborative-knowledge-base 3.1-3.5
 */

import type { DatabaseManager } from '../database.js'
import type { FunctionKbEntry } from './kb-database.js'

export interface SearchFunctionsQuery {
  name?: string
  apis?: string[]
  strings?: string[]
  behavior?: string
  minConfidence?: number
  source?: 'auto' | 'llm' | 'human'
  limit?: number
}

export interface SearchFunctionsResult {
  total: number
  results: Array<{
    id: string
    name: string
    explanation: string
    behavior: string
    confidence: number
    source: string
    samples: string[]
    matchScore: number
    matchReasons: string[]
  }>
}

export function searchFunctions(db: DatabaseManager, query: SearchFunctionsQuery): SearchFunctionsResult {
  const { name, apis, strings, behavior, minConfidence = 0, source, limit = 20 } = query
  
  const conditions: string[] = []
  const params: any[] = []
  
  if (name) {
    conditions.push('semantics_name LIKE ?')
    params.push(`%${name}%`)
  }
  if (behavior) {
    conditions.push('semantics_behavior LIKE ?')
    params.push(`%${behavior}%`)
  }
  if (minConfidence > 0) {
    conditions.push('semantics_confidence >= ?')
    params.push(minConfidence)
  }
  if (source) {
    conditions.push('semantics_source = ?')
    params.push(source)
  }
  
  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''
  
  const rows = db.querySql<any>(`
    SELECT * FROM function_kb
    ${whereClause}
    ORDER BY semantics_confidence DESC, updated_at DESC
    LIMIT ?
  `, [...params, limit])
  
  const results = rows.map(row => {
    const entry: FunctionKbEntry = {
      id: row.id,
      features: {
        apis: JSON.parse(row.features_apis_json),
        strings: JSON.parse(row.features_strings_json),
        cfg_shape: row.features_cfg_shape,
        crypto_constants: row.features_crypto_constants_json ? JSON.parse(row.features_crypto_constants_json) : undefined,
      },
      semantics: {
        name: row.semantics_name,
        explanation: row.semantics_explanation,
        behavior: row.semantics_behavior,
        confidence: row.semantics_confidence,
        source: row.semantics_source,
      },
      samples: JSON.parse(row.samples_json),
      created_at: row.created_at,
      updated_at: row.updated_at,
      user_id: row.user_id,
    }
    
    const { score, reasons } = calculateMatchScore(entry, query)
    
    return {
      id: entry.id,
      name: entry.semantics.name,
      explanation: entry.semantics.explanation,
      behavior: entry.semantics.behavior,
      confidence: entry.semantics.confidence,
      source: entry.semantics.source,
      samples: entry.samples,
      matchScore: score,
      matchReasons: reasons,
    }
  })
  
  results.sort((a, b) => b.matchScore - a.matchScore)
  
  return { total: results.length, results }
}

function calculateMatchScore(entry: FunctionKbEntry, query: SearchFunctionsQuery): { score: number; reasons: string[] } {
  let score = 0
  const reasons: string[] = []
  
  score += entry.semantics.confidence * 50
  reasons.push(`Confidence: ${(entry.semantics.confidence * 100).toFixed(0)}%`)
  
  if (query.apis && query.apis.length > 0) {
    const apiMatches = entry.features.apis.filter(api =>
      query.apis!.some(qApi => api.toLowerCase().includes(qApi.toLowerCase()) || qApi.toLowerCase().includes(api.toLowerCase()))
    )
    if (apiMatches.length > 0) {
      score += Math.min(apiMatches.length * 10, 30)
      reasons.push(`API matches: ${apiMatches.length}`)
    }
  }
  
  if (query.strings && query.strings.length > 0) {
    const stringMatches = entry.features.strings.filter(str =>
      query.strings!.some(qStr => str.toLowerCase().includes(qStr.toLowerCase()) || qStr.toLowerCase().includes(str.toLowerCase()))
    )
    if (stringMatches.length > 0) {
      score += Math.min(stringMatches.length * 5, 20)
      reasons.push(`String matches: ${stringMatches.length}`)
    }
  }
  
  if (query.behavior && entry.semantics.behavior.toLowerCase().includes(query.behavior.toLowerCase())) {
    score += 15
    reasons.push('Behavior match')
  }
  
  if (entry.semantics.source === 'human') { score += 10; reasons.push('Human verified') }
  else if (entry.semantics.source === 'llm') { score += 5; reasons.push('LLM reviewed') }
  
  const daysSinceUpdate = (Date.now() - new Date(entry.updated_at).getTime()) / (1000 * 60 * 60 * 24)
  if (daysSinceUpdate < 30) { score += 5; reasons.push('Recently updated') }
  
  return { score: Math.min(score, 100), reasons }
}
