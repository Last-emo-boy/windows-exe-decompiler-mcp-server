/**
 * Function Knowledge Base API
 * Tasks: collaborative-knowledge-base 2.1-2.6
 */

import crypto from 'crypto'
import type { DatabaseManager } from '../database.js'
import type { FunctionKbEntry } from './kb-database.js'

export interface ContributeFunctionData {
  address: string
  name: string
  explanation: string
  behavior: string
  features: {
    apis: string[]
    strings: string[]
    cfg_shape: string
    crypto_constants?: string[]
  }
  source: 'auto' | 'llm' | 'human'
  sampleId: string
  userId?: string
}

export function calculateConfidence(source: 'auto' | 'llm' | 'human'): number {
  switch (source) {
    case 'auto': return 0.3 + Math.random() * 0.2
    case 'llm': return 0.6 + Math.random() * 0.2
    case 'human': return 0.9 + Math.random() * 0.1
  }
}

export async function contributeFunction(
  db: DatabaseManager,
  data: ContributeFunctionData
): Promise<string> {
  const id = crypto.randomUUID()
  const now = new Date().toISOString()
  const confidence = calculateConfidence(data.source)
  
  const entry: FunctionKbEntry = {
    id,
    features: data.features,
    semantics: {
      name: data.name,
      explanation: data.explanation,
      behavior: data.behavior,
      confidence,
      source: data.source,
    },
    samples: [data.sampleId],
    created_at: now,
    updated_at: now,
    user_id: data.userId,
  }
  
  db.runSql(`
    INSERT INTO function_kb (
      id, features_apis_json, features_strings_json, features_cfg_shape,
      features_crypto_constants_json, semantics_name, semantics_explanation,
      semantics_behavior, semantics_confidence, semantics_source,
      samples_json, created_at, updated_at, user_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    id,
    JSON.stringify(entry.features.apis),
    JSON.stringify(entry.features.strings),
    entry.features.cfg_shape,
    entry.features.crypto_constants ? JSON.stringify(entry.features.crypto_constants) : null,
    entry.semantics.name,
    entry.semantics.explanation,
    entry.semantics.behavior,
    entry.semantics.confidence,
    entry.semantics.source,
    JSON.stringify(entry.samples),
    entry.created_at,
    entry.updated_at,
    entry.user_id || null
  ])
  
  return id
}

export async function updateFunction(
  db: DatabaseManager,
  id: string,
  data: Partial<ContributeFunctionData>
): Promise<void> {
  const now = new Date().toISOString()
  const existing = await getFunctionById(db, id)
  if (!existing) throw new Error(`Function KB entry not found: ${id}`)
  
  if (data.name) existing.semantics.name = data.name
  if (data.explanation) existing.semantics.explanation = data.explanation
  if (data.behavior) existing.semantics.behavior = data.behavior
  if (data.features) existing.features = data.features
  if (data.source) {
    existing.semantics.source = data.source
    existing.semantics.confidence = calculateConfidence(data.source)
  }
  if (data.sampleId && !existing.samples.includes(data.sampleId)) {
    existing.samples.push(data.sampleId)
  }
  existing.updated_at = now
  
  db.runSql(`
    UPDATE function_kb SET
      features_apis_json = ?, features_strings_json = ?, features_cfg_shape = ?,
      features_crypto_constants_json = ?, semantics_name = ?, semantics_explanation = ?,
      semantics_behavior = ?, semantics_confidence = ?, semantics_source = ?,
      samples_json = ?, updated_at = ?, user_id = ?
    WHERE id = ?
  `, [
    JSON.stringify(existing.features.apis),
    JSON.stringify(existing.features.strings),
    existing.features.cfg_shape,
    existing.features.crypto_constants ? JSON.stringify(existing.features.crypto_constants) : null,
    existing.semantics.name,
    existing.semantics.explanation,
    existing.semantics.behavior,
    existing.semantics.confidence,
    existing.semantics.source,
    JSON.stringify(existing.samples),
    now,
    existing.user_id || null,
    id
  ])
}

async function getFunctionById(db: DatabaseManager, id: string): Promise<FunctionKbEntry | null> {
  const rows = db.querySql<any>('SELECT * FROM function_kb WHERE id = ?', [id])
  const row = rows[0]
  if (!row) return null
  
  return {
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
}
