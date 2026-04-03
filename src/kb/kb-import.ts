/**
 * KB import — imports JSONL files with conflict resolution.
 */

import fs from 'fs/promises'
import { randomUUID } from 'crypto'
import type { DatabaseManager } from '../database.js'

export type ConflictStrategy = 'skip' | 'overwrite' | 'merge'

export interface ImportResult {
  inserted: number
  skipped: number
  merged: number
  errors: number
  total_lines: number
}

export async function importFromJsonl(
  db: DatabaseManager,
  filePath: string,
  conflictStrategy: ConflictStrategy = 'skip'
): Promise<ImportResult> {
  const content = await fs.readFile(filePath, 'utf8')
  const lines = content.split('\n').filter((l) => l.trim().length > 0)

  const result: ImportResult = {
    inserted: 0,
    skipped: 0,
    merged: 0,
    errors: 0,
    total_lines: lines.length,
  }

  for (const line of lines) {
    try {
      const entry = JSON.parse(line) as { type: string; data: Record<string, unknown> }

      if (entry.type === 'function_kb') {
        importFunctionKbEntry(db, entry.data, conflictStrategy, result)
      } else if (entry.type === 'sample_kb') {
        importSampleKbEntry(db, entry.data, conflictStrategy, result)
      } else {
        result.errors++
      }
    } catch {
      result.errors++
    }
  }

  return result
}

function importFunctionKbEntry(
  db: DatabaseManager,
  data: Record<string, unknown>,
  strategy: ConflictStrategy,
  result: ImportResult
): void {
  const id = String(data.id ?? randomUUID())
  const now = new Date().toISOString()

  // Check if exists
  const existing = db.queryOneSql<{ id: string; semantics_confidence: number }>(
    'SELECT id, semantics_confidence FROM function_kb WHERE id = ?',
    [id]
  )

  if (existing) {
    switch (strategy) {
      case 'skip':
        result.skipped++
        return
      case 'overwrite':
        db.runSql('DELETE FROM function_kb WHERE id = ?', [id])
        break
      case 'merge': {
        // Merge: keep higher confidence
        const newConfidence = Number(data.semantics_confidence ?? 0)
        if (newConfidence > existing.semantics_confidence) {
          db.runSql(
            `UPDATE function_kb SET 
              semantics_name = ?, semantics_explanation = ?, semantics_behavior = ?,
              semantics_confidence = ?, updated_at = ?
            WHERE id = ?`,
            [
              String(data.semantics_name ?? ''),
              String(data.semantics_explanation ?? ''),
              String(data.semantics_behavior ?? ''),
              newConfidence,
              now,
              id,
            ]
          )
        }
        // Merge feature vectors
        const existingRow = db.queryOneSql<{ features_apis_json: string; samples_json: string }>(
          'SELECT features_apis_json, samples_json FROM function_kb WHERE id = ?',
          [id]
        )
        if (existingRow) {
          const existingApis = safeParse(existingRow.features_apis_json) as string[]
          const newApis = (data.features_apis ?? []) as string[]
          const mergedApis = [...new Set([...existingApis, ...newApis])]

          const existingSamples = safeParse(existingRow.samples_json) as string[]
          const newSamples = (data.samples ?? []) as string[]
          const mergedSamples = [...new Set([...existingSamples, ...newSamples])]

          db.runSql(
            'UPDATE function_kb SET features_apis_json = ?, samples_json = ?, updated_at = ? WHERE id = ?',
            [JSON.stringify(mergedApis), JSON.stringify(mergedSamples), now, id]
          )
        }
        result.merged++
        return
      }
    }
  }

  // Insert
  db.runSql(
    `INSERT INTO function_kb (
      id, features_apis_json, features_strings_json, features_cfg_shape,
      features_crypto_constants_json, semantics_name, semantics_explanation,
      semantics_behavior, semantics_confidence, semantics_source,
      samples_json, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      JSON.stringify(data.features_apis ?? []),
      JSON.stringify(data.features_strings ?? []),
      String(data.features_cfg_shape ?? 'unknown'),
      JSON.stringify(data.features_crypto_constants ?? []),
      String(data.semantics_name ?? ''),
      String(data.semantics_explanation ?? ''),
      String(data.semantics_behavior ?? ''),
      Number(data.semantics_confidence ?? 0),
      String(data.semantics_source ?? 'import'),
      JSON.stringify(data.samples ?? []),
      String(data.created_at ?? now),
      now,
    ]
  )
  result.inserted++
}

function importSampleKbEntry(
  db: DatabaseManager,
  data: Record<string, unknown>,
  strategy: ConflictStrategy,
  result: ImportResult
): void {
  const id = String(data.id ?? randomUUID())
  const sampleId = String(data.sample_id ?? '')
  const now = new Date().toISOString()

  const existing = db.queryOneSql<{ id: string }>(
    'SELECT id FROM sample_kb WHERE sample_id = ?',
    [sampleId]
  )

  if (existing) {
    switch (strategy) {
      case 'skip':
        result.skipped++
        return
      case 'overwrite':
        db.runSql('DELETE FROM sample_kb WHERE sample_id = ?', [sampleId])
        break
      case 'merge': {
        // Merge tags
        const existingRow = db.queryOneSql<{ threat_intel_tags_json: string }>(
          'SELECT threat_intel_tags_json FROM sample_kb WHERE sample_id = ?',
          [sampleId]
        )
        if (existingRow) {
          const existingTags = safeParse(existingRow.threat_intel_tags_json) as string[]
          const newTags = (data.threat_intel_tags ?? []) as string[]
          const merged = [...new Set([...existingTags, ...newTags])]
          db.runSql(
            'UPDATE sample_kb SET threat_intel_tags_json = ?, updated_at = ? WHERE sample_id = ?',
            [JSON.stringify(merged), now, sampleId]
          )
        }
        result.merged++
        return
      }
    }
  }

  db.runSql(
    `INSERT INTO sample_kb (
      id, sample_id, threat_intel_family, threat_intel_campaign,
      threat_intel_tags_json, threat_intel_attribution, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      sampleId,
      data.threat_intel_family ?? null,
      data.threat_intel_campaign ?? null,
      JSON.stringify(data.threat_intel_tags ?? []),
      data.threat_intel_attribution ?? null,
      String(data.created_at ?? now),
      now,
    ]
  )
  result.inserted++
}

function safeParse(val: unknown): unknown {
  if (typeof val === 'string') {
    try {
      return JSON.parse(val)
    } catch {
      return []
    }
  }
  return val ?? []
}
