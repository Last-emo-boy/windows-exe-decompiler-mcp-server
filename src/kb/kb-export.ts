/**
 * KB export — exports function_kb and sample_kb as JSONL.
 */

import type { DatabaseManager } from '../database.js'

export interface KbExportEntry {
  type: 'function_kb' | 'sample_kb'
  data: Record<string, unknown>
}

export function exportToJsonl(
  db: DatabaseManager,
  filters?: {
    minConfidence?: number
    since?: string
    entryType?: 'function_kb' | 'sample_kb' | 'all'
  }
): string {
  const lines: string[] = []
  const entryType = filters?.entryType ?? 'all'

  // Export function_kb entries
  if (entryType === 'all' || entryType === 'function_kb') {
    let query = 'SELECT * FROM function_kb WHERE 1=1'
    const params: unknown[] = []

    if (filters?.minConfidence !== undefined) {
      query += ' AND semantics_confidence >= ?'
      params.push(filters.minConfidence)
    }
    if (filters?.since) {
      query += ' AND updated_at >= ?'
      params.push(filters.since)
    }

    const rows = db.querySql<Record<string, unknown>>(query, params)
    for (const row of rows) {
      lines.push(
        JSON.stringify({
          type: 'function_kb',
          data: {
            id: row.id,
            features_apis: safeParse(row.features_apis_json),
            features_strings: safeParse(row.features_strings_json),
            features_cfg_shape: row.features_cfg_shape,
            features_crypto_constants: safeParse(row.features_crypto_constants_json),
            semantics_name: row.semantics_name,
            semantics_explanation: row.semantics_explanation,
            semantics_behavior: row.semantics_behavior,
            semantics_confidence: row.semantics_confidence,
            semantics_source: row.semantics_source,
            samples: safeParse(row.samples_json),
            created_at: row.created_at,
            updated_at: row.updated_at,
          },
        })
      )
    }
  }

  // Export sample_kb entries
  if (entryType === 'all' || entryType === 'sample_kb') {
    let query = 'SELECT * FROM sample_kb WHERE 1=1'
    const params: unknown[] = []

    if (filters?.since) {
      query += ' AND updated_at >= ?'
      params.push(filters.since)
    }

    const rows = db.querySql<Record<string, unknown>>(query, params)
    for (const row of rows) {
      lines.push(
        JSON.stringify({
          type: 'sample_kb',
          data: {
            id: row.id,
            sample_id: row.sample_id,
            threat_intel_family: row.threat_intel_family,
            threat_intel_campaign: row.threat_intel_campaign,
            threat_intel_tags: safeParse(row.threat_intel_tags_json),
            threat_intel_attribution: row.threat_intel_attribution,
            created_at: row.created_at,
            updated_at: row.updated_at,
          },
        })
      )
    }
  }

  return lines.join('\n')
}

function safeParse(val: unknown): unknown {
  if (typeof val === 'string') {
    try {
      return JSON.parse(val)
    } catch {
      return val
    }
  }
  return val
}
