/**
 * KB seed data loader — loads Windows API semantics on first access.
 */

import fs from 'fs/promises'
import path from 'path'
import { fileURLToPath } from 'url'
import { randomUUID } from 'crypto'
import type { DatabaseManager } from '../database.js'
import { logger } from '../logger.js'

export interface ApiSeedEntry {
  api: string
  semantic: string
  category: string
  risk: string
  cwe: string[]
}

export async function loadSeedDataIfEmpty(db: DatabaseManager): Promise<{ loaded: number }> {
  // Check if function_kb is empty
  const row = db.queryOneSql<{ count: number }>('SELECT COUNT(*) as count FROM function_kb')
  if (row && row.count > 0) {
    return { loaded: 0 }
  }

  // Load seed data
  const seedPath = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    '..',
    'data',
    'windows-api-semantics.json'
  )

  let entries: ApiSeedEntry[]
  try {
    const content = await fs.readFile(seedPath, 'utf8')
    entries = JSON.parse(content)
  } catch (err) {
    logger.warn(`Failed to load seed data from ${seedPath}: ${err}`)
    return { loaded: 0 }
  }

  let loaded = 0
  const now = new Date().toISOString()

  for (const entry of entries) {
    try {
      db.runSql(
        `INSERT OR IGNORE INTO function_kb (
          id, features_apis_json, features_strings_json, features_cfg_shape,
          features_crypto_constants_json, semantics_name, semantics_explanation,
          semantics_behavior, semantics_confidence, semantics_source,
          samples_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          randomUUID(),
          JSON.stringify([entry.api]),
          JSON.stringify([]),
          'unknown',
          JSON.stringify([]),
          entry.api,
          `Windows API: ${entry.semantic} (${entry.category})`,
          entry.semantic,
          0.8,
          'auto',
          JSON.stringify([]),
          now,
          now,
        ]
      )
      loaded++
    } catch {
      // Ignore duplicate entries
    }
  }

  logger.info(`Loaded ${loaded} seed entries into function_kb`)
  return { loaded }
}
