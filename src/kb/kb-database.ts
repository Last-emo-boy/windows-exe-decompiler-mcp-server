/**
 * Knowledge Base Database Schema
 * Tasks: collaborative-knowledge-base 1.1-1.5
 */

import type { DatabaseManager } from '../database.js'
import { logger } from '../logger.js'

/**
 * Function KB entry
 */
export interface FunctionKbEntry {
  id: string
  features: {
    apis: string[]
    strings: string[]
    cfg_shape: string
    crypto_constants?: string[]
  }
  semantics: {
    name: string
    explanation: string
    behavior: string
    confidence: number
    source: 'auto' | 'llm' | 'human'
  }
  samples: string[]
  created_at: string
  updated_at: string
  user_id?: string
}

/**
 * Sample KB entry
 */
export interface SampleKbEntry {
  id: string
  sample_id: string
  threat_intel: {
    family?: string
    campaign?: string
    tags: string[]
    attribution?: string
  }
  created_at: string
  updated_at: string
  user_id?: string
}

/**
 * Initialize knowledge base tables
 * Tasks: collaborative-knowledge-base 1.1, 1.2, 1.3
 */
export function initializeKnowledgeBase(db: DatabaseManager): void {
  // Create function_kb table
  db.runSql(`
    CREATE TABLE IF NOT EXISTS function_kb (
      id TEXT PRIMARY KEY,
      features_apis_json TEXT NOT NULL,
      features_strings_json TEXT NOT NULL,
      features_cfg_shape TEXT NOT NULL,
      features_crypto_constants_json TEXT,
      semantics_name TEXT NOT NULL,
      semantics_explanation TEXT NOT NULL,
      semantics_behavior TEXT NOT NULL,
      semantics_confidence REAL NOT NULL,
      semantics_source TEXT NOT NULL,
      samples_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      user_id TEXT
    )
  `)
  
  // Create indexes for function_kb
  db.runSql(`
    CREATE INDEX IF NOT EXISTS idx_function_kb_name ON function_kb(semantics_name)
  `)
  db.runSql(`
    CREATE INDEX IF NOT EXISTS idx_function_kb_confidence ON function_kb(semantics_confidence DESC)
  `)
  db.runSql(`
    CREATE INDEX IF NOT EXISTS idx_function_kb_updated ON function_kb(updated_at DESC)
  `)
  
  // Create sample_kb table
  db.runSql(`
    CREATE TABLE IF NOT EXISTS sample_kb (
      id TEXT PRIMARY KEY,
      sample_id TEXT NOT NULL UNIQUE,
      threat_intel_family TEXT,
      threat_intel_campaign TEXT,
      threat_intel_tags_json TEXT,
      threat_intel_attribution TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      user_id TEXT
    )
  `)
  
  // Create indexes for sample_kb
  db.runSql(`
    CREATE INDEX IF NOT EXISTS idx_sample_kb_sample ON sample_kb(sample_id)
  `)
  db.runSql(`
    CREATE INDEX IF NOT EXISTS idx_sample_kb_family ON sample_kb(threat_intel_family)
  `)
  
  // Create kb_index table for feature-based search
  db.runSql(`
    CREATE TABLE IF NOT EXISTS kb_index (
      id TEXT PRIMARY KEY,
      entry_type TEXT NOT NULL,
      entry_id TEXT NOT NULL,
      api_hash TEXT,
      string_hash TEXT,
      feature_vector_json TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `)
  
  // Create indexes for kb_index
  db.runSql(`
    CREATE INDEX IF NOT EXISTS idx_kb_index_type ON kb_index(entry_type, entry_id)
  `)
  db.runSql(`
    CREATE INDEX IF NOT EXISTS idx_kb_index_api_hash ON kb_index(api_hash)
  `)
  db.runSql(`
    CREATE INDEX IF NOT EXISTS idx_kb_index_string_hash ON kb_index(string_hash)
  `)
  
  logger.info('Knowledge base tables initialized')
}

/**
 * Get KB statistics
 */
export function getKbStats(db: DatabaseManager): {
  totalFunctions: number
  totalSamples: number
  totalIndexEntries: number
} {
  const funcRow = db.queryOneSql<{ count: number }>('SELECT COUNT(*) as count FROM function_kb')
  const sampleRow = db.queryOneSql<{ count: number }>('SELECT COUNT(*) as count FROM sample_kb')
  const indexRow = db.queryOneSql<{ count: number }>('SELECT COUNT(*) as count FROM kb_index')
  
  return {
    totalFunctions: funcRow?.count || 0,
    totalSamples: sampleRow?.count || 0,
    totalIndexEntries: indexRow?.count || 0,
  }
}
