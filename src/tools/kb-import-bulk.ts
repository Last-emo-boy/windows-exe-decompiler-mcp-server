/**
 * kb.import.bulk MCP tool — import knowledge from capa rules, MISP events, or JSONL exports.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { parseCapaRules } from '../kb/capa-import.js'
import { parseMispEvents } from '../kb/misp-import.js'
import { importFromJsonl } from '../kb/kb-import.js'
import { loadSeedDataIfEmpty } from '../kb/seed-loader.js'

const TOOL_NAME = 'kb.import.bulk'

export const KbImportBulkInputSchema = z.object({
  source_type: z
    .enum(['capa', 'misp', 'jsonl', 'seed'])
    .describe('Type of knowledge source to import'),
  source_path: z
    .string()
    .optional()
    .describe('Path to source file or directory (not needed for seed)'),
  conflict_strategy: z
    .enum(['skip', 'overwrite', 'merge'])
    .optional()
    .default('skip')
    .describe('How to handle duplicate entries'),
})

export const KbImportBulkOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const kbImportBulkToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Bulk-import knowledge base entries from capa rules, MISP threat intel events, JSONL exports, or seed the built-in Windows API knowledge.',
  inputSchema: KbImportBulkInputSchema,
  outputSchema: KbImportBulkOutputSchema,
}

export function createKbImportBulkHandler(
  _workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: z.infer<typeof KbImportBulkInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const errors: string[] = []

    try {
      let result: Record<string, unknown>

      switch (args.source_type) {
        case 'seed': {
          const seedResult = await loadSeedDataIfEmpty(database)
          result = { source: 'seed', entries_loaded: seedResult.loaded }
          break
        }
        case 'capa': {
          if (!args.source_path) {
            return { ok: false, errors: ['source_path required for capa import'] }
          }
          const entries = await parseCapaRules(args.source_path)
          let inserted = 0
          const now = new Date().toISOString()
          for (const entry of entries) {
            try {
              database.runSql(
                `INSERT OR IGNORE INTO function_kb (
                  id, features_apis_json, features_strings_json, features_cfg_shape,
                  semantics_name, semantics_explanation, semantics_behavior,
                  semantics_confidence, semantics_source, samples_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                  crypto.randomUUID(),
                  JSON.stringify(entry.apis),
                  JSON.stringify(entry.strings),
                  'unknown',
                  entry.rule_name,
                  entry.description,
                  (entry.attack_techniques || []).join(', '),
                  0.7,
                  'capa',
                  JSON.stringify([]),
                  now,
                  now,
                ]
              )
              inserted++
            } catch {
              errors.push(`Failed to insert capa rule: ${entry.rule_name}`)
            }
          }
          result = { source: 'capa', rules_parsed: entries.length, inserted }
          break
        }
        case 'misp': {
          if (!args.source_path) {
            return { ok: false, errors: ['source_path required for misp import'] }
          }
          const events = await parseMispEvents(args.source_path)
          let inserted = 0
          const now = new Date().toISOString()
          for (const event of events) {
            try {
              database.runSql(
                `INSERT OR IGNORE INTO sample_kb (
                  id, sample_id, threat_intel_family, threat_intel_campaign,
                  threat_intel_tags_json, threat_intel_attribution, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                  crypto.randomUUID(),
                  '', // No sample_id for MISP events yet
                  event.family ?? null,
                  event.campaign ?? null,
                  JSON.stringify(event.tags),
                  event.attribution ?? null,
                  now,
                  now,
                ]
              )
              inserted++
            } catch {
              errors.push(`Failed to insert MISP event: ${event.event_id}`)
            }
          }
          result = { source: 'misp', events_parsed: events.length, inserted }
          break
        }
        case 'jsonl': {
          if (!args.source_path) {
            return { ok: false, errors: ['source_path required for jsonl import'] }
          }
          const importResult = await importFromJsonl(
            database,
            args.source_path,
            args.conflict_strategy
          )
          result = { source: 'jsonl', ...importResult }
          break
        }
        default:
          return { ok: false, errors: [`Unknown source type: ${args.source_type}`] }
      }

      return {
        ok: true,
        data: result,
        errors: errors.length > 0 ? errors : undefined,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
