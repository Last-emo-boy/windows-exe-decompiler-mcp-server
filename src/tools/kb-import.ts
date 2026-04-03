/**
 * kb.import MCP tool — import JSONL knowledge base file with conflict resolution.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { importFromJsonl, type ConflictStrategy } from '../kb/kb-import.js'

const TOOL_NAME = 'kb.import'

export const KbImportInputSchema = z.object({
  file_path: z.string().describe('Path to JSONL file to import'),
  conflict_strategy: z
    .enum(['skip', 'overwrite', 'merge'])
    .optional()
    .default('skip')
    .describe('skip: ignore duplicates, overwrite: replace, merge: combine fields'),
})

export const KbImportOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const kbImportToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Import a JSONL knowledge base file exported by kb.export, with configurable conflict resolution strategy.',
  inputSchema: KbImportInputSchema,
  outputSchema: KbImportOutputSchema,
}

export function createKbImportHandler(
  _workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: z.infer<typeof KbImportInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      const result = await importFromJsonl(
        database,
        args.file_path,
        args.conflict_strategy as ConflictStrategy
      )

      return {
        ok: true,
        data: result,
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
