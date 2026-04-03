/**
 * kb.export MCP tool — export knowledge base entries as JSONL.
 */

import { z } from 'zod'
import fs from 'fs/promises'
import type { ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { exportToJsonl } from '../kb/kb-export.js'

const TOOL_NAME = 'kb.export'

export const KbExportInputSchema = z.object({
  output_path: z.string().describe('File path to write the JSONL export'),
  min_confidence: z
    .number()
    .min(0)
    .max(1)
    .optional()
    .describe('Minimum confidence threshold for function_kb entries'),
  since: z
    .string()
    .optional()
    .describe('Only export entries updated after this ISO date'),
  entry_type: z
    .enum(['function_kb', 'sample_kb', 'all'])
    .optional()
    .default('all')
    .describe('Which entry types to export'),
})

export const KbExportOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const kbExportToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Export knowledge base entries (function_kb and/or sample_kb) as JSONL for sharing or backup.',
  inputSchema: KbExportInputSchema,
  outputSchema: KbExportOutputSchema,
}

export function createKbExportHandler(
  _workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: z.infer<typeof KbExportInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      const jsonl = exportToJsonl(database, {
        minConfidence: args.min_confidence,
        since: args.since,
        entryType: args.entry_type === 'all' ? undefined : args.entry_type,
      })

      await fs.writeFile(args.output_path, jsonl, 'utf8')

      const lineCount = jsonl.split('\n').filter((l) => l.trim().length > 0).length

      return {
        ok: true,
        data: {
          output_path: args.output_path,
          entries_exported: lineCount,
          size_bytes: Buffer.byteLength(jsonl, 'utf8'),
        },
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
