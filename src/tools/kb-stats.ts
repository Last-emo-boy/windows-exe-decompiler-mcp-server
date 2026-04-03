/**
 * kb.stats MCP tool — display knowledge base statistics.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'

const TOOL_NAME = 'kb.stats'

export const KbStatsInputSchema = z.object({
  include_category_breakdown: z
    .boolean()
    .optional()
    .default(false)
    .describe('Include per-category entry counts'),
})

export const KbStatsOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const kbStatsToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Display knowledge base statistics: entry counts, source distribution, confidence histogram, and optional category breakdown.',
  inputSchema: KbStatsInputSchema,
  outputSchema: KbStatsOutputSchema,
}

export function createKbStatsHandler(
  _workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: z.infer<typeof KbStatsInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      // Function KB stats
      const fnCount = database.queryOneSql<{ count: number }>(
        'SELECT COUNT(*) as count FROM function_kb'
      )
      const sampleKbCount = database.queryOneSql<{ count: number }>(
        'SELECT COUNT(*) as count FROM sample_kb'
      )

      // Source distribution
      const sourceDistribution = database.querySql<{ semantics_source: string; cnt: number }>(
        'SELECT semantics_source, COUNT(*) as cnt FROM function_kb GROUP BY semantics_source ORDER BY cnt DESC'
      )

      // Confidence histogram (buckets: 0-0.2, 0.2-0.4, 0.4-0.6, 0.6-0.8, 0.8-1.0)
      const confidenceBuckets = database.querySql<{ bucket: string; cnt: number }>(`
        SELECT 
          CASE 
            WHEN semantics_confidence < 0.2 THEN '0.0-0.2'
            WHEN semantics_confidence < 0.4 THEN '0.2-0.4'
            WHEN semantics_confidence < 0.6 THEN '0.4-0.6'
            WHEN semantics_confidence < 0.8 THEN '0.6-0.8'
            ELSE '0.8-1.0'
          END as bucket,
          COUNT(*) as cnt
        FROM function_kb
        GROUP BY bucket
        ORDER BY bucket
      `)

      const stats: Record<string, unknown> = {
        function_kb_count: fnCount?.count ?? 0,
        sample_kb_count: sampleKbCount?.count ?? 0,
        source_distribution: Object.fromEntries(
          (sourceDistribution || []).map((r) => [r.semantics_source, r.cnt])
        ),
        confidence_histogram: Object.fromEntries(
          (confidenceBuckets || []).map((r) => [r.bucket, r.cnt])
        ),
      }

      if (args.include_category_breakdown) {
        // Parse semantics_behavior for category hints
        const allEntries = database.querySql<{ semantics_behavior: string }>(
          'SELECT semantics_behavior FROM function_kb WHERE semantics_behavior IS NOT NULL AND semantics_behavior != \'\''
        )
        const categories: Record<string, number> = {}
        for (const entry of allEntries || []) {
          const cats = entry.semantics_behavior.split(',').map((c) => c.trim().toLowerCase())
          for (const cat of cats) {
            if (cat) categories[cat] = (categories[cat] || 0) + 1
          }
        }
        stats.category_breakdown = categories
      }

      return {
        ok: true,
        data: stats,
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
