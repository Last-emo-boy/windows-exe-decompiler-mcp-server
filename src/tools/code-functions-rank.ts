/**
 * code.functions.rank MCP Tool
 * 
 * Requirements: 9.2, 9.8
 * 
 * Ranks functions by interest score
 */

import { z } from 'zod';
import type { ToolDefinition, ToolHandler, ToolResult } from '../types.js';
import type { DatabaseManager } from '../database.js';
import type { WorkspaceManager } from '../workspace-manager.js';
import { DecompilerWorker } from '../decompiler-worker.js';
import { logger } from '../logger.js';

/**
 * Input schema for code.functions.rank tool
 */
export const codeFunctionsRankInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  topk: z.number().optional().describe('Number of top functions to return (default: 20)'),
  include_vuln_risk: z.boolean().optional().describe('When true, boost ranking score based on vulnerability findings from vuln.pattern.scan'),
});

export type CodeFunctionsRankInput = z.infer<typeof codeFunctionsRankInputSchema>;

/**
 * Tool definition for code.functions.rank
 */
export const codeFunctionsRankToolDefinition: ToolDefinition = {
  name: 'code.functions.rank',
  description:
    'Rank indexed functions by interest score based on size, callers, sensitive API calls, and entry points. Works with Ghidra, recovered, or manually defined function indexes.',
  inputSchema: codeFunctionsRankInputSchema
};

/**
 * Create handler for code.functions.rank tool
 */
export function createCodeFunctionsRankHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
): ToolHandler {
  return async (args: unknown): Promise<ToolResult> => {
    try {
      const input = codeFunctionsRankInputSchema.parse(args);

      logger.info({
        sample_id: input.sample_id,
        topk: input.topk
      }, 'code.functions.rank tool called');

      // Check if sample exists
      const sample = database.findSample(input.sample_id);
      if (!sample) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ok: false,
              errors: [`Sample not found: ${input.sample_id}`]
            }, null, 2)
          }],
          isError: true
        };
      }

      // Create decompiler worker
      const decompilerWorker = new DecompilerWorker(database, workspaceManager);

      // Rank functions
      const rankedFunctions = await decompilerWorker.rankFunctions(
        input.sample_id,
        input.topk || 20
      );

      // Optional: boost ranking based on vulnerability findings
      if (input.include_vuln_risk) {
        const vulnArtifacts = database.findArtifactsByType(input.sample_id, 'vuln_scan');
        if (vulnArtifacts.length > 0) {
          try {
            const fs = await import('fs');
            const latestArt = vulnArtifacts[vulnArtifacts.length - 1];
            const vulnData = JSON.parse(fs.default.readFileSync(latestArt.path, 'utf-8'));
            const findings: Array<{ function_name: string; severity: string }> = vulnData?.findings ?? [];
            const severityBoost: Record<string, number> = { critical: 40, high: 25, medium: 10, low: 5 };
            const boostMap = new Map<string, number>();
            for (const f of findings) {
              const prev = boostMap.get(f.function_name) ?? 0;
              boostMap.set(f.function_name, prev + (severityBoost[f.severity] ?? 5));
            }
            for (const fn of rankedFunctions as Array<{ name?: string; score?: number; vuln_risk_boost?: number }>) {
              const boost = boostMap.get(fn.name ?? '') ?? 0;
              if (boost > 0) {
                fn.vuln_risk_boost = boost;
                fn.score = (fn.score ?? 0) + boost;
              }
            }
            // Re-sort by boosted score
            (rankedFunctions as Array<{ score?: number }>).sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
          } catch {
            // non-fatal: vuln data may not be available
          }
        }
      }

      logger.info({
        sample_id: input.sample_id,
        function_count: rankedFunctions.length
      }, 'Functions ranked successfully');

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ok: true,
            data: {
              functions: rankedFunctions,
              count: rankedFunctions.length,
              vuln_risk_applied: input.include_vuln_risk ?? false,
            }
          }, null, 2)
        }]
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error({
        error: errorMessage
      }, 'code.functions.rank tool failed');

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ok: false,
            errors: [errorMessage]
          }, null, 2)
        }],
        isError: true
      };
    }
  };
}
