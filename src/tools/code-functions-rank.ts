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
  topk: z.number().optional().describe('Number of top functions to return (default: 20)')
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
              count: rankedFunctions.length
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
