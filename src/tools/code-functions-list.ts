/**
 * code.functions.list MCP Tool
 * 
 * Requirements: 9.1
 * 
 * Lists all functions extracted from a binary sample
 */

import { z } from 'zod';
import type { ToolDefinition, ToolHandler, ToolResult } from '../types.js';
import type { DatabaseManager } from '../database.js';
import type { WorkspaceManager } from '../workspace-manager.js';
import { DecompilerWorker } from '../decompiler-worker.js';
import { logger } from '../logger.js';

/**
 * Input schema for code.functions.list tool
 */
export const codeFunctionsListInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  backend: z.enum(['ghidra', 'auto']).optional().describe('Decompiler backend (default: auto)'),
  limit: z.number().optional().describe('Maximum number of functions to return')
});

export type CodeFunctionsListInput = z.infer<typeof codeFunctionsListInputSchema>;

/**
 * Tool definition for code.functions.list
 */
export const codeFunctionsListToolDefinition: ToolDefinition = {
  name: 'code.functions.list',
  description:
    'List all indexed functions for a binary sample. Supports Ghidra-extracted, PE metadata-recovered, or manually defined function indexes.',
  inputSchema: codeFunctionsListInputSchema
};

/**
 * Create handler for code.functions.list tool
 */
export function createCodeFunctionsListHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
): ToolHandler {
  return async (args: unknown): Promise<ToolResult> => {
    try {
      const input = codeFunctionsListInputSchema.parse(args);

      logger.info({
        sample_id: input.sample_id,
        limit: input.limit
      }, 'code.functions.list tool called');

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

      // List functions
      const functions = await decompilerWorker.listFunctions(input.sample_id, input.limit);

      logger.info({
        sample_id: input.sample_id,
        function_count: functions.length
      }, 'Functions listed successfully');

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ok: true,
            data: {
              functions,
              count: functions.length
            }
          }, null, 2)
        }]
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error({
        error: errorMessage
      }, 'code.functions.list tool failed');

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
