import { z } from 'zod'
import type { ToolDefinition, ToolHandler, ToolResult } from '../types.js'
import type { DatabaseManager } from '../database.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import { DecompilerWorker, getGhidraDiagnostics, normalizeGhidraError } from '../decompiler-worker.js'
import { logger } from '../logger.js'

export const codeFunctionsSearchInputSchema = z
  .object({
    sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
    api: z.string().optional().describe('API name or substring, e.g. WriteProcessMemory'),
    string: z.string().optional().describe('String literal substring to reverse-map into functions'),
    limit: z.number().int().min(1).max(200).optional().default(20),
    timeout: z.number().int().min(5).max(300).optional().default(30).describe('Timeout in seconds for Ghidra-backed searches'),
  })
  .refine((data) => Boolean(data.api || data.string), {
    message: 'At least one of api or string must be provided',
  })

export type CodeFunctionsSearchInput = z.infer<typeof codeFunctionsSearchInputSchema>

export const codeFunctionsSearchToolDefinition: ToolDefinition = {
  name: 'code.functions.search',
  description:
    'Search functions by referenced API names or string literals. Uses Ghidra when available for string-to-function mapping and falls back to function-index API search otherwise. ' +
    'Use code.xrefs.analyze when you need bounded inbound/outbound relationship summaries instead of a simple function match list.',
  inputSchema: codeFunctionsSearchInputSchema,
}

export function createCodeFunctionsSearchHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
): ToolHandler {
  return async (args: unknown): Promise<ToolResult> => {
    try {
      const input = codeFunctionsSearchInputSchema.parse(args)

      logger.info(
        {
          sample_id: input.sample_id,
          api: input.api,
          string: input.string,
          limit: input.limit,
        },
        'code.functions.search tool called'
      )

      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  ok: false,
                  errors: [`Sample not found: ${input.sample_id}`],
                },
                null,
                2
              ),
            },
          ],
          isError: true,
        }
      }

      const decompilerWorker = new DecompilerWorker(database, workspaceManager)
      const result = await decompilerWorker.searchFunctions(input.sample_id, {
        apiQuery: input.api,
        stringQuery: input.string,
        limit: input.limit,
        timeout: input.timeout * 1000,
      })

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                ok: true,
                data: result,
              },
              null,
              2
            ),
          },
        ],
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      const diagnostics = getGhidraDiagnostics(error)
      const normalizedError = normalizeGhidraError(error, 'code.functions.search')
      logger.error(
        {
          error: errorMessage,
          ghidra_diagnostics: diagnostics,
          normalized_error: normalizedError,
        },
        'code.functions.search tool failed'
      )

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                ok: false,
                errors: [errorMessage],
                diagnostics,
                normalized_error: normalizedError,
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      }
    }
  }
}
