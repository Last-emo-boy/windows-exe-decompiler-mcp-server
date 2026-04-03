/**
 * mba.simplify MCP tool — simplify Mixed Boolean-Arithmetic obfuscated expressions.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { parseExpression, simplify, exprToString } from '../constraint/mba-simplifier.js'

const TOOL_NAME = 'mba.simplify'

export const mbaSimplifyInputSchema = z.object({
  expressions: z
    .array(z.string())
    .min(1)
    .max(100)
    .describe('Array of MBA expressions to simplify (e.g. ["(a + b) - 2 * (a & b)"])'),
  max_iterations: z
    .number()
    .int()
    .min(1)
    .max(100)
    .optional()
    .default(20)
    .describe('Maximum simplification iterations per expression'),
})

export const mbaSimplifyOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const mbaSimplifyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Simplify Mixed Boolean-Arithmetic (MBA) obfuscated expressions to their canonical forms. Applies algebraic identities like (a+b)-2*(a&b) → a^b, DeMorgan laws, constant folding, and more.',
  inputSchema: mbaSimplifyInputSchema,
  outputSchema: mbaSimplifyOutputSchema,
}

export function createMbaSimplifyHandler(
  _workspaceManager: WorkspaceManager,
  _database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = mbaSimplifyInputSchema.parse(args)
    const warnings: string[] = []
    const results: Array<{
      input: string
      output: string
      original_nodes: number
      simplified_nodes: number
      reduction_percent: number
      iterations: number
      error?: string
    }> = []

    for (const exprStr of input.expressions) {
      try {
        const ast = parseExpression(exprStr)
        const result = simplify(ast, input.max_iterations)
        results.push({
          input: exprStr,
          output: result.simplified,
          original_nodes: result.originalNodes,
          simplified_nodes: result.simplifiedNodes,
          reduction_percent: result.reductionPercent,
          iterations: result.iterations,
        })
      } catch (e) {
        results.push({
          input: exprStr,
          output: exprStr,
          original_nodes: 0,
          simplified_nodes: 0,
          reduction_percent: 0,
          iterations: 0,
          error: `Parse error: ${e}`,
        })
        warnings.push(`Failed to parse expression: ${exprStr}`)
      }
    }

    const totalReduction = results.length > 0
      ? Math.round(results.reduce((s, r) => s + r.reduction_percent, 0) / results.length)
      : 0

    return {
      ok: true,
      data: {
        results,
        total_expressions: results.length,
        average_reduction_percent: totalReduction,
      },
      warnings: warnings.length > 0 ? warnings : undefined,
      metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
    }
  }
}
