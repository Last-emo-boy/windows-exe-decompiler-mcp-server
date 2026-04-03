/**
 * constraint.extract MCP tool — extract mathematical constraints from VM emulation traces.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import { extractConstraints, constraintsToZ3Script } from '../constraint/constraint-extractor.js'

const TOOL_NAME = 'constraint.extract'

export const constraintExtractInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  bit_width: z.number().int().optional().default(32).describe('Bit width for Z3 BitVec declarations'),
})

export const constraintExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const constraintExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Extract mathematical constraints from a VM emulation trace. Produces constraints in IR form and a Z3 Python solver script.',
  inputSchema: constraintExtractInputSchema,
  outputSchema: constraintExtractOutputSchema,
}

export function createConstraintExtractHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = constraintExtractInputSchema.parse(args)
    const warnings: string[] = []

    const sample = database.findSample(input.sample_id)
    if (!sample) {
      return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
    }

    // Load emulation trace
    const evidence = database.findAnalysisEvidenceBySample(input.sample_id)
    let emulationData: Record<string, unknown> | null = null

    if (Array.isArray(evidence)) {
      for (const entry of evidence) {
        if (entry.evidence_family === 'vm_emulation') {
          const data = typeof entry.result_json === 'string'
            ? JSON.parse(entry.result_json)
            : entry.result_json
          if (data) {
            emulationData = data as Record<string, unknown>
            break
          }
        }
      }
    }

    if (!emulationData) {
      return {
        ok: false,
        errors: ['No emulation trace found. Run vm.emulate first.'],
      }
    }

    // Extract constraints from the emulation trace
    const trace = (emulationData.steps ?? emulationData.trace ?? []) as Array<Record<string, unknown>>
    const constraints = extractConstraints(trace as never[])

    // Generate Z3 script
    const z3Script = constraintsToZ3Script(constraints, input.bit_width)

    const result = {
      constraint_count: constraints.length,
      constraints: constraints.map(c => ({
        left: c.raw ?? 'expr',
        operator: c.operator,
        source_pc: c.sourcePC,
      })),
      z3_script: z3Script,
      variables: [...new Set(constraints.flatMap(c => {
        const vars: string[] = []
        function walkExpr(e: unknown): void {
          if (!e || typeof e !== 'object') return
          const node = e as Record<string, unknown>
          if (node.kind === 'var') vars.push(node.name as string)
          if (node.left) walkExpr(node.left)
          if (node.right) walkExpr(node.right)
          if (node.child) walkExpr(node.child)
          if (Array.isArray(node.args)) (node.args as unknown[]).forEach(walkExpr)
        }
        walkExpr(c.leftExpr)
        walkExpr(c.rightExpr)
        return vars
      }))],
    }

    // Persist
    const artifacts: ArtifactRef[] = []
    try {
      const ref = await persistStaticAnalysisJsonArtifact(
        workspaceManager, database, input.sample_id,
        'constraint_extraction', 'constraints', result
      )
      artifacts.push(ref)
    } catch {
      warnings.push('Failed to persist constraint artifact')
    }

    return {
      ok: true,
      data: result,
      warnings: warnings.length > 0 ? warnings : undefined,
      artifacts,
      metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
    }
  }
}
