/**
 * vm.semantic.diff MCP tool — compare opcode tables from two VM-protected samples.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import { diffOpcodeTables } from '../vm/semantic-diff.js'

const TOOL_NAME = 'vm.semantic.diff'

export const vmSemanticDiffInputSchema = z.object({
  sample_id_a: z.string().describe('First sample ID'),
  sample_id_b: z.string().describe('Second sample ID'),
})

export const vmSemanticDiffOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const vmSemanticDiffToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Compare opcode tables from two VM-protected samples to detect renamed opcodes, trap insertions (bit-width changes, operand swaps), and semantic differences.',
  inputSchema: vmSemanticDiffInputSchema,
  outputSchema: vmSemanticDiffOutputSchema,
}

function loadOpcodeTable(database: DatabaseManager, sampleId: string) {
  const evidence = database.findAnalysisEvidenceBySample(sampleId)
  if (!Array.isArray(evidence)) return null
  for (const entry of evidence) {
    if (entry.evidence_family === 'vm_opcode_table') {
      const data = typeof entry.result_json === 'string'
        ? JSON.parse(entry.result_json)
        : entry.result_json
      if (data?.opcode_table) return data.opcode_table
    }
  }
  return null
}

export function createVmSemanticDiffHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = vmSemanticDiffInputSchema.parse(args)
    const warnings: string[] = []

    for (const sid of [input.sample_id_a, input.sample_id_b]) {
      if (!database.findSample(sid)) {
        return { ok: false, errors: [`Sample not found: ${sid}`] }
      }
    }

    const tableA = loadOpcodeTable(database, input.sample_id_a)
    const tableB = loadOpcodeTable(database, input.sample_id_b)

    if (!tableA) {
      return { ok: false, errors: [`No opcode table for ${input.sample_id_a}. Run vm.opcode.extract first.`] }
    }
    if (!tableB) {
      return { ok: false, errors: [`No opcode table for ${input.sample_id_b}. Run vm.opcode.extract first.`] }
    }

    const report = diffOpcodeTables(tableA, tableB)

    const result = {
      ...report,
      sample_a: input.sample_id_a,
      sample_b: input.sample_id_b,
    }

    // Persist
    const artifacts: ArtifactRef[] = []
    try {
      const ref = await persistStaticAnalysisJsonArtifact(
        workspaceManager, database, input.sample_id_a,
        'vm_semantic_diff', 'semantic_diff_report', result
      )
      artifacts.push(ref)
    } catch {
      warnings.push('Failed to persist semantic diff artifact')
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
