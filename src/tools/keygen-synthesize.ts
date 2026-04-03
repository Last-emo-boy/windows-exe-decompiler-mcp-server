/**
 * keygen.synthesize MCP tool — synthesize a forward keygen from VM constraints.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import { synthesizeKeygen } from '../constraint/keygen-synthesizer.js'
import { extractConstraints } from '../constraint/constraint-extractor.js'

const TOOL_NAME = 'keygen.synthesize'

export const keygenSynthesizeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  bit_width: z.number().int().optional().default(32).describe('Register bit width'),
})

export const keygenSynthesizeOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const keygenSynthesizeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Synthesize a forward keygen (Python script) from extracted VM constraints. Analyzes dependency chains, detects non-invertible operations, and generates sequential computation code.',
  inputSchema: keygenSynthesizeInputSchema,
  outputSchema: keygenSynthesizeOutputSchema,
}

export function createKeygenSynthesizeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = keygenSynthesizeInputSchema.parse(args)
    const warnings: string[] = []

    const sample = database.findSample(input.sample_id)
    if (!sample) {
      return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
    }

    // Load emulation trace for constraint extraction
    const evidence = database.findAnalysisEvidenceBySample(input.sample_id)
    let constraints: ReturnType<typeof extractConstraints> = []

    if (Array.isArray(evidence)) {
      // Try constraint extraction results first
      for (const entry of evidence) {
        if (entry.evidence_family === 'constraint_extraction') {
          const data = typeof entry.result_json === 'string'
            ? JSON.parse(entry.result_json)
            : entry.result_json
          if (data?.constraints) {
            constraints = data.constraints
            break
          }
        }
      }

      // Fall back to emulation trace
      if (constraints.length === 0) {
        for (const entry of evidence) {
          if (entry.evidence_family === 'vm_emulation') {
            const data = typeof entry.result_json === 'string'
              ? JSON.parse(entry.result_json)
              : entry.result_json
            if (data) {
              const trace = ((data as Record<string, unknown>).steps ??
                (data as Record<string, unknown>).trace ?? []) as never[]
              constraints = extractConstraints(trace)
              break
            }
          }
        }
      }
    }

    if (constraints.length === 0) {
      return {
        ok: false,
        errors: ['No constraints found. Run vm.emulate and constraint.extract first.'],
      }
    }

    const keygenResult = synthesizeKeygen(constraints, input.bit_width)

    const result = {
      feasible: keygenResult.feasible,
      forward_computable: keygenResult.forwardComputable,
      dependency_order: keygenResult.dependencyOrder,
      brute_force_vars: keygenResult.bruteForceVars,
      notes: keygenResult.notes,
      python_code: keygenResult.pythonCode,
      node_count: keygenResult.nodes.length,
    }

    // Persist
    const artifacts: ArtifactRef[] = []
    try {
      const ref = await persistStaticAnalysisJsonArtifact(
        workspaceManager, database, input.sample_id,
        'keygen_synthesis', 'keygen_result', result
      )
      artifacts.push(ref)
    } catch {
      warnings.push('Failed to persist keygen artifact')
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
