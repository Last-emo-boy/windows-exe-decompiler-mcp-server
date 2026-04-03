/**
 * vm.detect MCP tool — detect VM-based protection in a binary sample.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import { scoreVMCandidate, classifyVMComponents, type DecompiledFunc } from '../vm/vm-detector.js'

const TOOL_NAME = 'vm.detect'

export const vmDetectInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  min_score: z
    .number()
    .min(0)
    .max(100)
    .optional()
    .default(40)
    .describe('Minimum VM score threshold (0-100)'),
})

export const vmDetectOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const vmDetectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Detect virtual machine (VM) based protection in a binary. Scores functions for VM-like patterns (dispatch loops, bytecode fetches, handler tables) and classifies VM components.',
  inputSchema: vmDetectInputSchema,
  outputSchema: vmDetectOutputSchema,
}

function extractDecompiledFunctions(
  database: DatabaseManager,
  sampleId: string
): DecompiledFunc[] {
  const functions: DecompiledFunc[] = []
  const evidence = database.findAnalysisEvidenceBySample(sampleId)
  if (!Array.isArray(evidence)) return functions

  for (const entry of evidence) {
    const family = entry.evidence_family ?? ''
    if (family === 'function_map' || family === 'decompilation' || family === 'functions') {
      const data =
        typeof entry.result_json === 'string'
          ? JSON.parse(entry.result_json)
          : entry.result_json
      if (!data) continue

      const fnList =
        (data as Record<string, unknown>).functions ??
        (data as Record<string, unknown>).decompiled_functions ??
        []
      if (Array.isArray(fnList)) {
        for (const fn of fnList) {
          if (fn && typeof fn === 'object') {
            const obj = fn as Record<string, unknown>
            const code = String(obj.decompiled ?? obj.code ?? obj.decompiled_code ?? '')
            if (code) {
              functions.push({
                name: String(obj.name ?? obj.function_name ?? 'unknown'),
                address: String(obj.address ?? obj.offset ?? obj.addr ?? '0x0'),
                decompiled_code: code,
              })
            }
          }
        }
      }
    }
  }
  return functions
}

export function createVmDetectHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = vmDetectInputSchema.parse(args)
    const warnings: string[] = []

    const sample = database.findSample(input.sample_id)
    if (!sample) {
      return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
    }

    const functions = extractDecompiledFunctions(database, input.sample_id)
    if (functions.length === 0) {
      return {
        ok: false,
        errors: ['No decompiled functions found. Run function_map or code.functions.reconstruct first.'],
      }
    }

    // Score all functions and filter by threshold
    const candidates = functions
      .map(fn => ({
        function: fn.name,
        address: fn.address,
        score: scoreVMCandidate(fn.decompiled_code),
      }))
      .filter(c => c.score.total >= input.min_score)
      .sort((a, b) => b.score.total - a.score.total)

    // Classify components for top candidates
    const vmFunctions = candidates.length > 0
      ? classifyVMComponents(
          candidates.map(c => {
            const fn = functions.find(f => f.name === c.function)!
            return fn
          })
        )
      : []

    const result = {
      vm_detected: candidates.length > 0 && candidates[0].score.total >= 60,
      candidates: candidates.slice(0, 50),
      components: vmFunctions,
      total_functions_scanned: functions.length,
      vm_function_count: candidates.length,
    }

    // Persist artifact
    const artifacts: ArtifactRef[] = []
    try {
      const ref = await persistStaticAnalysisJsonArtifact(
        workspaceManager, database, input.sample_id,
        'vm_detection', 'vm_detect_result', result
      )
      artifacts.push(ref)
    } catch {
      warnings.push('Failed to persist VM detection artifact')
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
