/**
 * vm.pattern.analyze MCP tool — deep pattern analysis of a VM-protected function.
 * Combines VM detection scoring with component classification in a single call.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import {
  scoreVMCandidate,
  classifyVMComponents,
  detectLoopSwitchPattern,
  detectBytecodeFetch,
  detectPCIncrement,
  detectHandlerRegularity,
  detectOpcodeRange,
  type DecompiledFunc,
} from '../vm/vm-detector.js'

const TOOL_NAME = 'vm.pattern.analyze'

export const vmPatternAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  function_name: z.string().optional().describe('Specific function name to analyze'),
  function_address: z.string().optional().describe('Specific function address to analyze'),
  top_n: z.number().int().min(1).max(50).optional().default(10).describe('Number of top VM candidates to analyze in detail'),
})

export const vmPatternAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const vmPatternAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Deep analysis of VM protection patterns in specific functions. Provides per-heuristic scoring breakdown (loop-switch, bytecode fetch, PC increment, handler regularity, opcode range) and component role classification.',
  inputSchema: vmPatternAnalyzeInputSchema,
  outputSchema: vmPatternAnalyzeOutputSchema,
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

export function createVmPatternAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = vmPatternAnalyzeInputSchema.parse(args)
    const warnings: string[] = []

    const sample = database.findSample(input.sample_id)
    if (!sample) {
      return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
    }

    let functions = extractDecompiledFunctions(database, input.sample_id)
    if (functions.length === 0) {
      return {
        ok: false,
        errors: ['No decompiled functions found. Run function_map or code.functions.reconstruct first.'],
      }
    }

    // Filter to specific function if requested
    if (input.function_name) {
      functions = functions.filter(f => f.name === input.function_name)
    } else if (input.function_address) {
      functions = functions.filter(f => f.address === input.function_address)
    }

    if (functions.length === 0) {
      return {
        ok: false,
        errors: ['Specified function not found in decompiled output.'],
      }
    }

    // Deep analysis: per-heuristic breakdown
    const detailed = functions
      .map(fn => ({
        function_name: fn.name,
        address: fn.address,
        score: scoreVMCandidate(fn.decompiled_code),
        heuristics: {
          loop_switch: detectLoopSwitchPattern(fn.decompiled_code),
          bytecode_fetch: detectBytecodeFetch(fn.decompiled_code),
          pc_increment: detectPCIncrement(fn.decompiled_code),
          handler_regularity: detectHandlerRegularity(fn.decompiled_code),
          opcode_range: detectOpcodeRange(fn.decompiled_code),
        },
      }))
      .sort((a, b) => b.score.total - a.score.total)
      .slice(0, input.top_n)

    // Component classification
    const topFunctions = detailed
      .filter(d => d.score.total >= 30)
      .map(d => functions.find(f => f.name === d.function_name)!)
      .filter(Boolean)
    const components = classifyVMComponents(topFunctions)

    const result = {
      analyzed_functions: detailed,
      components,
      summary: {
        total_functions: functions.length,
        vm_candidates: detailed.filter(d => d.score.total >= 60).length,
        possible_vm: detailed.filter(d => d.score.total >= 30 && d.score.total < 60).length,
      },
    }

    // Persist
    const artifacts: ArtifactRef[] = []
    try {
      const ref = await persistStaticAnalysisJsonArtifact(
        workspaceManager, database, input.sample_id,
        'vm_pattern_analysis', 'pattern_analysis_result', result
      )
      artifacts.push(ref)
    } catch {
      warnings.push('Failed to persist pattern analysis artifact')
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
