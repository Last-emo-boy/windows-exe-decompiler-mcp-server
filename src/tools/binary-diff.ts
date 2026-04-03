/**
 * binary.diff MCP tool — compares two samples with function-level and structural diffing.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import {
  runRizinDiff,
  computeStructuralDelta,
  computeAttackDelta,
  buildSummaryStats,
  type BinaryDiffResult,
  type AttackTechnique,
} from '../binary-diff-engine.js'

// ============================================================================
// Schemas
// ============================================================================

const TOOL_NAME = 'binary.diff'

export const BinaryDiffInputSchema = z.object({
  sample_id_a: z.string().describe('First sample ID (format: sha256:<hex>)'),
  sample_id_b: z.string().describe('Second sample ID (format: sha256:<hex>)'),
  include_function_diff: z
    .boolean()
    .optional()
    .default(true)
    .describe('Run radiff2 function-level diff'),
  include_structural_diff: z
    .boolean()
    .optional()
    .default(true)
    .describe('Compare imports, exports, sections, strings'),
  include_attack_diff: z
    .boolean()
    .optional()
    .default(true)
    .describe('Compare ATT&CK technique mappings'),
  max_functions: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .default(50)
    .describe('Max functions to include in diff output'),
})

export const BinaryDiffOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const binaryDiffToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Compare two binary samples: function-level diff (via radiff2), structural delta (imports/exports/sections/strings), and ATT&CK technique delta. Produces a structured diff artifact.',
  inputSchema: BinaryDiffInputSchema,
  outputSchema: BinaryDiffOutputSchema,
}

// ============================================================================
// Helpers
// ============================================================================

function extractImportNames(artifactData: unknown): string[] {
  if (!artifactData || typeof artifactData !== 'object') return []
  const data = artifactData as Record<string, unknown>
  const imports = data.imports as unknown[] | undefined
  if (!Array.isArray(imports)) return []
  const names: string[] = []
  for (const imp of imports) {
    if (typeof imp === 'string') {
      names.push(imp)
    } else if (imp && typeof imp === 'object') {
      const obj = imp as Record<string, unknown>
      if (typeof obj.name === 'string') names.push(obj.name)
      // Handle grouped imports: { dll: "...", functions: [...] }
      if (Array.isArray(obj.functions)) {
        for (const fn of obj.functions) {
          if (typeof fn === 'string') names.push(fn)
          else if (fn && typeof fn === 'object' && typeof (fn as Record<string, unknown>).name === 'string') {
            names.push((fn as Record<string, unknown>).name as string)
          }
        }
      }
    }
  }
  return names
}

function extractExportNames(artifactData: unknown): string[] {
  if (!artifactData || typeof artifactData !== 'object') return []
  const data = artifactData as Record<string, unknown>
  const exports = data.exports as unknown[] | undefined
  if (!Array.isArray(exports)) return []
  return exports
    .map((e) =>
      typeof e === 'string'
        ? e
        : e && typeof e === 'object' && typeof (e as Record<string, unknown>).name === 'string'
          ? ((e as Record<string, unknown>).name as string)
          : null
    )
    .filter((x): x is string => x !== null)
}

function extractStrings(artifactData: unknown): string[] {
  if (!artifactData || typeof artifactData !== 'object') return []
  const data = artifactData as Record<string, unknown>
  const strings = data.strings as unknown[] | undefined
  if (!Array.isArray(strings)) return []
  return strings
    .map((s) =>
      typeof s === 'string'
        ? s
        : s && typeof s === 'object' && typeof (s as Record<string, unknown>).value === 'string'
          ? ((s as Record<string, unknown>).value as string)
          : null
    )
    .filter((x): x is string => x !== null)
    .slice(0, 5000)
}

function extractSections(artifactData: unknown): Array<{ name: string; size: number }> {
  if (!artifactData || typeof artifactData !== 'object') return []
  const data = artifactData as Record<string, unknown>
  const sections = data.sections as unknown[] | undefined
  if (!Array.isArray(sections)) return []
  return sections
    .filter((s): s is Record<string, unknown> => s !== null && typeof s === 'object')
    .map((s) => ({
      name: String(s.name ?? ''),
      size: typeof s.size === 'number' ? s.size : typeof s.virtual_size === 'number' ? s.virtual_size : 0,
    }))
}

function extractAttackTechniques(artifactData: unknown): AttackTechnique[] {
  if (!artifactData || typeof artifactData !== 'object') return []
  const data = artifactData as Record<string, unknown>
  const techniques = (data.techniques ?? data.attack_techniques ?? data.mappings) as unknown[] | undefined
  if (!Array.isArray(techniques)) return []
  return techniques
    .filter((t): t is Record<string, unknown> => t !== null && typeof t === 'object')
    .map((t) => ({
      id: String(t.id ?? t.technique_id ?? ''),
      name: String(t.name ?? t.technique_name ?? ''),
      confidence: typeof t.confidence === 'number' ? t.confidence : undefined,
    }))
    .filter((t) => t.id.length > 0)
}

async function loadSampleArtifacts(
  database: DatabaseManager,
  sampleId: string
): Promise<{
  imports: string[]
  exports: string[]
  sections: Array<{ name: string; size: number }>
  strings: string[]
  attack_techniques: AttackTechnique[]
}> {
  // Try to load from analysis_evidence
  const evidence = database.findAnalysisEvidenceBySample(sampleId)
  const result = {
    imports: [] as string[],
    exports: [] as string[],
    sections: [] as Array<{ name: string; size: number }>,
    strings: [] as string[],
    attack_techniques: [] as AttackTechnique[],
  }

  if (Array.isArray(evidence)) {
    for (const entry of evidence) {
      const data = typeof entry.result_json === 'string'
        ? JSON.parse(entry.result_json)
        : entry.result_json
      if (!data) continue
      const family = entry.evidence_family ?? ''

      if (family === 'pe_imports' || family === 'imports') {
        result.imports = extractImportNames(data)
      } else if (family === 'pe_exports' || family === 'exports') {
        result.exports = extractExportNames(data)
      } else if (family === 'strings') {
        result.strings = extractStrings(data)
      } else if (family === 'pe_structure' || family === 'structure') {
        result.sections = extractSections(data)
      } else if (family === 'attack_map' || family === 'attack') {
        result.attack_techniques = extractAttackTechniques(data)
      }
    }
  }

  return result
}

// ============================================================================
// Handler
// ============================================================================

export function createBinaryDiffHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = BinaryDiffInputSchema.parse(args)
    const warnings: string[] = []
    const errors: string[] = []

    // Validate both samples exist
    const sampleA = database.findSample(input.sample_id_a)
    const sampleB = database.findSample(input.sample_id_b)
    if (!sampleA) {
      return { ok: false, errors: [`Sample A not found: ${input.sample_id_a}`] }
    }
    if (!sampleB) {
      return { ok: false, errors: [`Sample B not found: ${input.sample_id_b}`] }
    }

    const diffResult: BinaryDiffResult = {
      ok: true,
      sample_id_a: input.sample_id_a,
      sample_id_b: input.sample_id_b,
      function_diff: null,
      structural_delta: null,
      attack_delta: null,
      summary_stats: {
        functions_added: 0,
        functions_removed: 0,
        functions_modified: 0,
        imports_added: 0,
        imports_removed: 0,
        strings_added: 0,
        strings_removed: 0,
        attack_techniques_added: 0,
        attack_techniques_removed: 0,
      },
      errors: [],
      warnings: [],
    }

    // Function-level diff via radiff2
    if (input.include_function_diff) {
      try {
        const resolvedA = await resolvePrimarySamplePath(workspaceManager, input.sample_id_a)
        const resolvedB = await resolvePrimarySamplePath(workspaceManager, input.sample_id_b)
        const rizinResult = await runRizinDiff(resolvedA.samplePath, resolvedB.samplePath)
        if (rizinResult.ok) {
          rizinResult.functions_modified = rizinResult.functions_modified.slice(0, input.max_functions)
          rizinResult.functions_added = rizinResult.functions_added.slice(0, input.max_functions)
          rizinResult.functions_removed = rizinResult.functions_removed.slice(0, input.max_functions)
        }
        diffResult.function_diff = rizinResult
        if (rizinResult.warnings) warnings.push(...rizinResult.warnings)
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        warnings.push(`Function diff failed: ${msg.slice(0, 300)}`)
      }
    }

    // Structural delta
    if (input.include_structural_diff) {
      try {
        const [artifactsA, artifactsB] = await Promise.all([
          loadSampleArtifacts(database, input.sample_id_a),
          loadSampleArtifacts(database, input.sample_id_b),
        ])
        diffResult.structural_delta = computeStructuralDelta(artifactsA, artifactsB)

        // ATT&CK delta (uses data loaded above)
        if (input.include_attack_diff) {
          diffResult.attack_delta = computeAttackDelta(
            artifactsA.attack_techniques,
            artifactsB.attack_techniques
          )
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        warnings.push(`Structural diff failed: ${msg.slice(0, 300)}`)
      }
    }

    // Build summary stats
    diffResult.summary_stats = buildSummaryStats(diffResult)
    diffResult.errors = errors
    diffResult.warnings = warnings

    // Persist artifact
    const artifacts: ArtifactRef[] = []
    try {
      const artifactRef = await persistStaticAnalysisJsonArtifact(
        workspaceManager,
        database,
        input.sample_id_a,
        'binary_diff',
        `diff_${input.sample_id_a.slice(7, 15)}_vs_${input.sample_id_b.slice(7, 15)}`,
        diffResult
      )
      artifacts.push(artifactRef)
    } catch {
      warnings.push('Failed to persist diff artifact')
    }

    return {
      ok: true,
      data: diffResult,
      warnings: warnings.length > 0 ? warnings : undefined,
      errors: errors.length > 0 ? errors : undefined,
      artifacts: artifacts.length > 0 ? artifacts : undefined,
      metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
    }
  }
}
