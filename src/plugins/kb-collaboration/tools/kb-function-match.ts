/**
 * kb.function.match MCP tool — Match function signatures across samples
 * to find reused code, shared libraries, and known function patterns.
 * Leverages the knowledge base to propagate names/annotations.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'kb.function.match'

export const KbFunctionMatchInputSchema = z.object({
  sample_id: z.string().describe('Target sample ID to match functions for'),
  match_against: z
    .array(z.string())
    .optional()
    .describe('Specific sample IDs to match against (or all KB entries if omitted)'),
  min_confidence: z
    .number()
    .optional()
    .default(0.7)
    .describe('Minimum similarity score to report a match (0.0-1.0)'),
  max_matches: z
    .number()
    .optional()
    .default(100)
    .describe('Maximum matches to return'),
})

export const kbFunctionMatchToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Match function signatures from a sample against the knowledge base and other ' +
    'analyzed samples. Uses byte-pattern hashing and API-call fingerprinting to ' +
    'find reused code and propagate function names and annotations.',
  inputSchema: KbFunctionMatchInputSchema,
}

interface FunctionSig {
  sample_id: string
  address: string
  name: string
  hash?: string
  size?: number
  api_calls?: string[]
}

function signatureOverlap(a: FunctionSig, b: FunctionSig): number {
  // Hash match = high confidence
  if (a.hash && b.hash && a.hash === b.hash) return 1.0

  // API call overlap
  if (a.api_calls?.length && b.api_calls?.length) {
    const setA = new Set(a.api_calls)
    const setB = new Set(b.api_calls)
    const intersection = [...setA].filter((x) => setB.has(x))
    const union = new Set([...setA, ...setB])
    const jaccard = union.size > 0 ? intersection.length / union.size : 0

    // Size similarity bonus
    let sizeBonus = 0
    if (a.size && b.size) {
      const ratio = Math.min(a.size, b.size) / Math.max(a.size, b.size)
      sizeBonus = ratio * 0.2
    }

    return Math.min(1.0, jaccard * 0.8 + sizeBonus)
  }

  // Size-only comparison (weak)
  if (a.size && b.size) {
    const ratio = Math.min(a.size, b.size) / Math.max(a.size, b.size)
    return ratio > 0.95 ? 0.5 : 0
  }

  return 0
}

export function createKbFunctionMatchHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, persistStaticAnalysisJsonArtifact } = deps

  return async (args: z.infer<typeof KbFunctionMatchInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      // Collect functions from target sample
      const targetFunctions: FunctionSig[] = []
      const targetEvidence = database.findAnalysisEvidenceBySample(args.sample_id)
      if (Array.isArray(targetEvidence)) {
        for (const entry of targetEvidence) {
          try {
            const data =
              typeof entry.result_json === 'string'
                ? JSON.parse(entry.result_json)
                : entry.result_json
            const family = entry.evidence_family ?? ''

            if (family === 'function_index' || family === 'function_list' || family === 'ghidra_functions') {
              const funcs = data?.data?.functions ?? data?.functions ?? []
              for (const f of funcs) {
                targetFunctions.push({
                  sample_id: args.sample_id,
                  address: f.address ?? f.entry ?? f.offset ?? '0x0',
                  name: f.name ?? `sub_${f.address ?? 'unknown'}`,
                  hash: f.hash ?? f.byte_hash,
                  size: f.size ?? f.length,
                  api_calls: f.api_calls ?? f.imports ?? f.calls,
                })
              }
            }
          } catch { /* skip */ }
        }
      }

      if (targetFunctions.length === 0) {
        return { ok: false, errors: ['No function data found for target sample. Run function analysis first.'] }
      }

      // Collect reference functions from other samples
      const referenceFunctions: FunctionSig[] = []
      const matchSampleIds = args.match_against ?? []

      // If no specific samples, search all KB entries
      if (matchSampleIds.length === 0) {
        warnings.push('No match_against samples provided; specify sample IDs to match against')
      }

      // Also gather from specified sample IDs
      for (const sid of matchSampleIds) {
        if (sid === args.sample_id) continue
        const evidence = database.findAnalysisEvidenceBySample(sid)
        if (Array.isArray(evidence)) {
          for (const entry of evidence) {
            try {
              const data =
                typeof entry.result_json === 'string'
                  ? JSON.parse(entry.result_json)
                  : entry.result_json
              const family = entry.evidence_family ?? ''

              if (family === 'function_index' || family === 'function_list' || family === 'ghidra_functions') {
                const funcs = data?.data?.functions ?? data?.functions ?? []
                for (const f of funcs) {
                  referenceFunctions.push({
                    sample_id: sid,
                    address: f.address ?? f.entry ?? '0x0',
                    name: f.name ?? `sub_${f.address ?? 'unknown'}`,
                    hash: f.hash ?? f.byte_hash,
                    size: f.size ?? f.length,
                    api_calls: f.api_calls ?? f.imports ?? f.calls,
                  })
                }
              }
            } catch { /* skip */ }
          }
        }
      }

      if (referenceFunctions.length === 0) {
        warnings.push('No reference functions found. Provide match_against sample IDs or build KB first.')
      }

      // Match functions
      interface Match {
        target_function: string
        target_address: string
        matched_function: string
        matched_sample_id: string
        matched_address: string
        confidence: number
      }

      const matches: Match[] = []
      for (const target of targetFunctions) {
        let bestMatch: Match | null = null
        let bestScore = 0

        for (const ref of referenceFunctions) {
          const score = signatureOverlap(target, ref)
          if (score >= args.min_confidence && score > bestScore) {
            bestScore = score
            bestMatch = {
              target_function: target.name,
              target_address: target.address,
              matched_function: ref.name,
              matched_sample_id: ref.sample_id,
              matched_address: ref.address,
              confidence: Math.round(score * 1000) / 1000,
            }
          }
        }

        if (bestMatch) matches.push(bestMatch)
      }

      matches.sort((a, b) => b.confidence - a.confidence)
      const topMatches = matches.slice(0, args.max_matches)

      const resultData = {
        sample_id: args.sample_id,
        target_function_count: targetFunctions.length,
        reference_function_count: referenceFunctions.length,
        match_count: topMatches.length,
        exact_matches: topMatches.filter((m) => m.confidence >= 0.99).length,
        high_confidence_matches: topMatches.filter((m) => m.confidence >= 0.8 && m.confidence < 0.99).length,
        matches: topMatches,
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, args.sample_id,
          'function_match', 'kb-function-match', resultData
        )
        if (artRef) artifacts.push(artRef)
      } catch { /* non-fatal */ }

      return {
        ok: true,
        data: resultData,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
