/**
 * cross.binary.compare MCP tool — Compare multiple binaries across a sample set
 * to find shared code, common libraries, and lineage relationships.
 * Supports PE, ELF, and Mach-O.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'cross.binary.compare'

export const CrossBinaryCompareInputSchema = z.object({
  sample_ids: z
    .array(z.string())
    .min(2)
    .max(20)
    .describe('Array of sample IDs to compare (format: sha256:<hex>)'),
  comparison_mode: z
    .enum(['function_hashes', 'import_overlap', 'string_overlap', 'full'])
    .optional()
    .default('full')
    .describe('Comparison strategy'),
})

export const crossBinaryCompareToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Compare two or more binaries to discover shared code (function hashes), ' +
    'common imported APIs, overlapping strings, and possible lineage/versioning ' +
    'relationships. Useful for malware family clustering and multi-component analysis.',
  inputSchema: CrossBinaryCompareInputSchema,
}

interface SampleEvidence {
  sample_id: string
  functions: string[]
  imports: string[]
  strings: string[]
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 0
  const intersection = new Set([...a].filter((x) => b.has(x)))
  const union = new Set([...a, ...b])
  return intersection.size / union.size
}

export function createCrossBinaryCompareHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, persistStaticAnalysisJsonArtifact } = deps

  return async (args: z.infer<typeof CrossBinaryCompareInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const sampleData: SampleEvidence[] = []

      for (const sid of args.sample_ids) {
        const sample = database.findSample(sid)
        if (!sample) {
          warnings.push(`Sample not found: ${sid}, skipping`)
          continue
        }

        const fns: string[] = []
        const imports: string[] = []
        const strings: string[] = []

        const evidence = database.findAnalysisEvidenceBySample(sid)
        if (Array.isArray(evidence)) {
          for (const entry of evidence) {
            try {
              const data =
                typeof entry.result_json === 'string'
                  ? JSON.parse(entry.result_json)
                  : entry.result_json
              const family = entry.evidence_family ?? ''

              if (family === 'function_index' || family === 'function_list') {
                const funcs = data?.data?.functions ?? data?.functions ?? []
                for (const f of funcs) {
                  if (f.hash) fns.push(f.hash)
                  else if (f.name) fns.push(f.name)
                }
              }
              if (family === 'pe_imports' || family === 'elf_imports') {
                const imps = data?.data?.imports ?? data?.imports ?? []
                for (const imp of imps) {
                  const name = typeof imp === 'string' ? imp : imp?.name ?? imp?.function_name
                  if (name) imports.push(name)
                }
              }
              if (family === 'strings') {
                const strs = data?.data?.strings ?? data?.strings ?? []
                for (const s of strs) {
                  const val = typeof s === 'string' ? s : s?.value
                  if (val && val.length >= 6) strings.push(val)
                }
              }
            } catch {
              /* skip malformed evidence */
            }
          }
        }

        sampleData.push({ sample_id: sid, functions: fns, imports, strings })
      }

      if (sampleData.length < 2) {
        return { ok: false, errors: ['Need at least 2 valid samples for comparison'] }
      }

      // Pairwise similarity matrix
      const pairResults: Array<{
        a: string
        b: string
        function_similarity: number
        import_similarity: number
        string_similarity: number
        overall: number
        shared_imports: string[]
        shared_strings: string[]
      }> = []

      for (let i = 0; i < sampleData.length; i++) {
        for (let j = i + 1; j < sampleData.length; j++) {
          const a = sampleData[i]
          const b = sampleData[j]

          const fnSim =
            args.comparison_mode === 'import_overlap' || args.comparison_mode === 'string_overlap'
              ? 0
              : jaccard(new Set(a.functions), new Set(b.functions))

          const impSim =
            args.comparison_mode === 'function_hashes' || args.comparison_mode === 'string_overlap'
              ? 0
              : jaccard(new Set(a.imports), new Set(b.imports))

          const strSim =
            args.comparison_mode === 'function_hashes' || args.comparison_mode === 'import_overlap'
              ? 0
              : jaccard(new Set(a.strings), new Set(b.strings))

          const overall = (fnSim + impSim + strSim) / 3

          const sharedImports = [...new Set(a.imports)].filter((x) => new Set(b.imports).has(x)).slice(0, 50)
          const sharedStrings = [...new Set(a.strings)].filter((x) => new Set(b.strings).has(x)).slice(0, 50)

          pairResults.push({
            a: a.sample_id,
            b: b.sample_id,
            function_similarity: Math.round(fnSim * 1000) / 1000,
            import_similarity: Math.round(impSim * 1000) / 1000,
            string_similarity: Math.round(strSim * 1000) / 1000,
            overall: Math.round(overall * 1000) / 1000,
            shared_imports: sharedImports,
            shared_strings: sharedStrings,
          })
        }
      }

      // Cluster groups (simple threshold-based)
      const CLUSTER_THRESHOLD = 0.6
      const clusters: string[][] = []
      const assigned = new Set<string>()
      for (const pair of pairResults.sort((a, b) => b.overall - a.overall)) {
        if (pair.overall < CLUSTER_THRESHOLD) continue
        let found = false
        for (const cluster of clusters) {
          if (cluster.includes(pair.a) || cluster.includes(pair.b)) {
            if (!cluster.includes(pair.a)) cluster.push(pair.a)
            if (!cluster.includes(pair.b)) cluster.push(pair.b)
            assigned.add(pair.a)
            assigned.add(pair.b)
            found = true
            break
          }
        }
        if (!found) {
          clusters.push([pair.a, pair.b])
          assigned.add(pair.a)
          assigned.add(pair.b)
        }
      }

      const resultData = {
        sample_count: sampleData.length,
        comparison_mode: args.comparison_mode,
        pairwise_similarities: pairResults,
        clusters: clusters.length > 0 ? clusters : undefined,
        per_sample_stats: sampleData.map((s) => ({
          sample_id: s.sample_id,
          function_count: s.functions.length,
          import_count: s.imports.length,
          string_count: s.strings.length,
        })),
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          args.sample_ids[0],
          'cross_binary_compare',
          'cross-binary-compare',
          resultData
        )
        if (artRef) artifacts.push(artRef)
      } catch {
        /* non-fatal */
      }

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
