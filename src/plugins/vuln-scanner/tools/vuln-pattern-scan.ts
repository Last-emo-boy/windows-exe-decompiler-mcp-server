/**
 * vuln.pattern.scan MCP tool �?scan decompiled functions for CWE vulnerability patterns.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef , PluginToolDeps} from '../../sdk.js'
import { persistStaticAnalysisJsonArtifact } from '../../../static-analysis-artifacts.js'
import { loadPatterns, scanAllFunctions, type VulnScanResult } from '../../../vuln-patterns.js'

// ============================================================================
// Schemas
// ============================================================================

const TOOL_NAME = 'vuln.pattern.scan'

export const VulnPatternScanInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  min_confidence: z
    .number()
    .min(0)
    .max(1)
    .optional()
    .default(0.3)
    .describe('Minimum confidence threshold for findings'),
  max_findings: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .default(100)
    .describe('Maximum number of findings to return'),
})

export const VulnPatternScanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const vulnPatternScanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Scan decompiled functions for CWE vulnerability patterns (buffer overflow, format string, command injection, DLL hijacking, integer overflow, use-after-free).',
  inputSchema: VulnPatternScanInputSchema,
  outputSchema: VulnPatternScanOutputSchema,
}

// ============================================================================
// Handler
// ============================================================================

function extractDecompiledFunctions(
  database: any,
  sampleId: string
): Array<{ name: string; address: string; decompiled_code: string }> {
  const functions: Array<{ name: string; address: string; decompiled_code: string }> = []

  // Try loading from analysis_evidence (function_map stage)
  const evidence = database.findAnalysisEvidenceBySample(sampleId)
  if (Array.isArray(evidence)) {
    for (const entry of evidence) {
      const family = entry.evidence_family ?? ''
      if (
        family === 'function_map' ||
        family === 'decompilation' ||
        family === 'functions'
      ) {
        const data =
          typeof entry.result_json === 'string'
            ? JSON.parse(entry.result_json)
            : entry.result_json
        if (!data) continue

        // Extract functions array
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
  }

  return functions
}

export function createVulnPatternScanHandler(deps: PluginToolDeps) {
  const { workspaceManager, database } = deps
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = VulnPatternScanInputSchema.parse(args)
    const warnings: string[] = []

    const sample = database.findSample(input.sample_id)
    if (!sample) {
      return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
    }

    // Load vulnerability patterns
    const patternDB = await loadPatterns()

    // Extract decompiled functions
    const functions = extractDecompiledFunctions(database, input.sample_id)
    if (functions.length === 0) {
      return {
        ok: false,
        errors: [
          'No decompiled functions found. Run function_map stage or code.functions.reconstruct first.',
        ],
      }
    }

    // Scan
    const scanResult = scanAllFunctions(
      functions,
      patternDB.patterns,
      input.min_confidence
    )

    // Truncate findings
    scanResult.findings = scanResult.findings
      .sort((a, b) => {
        const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
        const diff = (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4)
        if (diff !== 0) return diff
        return b.confidence - a.confidence
      })
      .slice(0, input.max_findings)

    // Persist artifact
    const artifacts: ArtifactRef[] = []
    try {
      const ref = await persistStaticAnalysisJsonArtifact(
        workspaceManager,
        database,
        input.sample_id,
        'vuln_pattern_scan',
        'vuln_findings',
        scanResult
      )
      artifacts.push(ref)
    } catch {
      warnings.push('Failed to persist vulnerability scan artifact')
    }

    return {
      ok: true,
      data: scanResult,
      warnings: warnings.length > 0 ? warnings : undefined,
      artifacts: artifacts.length > 0 ? artifacts : undefined,
      metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
    }
  }
}
