/**
 * vuln.pattern.summary MCP tool â€?aggregate vulnerability scan findings into a concise summary.
 */

import { z } from 'zod'
import fs from 'fs/promises'
import type { ToolDefinition, ToolArgs, WorkerResult , PluginToolDeps} from '../../sdk.js'
import type { VulnScanResult, VulnFinding } from '../../../vuln-patterns.js'

// ============================================================================
// Schemas
// ============================================================================

const TOOL_NAME = 'vuln.pattern.summary'

export const VulnPatternSummaryInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  top_n_functions: z
    .number()
    .int()
    .min(1)
    .max(50)
    .optional()
    .default(10)
    .describe('Number of most vulnerable functions to include'),
})

export const VulnPatternSummaryOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const vulnPatternSummaryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Summarize vulnerability scan findings: aggregate by CWE, rank most vulnerable functions, compute severity distribution.',
  inputSchema: VulnPatternSummaryInputSchema,
  outputSchema: VulnPatternSummaryOutputSchema,
}

// ============================================================================
// Handler
// ============================================================================

function buildSummary(
  scanResult: VulnScanResult,
  topN: number
): Record<string, unknown> {
  // CWE breakdown
  const cweBreakdown = Object.entries(scanResult.cwe_counts)
    .sort((a, b) => b[1] - a[1])
    .map(([cwe, count]) => ({ cwe, count }))

  // Severity distribution
  const severityDist = {
    critical: scanResult.severity_counts['critical'] ?? 0,
    high: scanResult.severity_counts['high'] ?? 0,
    medium: scanResult.severity_counts['medium'] ?? 0,
    low: scanResult.severity_counts['low'] ?? 0,
  }

  // Most vulnerable functions
  const functionRisk = new Map<
    string,
    { name: string; address: string; findings: VulnFinding[]; risk_score: number }
  >()
  for (const f of scanResult.findings) {
    const key = f.function_address
    if (!functionRisk.has(key)) {
      functionRisk.set(key, { name: f.function_name, address: f.function_address, findings: [], risk_score: 0 })
    }
    const entry = functionRisk.get(key)!
    entry.findings.push(f)
    const severityWeight: Record<string, number> = { critical: 10, high: 5, medium: 2, low: 1 }
    entry.risk_score += (severityWeight[f.severity] ?? 1) * f.confidence
  }

  const topFunctions = [...functionRisk.values()]
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, topN)
    .map((f) => ({
      function_name: f.name,
      function_address: f.address,
      risk_score: Math.round(f.risk_score * 100) / 100,
      finding_count: f.findings.length,
      cwe_list: [...new Set(f.findings.map((x) => x.cwe))],
      top_severity: f.findings.reduce(
        (worst, cur) => {
          const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
          return (order[cur.severity] ?? 4) < (order[worst] ?? 4) ? cur.severity : worst
        },
        'low' as string
      ),
    }))

  // Overall risk assessment
  const totalRisk = [...functionRisk.values()].reduce((sum, f) => sum + f.risk_score, 0)
  let riskLevel: string
  if (severityDist.critical > 0 || totalRisk > 50) riskLevel = 'critical'
  else if (severityDist.high > 2 || totalRisk > 20) riskLevel = 'high'
  else if (severityDist.high > 0 || totalRisk > 5) riskLevel = 'medium'
  else riskLevel = 'low'

  return {
    overall_risk_level: riskLevel,
    total_findings: scanResult.total_findings,
    functions_scanned: scanResult.functions_scanned,
    functions_with_findings: functionRisk.size,
    severity_distribution: severityDist,
    cwe_breakdown: cweBreakdown,
    top_vulnerable_functions: topFunctions,
    total_risk_score: Math.round(totalRisk * 100) / 100,
  }
}

export function createVulnPatternSummaryHandler(deps: PluginToolDeps) {
  const { workspaceManager, database } = deps
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = VulnPatternSummaryInputSchema.parse(args)

    // Find scan artifact
    const artifacts = database.findArtifactsByType(input.sample_id, 'vuln_pattern_scan')
    const scanArtifact = artifacts[0]

    if (!scanArtifact) {
      return {
        ok: false,
        errors: [
          `No vulnerability scan results found for ${input.sample_id}. Run vuln.pattern.scan first.`,
        ],
      }
    }

    let scanResult: VulnScanResult
    try {
      const content = await fs.readFile(scanArtifact.path, 'utf8')
      scanResult = JSON.parse(content) as VulnScanResult
    } catch {
      return { ok: false, errors: ['Failed to parse scan artifact'] }
    }

    const summary = buildSummary(scanResult, input.top_n_functions)

    return {
      ok: true,
      data: summary,
      metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
    }
  }
}
