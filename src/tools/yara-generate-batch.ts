/**
 * yara.generate.batch MCP tool — generate family detection rules from multiple samples.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import {
  extractRuleEvidence,
  buildHybridRule,
  scoreRule,
  type RuleMeta,
  type RuleEvidence,
  type Strictness,
} from '../yara-rule-builder.js'

// ============================================================================
// Schemas
// ============================================================================

const TOOL_NAME = 'yara.generate.batch'

export const YaraGenerateBatchInputSchema = z.object({
  sample_ids: z
    .array(z.string())
    .min(2)
    .max(50)
    .describe('Array of sample IDs to find common features'),
  strictness: z
    .enum(['tight', 'balanced', 'loose'])
    .optional()
    .default('balanced')
    .describe('Rule strictness'),
  family_name: z.string().optional().describe('Malware family name for the rule'),
})

export const YaraGenerateBatchOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const yaraGenerateBatchToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Generate YARA family detection rules by finding common unique features across multiple samples.',
  inputSchema: YaraGenerateBatchInputSchema,
  outputSchema: YaraGenerateBatchOutputSchema,
}

// ============================================================================
// Common feature extraction
// ============================================================================

function findCommonStrings(evidenceList: RuleEvidence[], minOccurrence: number): string[] {
  const counts = new Map<string, number>()
  for (const ev of evidenceList) {
    const seen = new Set<string>()
    for (const s of ev.unique_strings) {
      if (!seen.has(s)) {
        counts.set(s, (counts.get(s) ?? 0) + 1)
        seen.add(s)
      }
    }
  }
  return [...counts.entries()]
    .filter(([, count]) => count >= minOccurrence)
    .sort((a, b) => b[1] - a[1])
    .map(([s]) => s)
    .slice(0, 50)
}

function findCommonImports(evidenceList: RuleEvidence[], minOccurrence: number): string[] {
  const counts = new Map<string, number>()
  for (const ev of evidenceList) {
    const seen = new Set<string>()
    for (const imp of ev.suspicious_imports) {
      const key = imp.toLowerCase()
      if (!seen.has(key)) {
        counts.set(key, (counts.get(key) ?? 0) + 1)
        seen.add(key)
      }
    }
  }
  return [...counts.entries()]
    .filter(([, count]) => count >= minOccurrence)
    .sort((a, b) => b[1] - a[1])
    .map(([s]) => s)
    .slice(0, 20)
}

// ============================================================================
// Handler
// ============================================================================

export function createYaraGenerateBatchHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = YaraGenerateBatchInputSchema.parse(args)
    const warnings: string[] = []

    // Validate all samples exist
    const missing = input.sample_ids.filter((id) => !database.findSample(id))
    if (missing.length > 0) {
      return { ok: false, errors: [`Samples not found: ${missing.join(', ')}`] }
    }

    // Load evidence for all samples
    const evidenceList: RuleEvidence[] = []
    for (const sampleId of input.sample_ids) {
      const evidence = database.findAnalysisEvidenceBySample(sampleId)
      const combined: Record<string, unknown> = {}
      if (Array.isArray(evidence)) {
        for (const entry of evidence) {
          const data = typeof entry.result_json === 'string' ? JSON.parse(entry.result_json) : entry.result_json
          if (data && typeof data === 'object') Object.assign(combined, data)
        }
      }
      const sample = database.findSample(sampleId)
      if (sample) combined.file_size = sample.size
      evidenceList.push(extractRuleEvidence(combined))
    }

    // Find common features (present in >= 60% of samples)
    const minOccurrence = Math.max(2, Math.floor(input.sample_ids.length * 0.6))
    const commonStrings = findCommonStrings(evidenceList, minOccurrence)
    const commonImports = findCommonImports(evidenceList, minOccurrence)

    if (commonStrings.length === 0 && commonImports.length === 0) {
      return {
        ok: false,
        errors: ['No common features found across the provided samples'],
        warnings,
      }
    }

    const familyEvidence: RuleEvidence = {
      unique_strings: commonStrings,
      suspicious_imports: commonImports,
      all_imports: commonImports,
      byte_patterns: [],
    }

    const meta: RuleMeta = {
      sample_id: input.sample_ids[0],
      description: `Family rule for ${input.family_name ?? 'unknown'} (${input.sample_ids.length} samples)`,
      family: input.family_name,
      date: new Date().toISOString().slice(0, 10),
    }

    const ruleText = buildHybridRule(familyEvidence, input.strictness as Strictness, meta)
    if (!ruleText) {
      return { ok: false, errors: ['Failed to generate family rule'] }
    }

    const { score, breakdown } = scoreRule(ruleText, familyEvidence)

    // Persist
    const artifacts: ArtifactRef[] = []
    try {
      const ref = await persistStaticAnalysisJsonArtifact(
        workspaceManager,
        database,
        input.sample_ids[0],
        'yara_family_rule',
        `yara_family_${input.family_name ?? 'batch'}`,
        {
          rule_text: ruleText,
          score,
          breakdown,
          common_strings: commonStrings.length,
          common_imports: commonImports.length,
          sample_count: input.sample_ids.length,
        }
      )
      artifacts.push(ref)
    } catch {
      warnings.push('Failed to persist family rule artifact')
    }

    return {
      ok: true,
      data: {
        rule_text: ruleText,
        score,
        breakdown,
        common_features: {
          strings: commonStrings.length,
          imports: commonImports.length,
          min_occurrence: minOccurrence,
        },
        sample_count: input.sample_ids.length,
      },
      warnings: warnings.length > 0 ? warnings : undefined,
      artifacts: artifacts.length > 0 ? artifacts : undefined,
      metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
    }
  }
}
