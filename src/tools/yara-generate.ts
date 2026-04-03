/**
 * yara.generate MCP tool — auto-generate YARA detection rules from sample analysis evidence.
 */

import { z } from 'zod'
import fs from 'fs/promises'
import path from 'path'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import {
  extractRuleEvidence,
  buildStringRule,
  buildImportRule,
  buildBytePatternRule,
  buildHybridRule,
  scoreRule,
  type Strictness,
  type RuleMeta,
  type RuleEvidence,
} from '../yara-rule-builder.js'

// ============================================================================
// Schemas
// ============================================================================

const TOOL_NAME = 'yara.generate'

export const YaraGenerateInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  strictness: z
    .enum(['tight', 'balanced', 'loose'])
    .optional()
    .default('balanced')
    .describe('Rule strictness: tight (fewer FPs), balanced, loose (fewer FNs)'),
  deploy: z
    .boolean()
    .optional()
    .default(false)
    .describe('Deploy generated rule to workers/yara_rules/ for future scans'),
  rule_types: z
    .array(z.enum(['string', 'import', 'byte_pattern', 'hybrid']))
    .optional()
    .default(['hybrid'])
    .describe('Types of rules to generate'),
})

export const YaraGenerateOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const yaraGenerateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Auto-generate YARA detection rules from sample analysis evidence (strings, imports, byte patterns). Supports tight/balanced/loose strictness levels.',
  inputSchema: YaraGenerateInputSchema,
  outputSchema: YaraGenerateOutputSchema,
}

// ============================================================================
// Handler
// ============================================================================

async function loadAnalysisEvidence(
  database: DatabaseManager,
  sampleId: string
): Promise<Record<string, unknown>> {
  const combined: Record<string, unknown> = {}
  const evidence = database.findAnalysisEvidenceBySample(sampleId)

  if (Array.isArray(evidence)) {
    for (const entry of evidence) {
      const data =
        typeof entry.result_json === 'string'
          ? JSON.parse(entry.result_json)
          : entry.result_json
      if (!data || typeof data !== 'object') continue
      Object.assign(combined, data)
    }
  }

  // Also get sample info
  const sample = database.findSample(sampleId)
  if (sample) {
    combined.file_size = sample.size
  }

  return combined
}

export function createYaraGenerateHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = YaraGenerateInputSchema.parse(args)
    const warnings: string[] = []

    const sample = database.findSample(input.sample_id)
    if (!sample) {
      return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
    }

    // Load analysis evidence
    const analysisData = await loadAnalysisEvidence(database, input.sample_id)
    const evidence = extractRuleEvidence(analysisData)

    if (
      evidence.unique_strings.length === 0 &&
      evidence.all_imports.length === 0 &&
      evidence.byte_patterns.length === 0
    ) {
      return {
        ok: false,
        errors: ['Insufficient analysis evidence to generate YARA rules. Run strings.extract and pe.imports.extract first.'],
      }
    }

    const meta: RuleMeta = {
      sample_id: input.sample_id,
      description: `Auto-generated ${input.strictness} YARA rule`,
      hash: input.sample_id.startsWith('sha256:') ? input.sample_id.slice(7) : undefined,
      date: new Date().toISOString().slice(0, 10),
    }

    // Generate requested rules
    const rules: Array<{ type: string; rule_text: string; score: number; breakdown: unknown }> = []

    for (const ruleType of input.rule_types) {
      let ruleText = ''
      switch (ruleType) {
        case 'string':
          ruleText = buildStringRule(evidence.unique_strings, meta)
          break
        case 'import':
          ruleText = buildImportRule(evidence.suspicious_imports.length > 0 ? evidence.suspicious_imports : evidence.all_imports, meta)
          break
        case 'byte_pattern':
          ruleText = buildBytePatternRule(evidence.byte_patterns, meta)
          break
        case 'hybrid':
          ruleText = buildHybridRule(evidence, input.strictness as Strictness, meta)
          break
      }

      if (ruleText) {
        const { score, breakdown } = scoreRule(ruleText, evidence)
        rules.push({ type: ruleType, rule_text: ruleText, score, breakdown })
      } else {
        warnings.push(`Could not generate ${ruleType} rule — insufficient evidence`)
      }
    }

    if (rules.length === 0) {
      return {
        ok: false,
        errors: ['No rules could be generated from available evidence'],
        warnings,
      }
    }

    // Deploy if requested
    if (input.deploy) {
      const yaraDir = path.resolve('workers', 'yara_rules')
      try {
        await fs.mkdir(yaraDir, { recursive: true })
        for (const rule of rules) {
          const filename = `auto_${input.sample_id.slice(7, 19)}_${rule.type}.yar`
          await fs.writeFile(path.join(yaraDir, filename), rule.rule_text, 'utf8')
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        warnings.push(`Deploy failed: ${msg.slice(0, 200)}`)
      }
    }

    // Persist artifact
    const artifacts: ArtifactRef[] = []
    try {
      const artifactRef = await persistStaticAnalysisJsonArtifact(
        workspaceManager,
        database,
        input.sample_id,
        'yara_rule_generation',
        `yara_${input.strictness}`,
        { rules, evidence_summary: { strings: evidence.unique_strings.length, imports: evidence.all_imports.length, suspicious_imports: evidence.suspicious_imports.length, byte_patterns: evidence.byte_patterns.length } }
      )
      artifacts.push(artifactRef)
    } catch {
      warnings.push('Failed to persist rule artifact')
    }

    return {
      ok: true,
      data: {
        rules,
        best_rule: rules.sort((a, b) => b.score - a.score)[0],
        evidence_summary: {
          unique_strings: evidence.unique_strings.length,
          suspicious_imports: evidence.suspicious_imports.length,
          byte_patterns: evidence.byte_patterns.length,
        },
      },
      warnings: warnings.length > 0 ? warnings : undefined,
      artifacts: artifacts.length > 0 ? artifacts : undefined,
      metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
    }
  }
}
