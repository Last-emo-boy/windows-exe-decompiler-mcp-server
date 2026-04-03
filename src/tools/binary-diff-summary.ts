/**
 * binary.diff.summary MCP tool — produces a bounded text digest of a binary diff.
 */

import { z } from 'zod'
import fs from 'fs/promises'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { BinaryDiffResult } from '../binary-diff-engine.js'

// ============================================================================
// Schemas
// ============================================================================

const TOOL_NAME = 'binary.diff.summary'

export const BinaryDiffSummaryInputSchema = z.object({
  sample_id_a: z.string().describe('First sample ID (format: sha256:<hex>)'),
  sample_id_b: z.string().describe('Second sample ID (format: sha256:<hex>)'),
  max_chars: z
    .number()
    .int()
    .min(200)
    .max(8000)
    .optional()
    .default(3000)
    .describe('Maximum characters in summary output'),
})

export const BinaryDiffSummaryOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({ summary: z.string() }).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const binaryDiffSummaryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Produce a compact text digest (≤ 3000 chars) of a binary diff between two samples, focusing on the most significant changes. Requires binary.diff to have been run first.',
  inputSchema: BinaryDiffSummaryInputSchema,
  outputSchema: BinaryDiffSummaryOutputSchema,
}

// ============================================================================
// Summary generator
// ============================================================================

export function generateDiffSummary(
  diff: BinaryDiffResult,
  maxChars: number
): string {
  const lines: string[] = []
  const stats = diff.summary_stats

  lines.push(`# Binary Diff: ${diff.sample_id_a.slice(0, 16)}… vs ${diff.sample_id_b.slice(0, 16)}…`)
  lines.push('')

  // Overview stats
  lines.push('## Overview')
  lines.push(
    `Functions: +${stats.functions_added} added, -${stats.functions_removed} removed, ~${stats.functions_modified} modified`
  )
  lines.push(
    `Imports: +${stats.imports_added} added, -${stats.imports_removed} removed`
  )
  lines.push(
    `Strings: +${stats.strings_added} added, -${stats.strings_removed} removed`
  )
  if (stats.attack_techniques_added > 0 || stats.attack_techniques_removed > 0) {
    lines.push(
      `ATT&CK: +${stats.attack_techniques_added} techniques, -${stats.attack_techniques_removed} techniques`
    )
  }
  lines.push('')

  // Most-changed functions
  if (diff.function_diff?.functions_modified.length) {
    lines.push('## Most Changed Functions')
    const topModified = diff.function_diff.functions_modified
      .sort((a, b) => (a.similarity ?? 1) - (b.similarity ?? 1))
      .slice(0, 10)
    for (const fn of topModified) {
      const sim = typeof fn.similarity === 'number' ? `${(fn.similarity * 100).toFixed(0)}%` : '?'
      lines.push(`- ${fn.name} (${sim} similar)`)
    }
    lines.push('')
  }

  // New functions
  if (diff.function_diff?.functions_added.length) {
    lines.push('## New Functions (in sample B)')
    for (const fn of diff.function_diff.functions_added.slice(0, 10)) {
      lines.push(`- ${fn.name}`)
    }
    if (diff.function_diff.functions_added.length > 10) {
      lines.push(`  ... and ${diff.function_diff.functions_added.length - 10} more`)
    }
    lines.push('')
  }

  // Removed functions
  if (diff.function_diff?.functions_removed.length) {
    lines.push('## Removed Functions (not in sample B)')
    for (const fn of diff.function_diff.functions_removed.slice(0, 10)) {
      lines.push(`- ${fn.name}`)
    }
    if (diff.function_diff.functions_removed.length > 10) {
      lines.push(`  ... and ${diff.function_diff.functions_removed.length - 10} more`)
    }
    lines.push('')
  }

  // Import changes
  if (diff.structural_delta?.imports.added.length || diff.structural_delta?.imports.removed.length) {
    lines.push('## Import Changes')
    for (const imp of (diff.structural_delta?.imports.added ?? []).slice(0, 10)) {
      lines.push(`+ ${imp}`)
    }
    for (const imp of (diff.structural_delta?.imports.removed ?? []).slice(0, 10)) {
      lines.push(`- ${imp}`)
    }
    lines.push('')
  }

  // ATT&CK changes
  if (diff.attack_delta) {
    const hasChanges =
      diff.attack_delta.techniques_added.length > 0 ||
      diff.attack_delta.techniques_removed.length > 0 ||
      diff.attack_delta.confidence_changed.length > 0
    if (hasChanges) {
      lines.push('## ATT&CK Technique Changes')
      for (const t of diff.attack_delta.techniques_added.slice(0, 5)) {
        lines.push(`+ ${t.id}: ${t.name}`)
      }
      for (const t of diff.attack_delta.techniques_removed.slice(0, 5)) {
        lines.push(`- ${t.id}: ${t.name}`)
      }
      for (const c of diff.attack_delta.confidence_changed.slice(0, 5)) {
        lines.push(`~ ${c.id}: ${c.name} (${c.confidence_a} → ${c.confidence_b})`)
      }
      lines.push('')
    }
  }

  // String changes (brief)
  if (diff.structural_delta?.strings.added.length) {
    lines.push('## Notable New Strings')
    // Prefer longer, more interesting strings
    const interesting = diff.structural_delta.strings.added
      .filter((s) => s.length >= 8)
      .slice(0, 10)
    for (const s of interesting) {
      lines.push(`  "${s.length > 80 ? s.slice(0, 80) + '…' : s}"`)
    }
    lines.push('')
  }

  let text = lines.join('\n')
  if (text.length > maxChars) {
    text = text.slice(0, maxChars - 20) + '\n\n... (truncated)'
  }
  return text
}

// ============================================================================
// Handler
// ============================================================================

export function createBinaryDiffSummaryHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = BinaryDiffSummaryInputSchema.parse(args)

    // Find the diff artifact
    const artifacts = database.findArtifactsByType(input.sample_id_a, 'binary_diff')
    const diffArtifact = artifacts[0]

    if (!diffArtifact) {
      return {
        ok: false,
        errors: [
          `No binary diff artifact found for ${input.sample_id_a}. Run binary.diff first.`,
        ],
      }
    }

    // Read artifact content
    let diffData: BinaryDiffResult
    try {
      const content = await fs.readFile(diffArtifact.path, 'utf8')
      diffData = JSON.parse(content) as BinaryDiffResult
    } catch {
      return { ok: false, errors: ['Failed to parse diff artifact'] }
    }

    const summary = generateDiffSummary(diffData, input.max_chars)

    return {
      ok: true,
      data: { summary },
      metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
    }
  }
}
