/**
 * Binary diff engine — computes structural and ATT&CK deltas between two samples.
 */

import { z } from 'zod'
import { execFile } from 'child_process'
import { promisify } from 'util'
import path from 'path'
import { fileURLToPath } from 'url'

const execFileAsync = promisify(execFile)

// ============================================================================
// Types
// ============================================================================

export interface FunctionDiffEntry {
  name: string
  address_a?: number | string | null
  address_b?: number | string | null
  size_a?: number | null
  size_b?: number | null
  similarity: number
}

export interface RizinDiffResult {
  ok: boolean
  functions_added: FunctionDiffEntry[]
  functions_removed: FunctionDiffEntry[]
  functions_modified: FunctionDiffEntry[]
  raw_output?: string
  warnings?: string[]
  error?: string
}

export interface ImportDelta {
  added: string[]
  removed: string[]
  common_count: number
}

export interface ExportDelta {
  added: string[]
  removed: string[]
  common_count: number
}

export interface SectionDelta {
  added: string[]
  removed: string[]
  size_changed: Array<{ name: string; size_a: number; size_b: number }>
}

export interface StringDelta {
  added: string[]
  removed: string[]
  common_count: number
}

export interface AttackTechnique {
  id: string
  name: string
  confidence?: number
}

export interface AttackDelta {
  techniques_added: AttackTechnique[]
  techniques_removed: AttackTechnique[]
  confidence_changed: Array<{
    id: string
    name: string
    confidence_a: number
    confidence_b: number
  }>
}

export interface StructuralDelta {
  imports: ImportDelta
  exports: ExportDelta
  sections: SectionDelta
  strings: StringDelta
}

export interface BinaryDiffResult {
  ok: boolean
  sample_id_a: string
  sample_id_b: string
  function_diff: RizinDiffResult | null
  structural_delta: StructuralDelta | null
  attack_delta: AttackDelta | null
  summary_stats: {
    functions_added: number
    functions_removed: number
    functions_modified: number
    imports_added: number
    imports_removed: number
    strings_added: number
    strings_removed: number
    attack_techniques_added: number
    attack_techniques_removed: number
  }
  errors: string[]
  warnings: string[]
}

// ============================================================================
// Rizin diff via Python worker
// ============================================================================

export async function runRizinDiff(
  binaryPathA: string,
  binaryPathB: string
): Promise<RizinDiffResult> {
  const workerScript = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    'workers',
    'rizin_diff_worker.py'
  )

  try {
    const { stdout } = await execFileAsync(
      'python3',
      [workerScript, binaryPathA, binaryPathB],
      { encoding: 'utf8', timeout: 180_000, windowsHide: true }
    )
    return JSON.parse(stdout.trim()) as RizinDiffResult
  } catch (err: unknown) {
    // Try python instead of python3 on Windows
    try {
      const { stdout } = await execFileAsync(
        'python',
        [workerScript, binaryPathA, binaryPathB],
        { encoding: 'utf8', timeout: 180_000, windowsHide: true }
      )
      return JSON.parse(stdout.trim()) as RizinDiffResult
    } catch {
      const msg = err instanceof Error ? err.message : String(err)
      return {
        ok: false,
        functions_added: [],
        functions_removed: [],
        functions_modified: [],
        error: `radiff2 worker failed: ${msg.slice(0, 500)}`,
      }
    }
  }
}

// ============================================================================
// Structural delta computation
// ============================================================================

export function computeImportDelta(
  importsA: string[],
  importsB: string[]
): ImportDelta {
  const setA = new Set(importsA.map((s) => s.toLowerCase()))
  const setB = new Set(importsB.map((s) => s.toLowerCase()))
  const added = [...setB].filter((x) => !setA.has(x))
  const removed = [...setA].filter((x) => !setB.has(x))
  const common = [...setA].filter((x) => setB.has(x))
  return { added, removed, common_count: common.length }
}

export function computeExportDelta(
  exportsA: string[],
  exportsB: string[]
): ExportDelta {
  const setA = new Set(exportsA)
  const setB = new Set(exportsB)
  const added = [...setB].filter((x) => !setA.has(x))
  const removed = [...setA].filter((x) => !setB.has(x))
  const common = [...setA].filter((x) => setB.has(x))
  return { added, removed, common_count: common.length }
}

export function computeSectionDelta(
  sectionsA: Array<{ name: string; size: number }>,
  sectionsB: Array<{ name: string; size: number }>
): SectionDelta {
  const mapA = new Map(sectionsA.map((s) => [s.name, s.size]))
  const mapB = new Map(sectionsB.map((s) => [s.name, s.size]))
  const added = [...mapB.keys()].filter((k) => !mapA.has(k))
  const removed = [...mapA.keys()].filter((k) => !mapB.has(k))
  const size_changed: SectionDelta['size_changed'] = []
  for (const [name, sizeA] of mapA) {
    const sizeB = mapB.get(name)
    if (sizeB !== undefined && sizeB !== sizeA) {
      size_changed.push({ name, size_a: sizeA, size_b: sizeB })
    }
  }
  return { added, removed, size_changed }
}

export function computeStringDelta(
  stringsA: string[],
  stringsB: string[]
): StringDelta {
  const setA = new Set(stringsA)
  const setB = new Set(stringsB)
  const added = [...setB].filter((x) => !setA.has(x)).slice(0, 200)
  const removed = [...setA].filter((x) => !setB.has(x)).slice(0, 200)
  const common = [...setA].filter((x) => setB.has(x))
  return { added, removed, common_count: common.length }
}

// ============================================================================
// ATT&CK mapping delta
// ============================================================================

export function computeAttackDelta(
  attackA: AttackTechnique[],
  attackB: AttackTechnique[]
): AttackDelta {
  const mapA = new Map(attackA.map((t) => [t.id, t]))
  const mapB = new Map(attackB.map((t) => [t.id, t]))

  const techniques_added = [...mapB.values()].filter((t) => !mapA.has(t.id))
  const techniques_removed = [...mapA.values()].filter((t) => !mapB.has(t.id))
  const confidence_changed: AttackDelta['confidence_changed'] = []

  for (const [id, techA] of mapA) {
    const techB = mapB.get(id)
    if (techB && techA.confidence !== techB.confidence) {
      confidence_changed.push({
        id,
        name: techA.name,
        confidence_a: techA.confidence ?? 0,
        confidence_b: techB.confidence ?? 0,
      })
    }
  }

  return { techniques_added, techniques_removed, confidence_changed }
}

// ============================================================================
// Full diff orchestration
// ============================================================================

export function computeStructuralDelta(
  artifactsA: {
    imports?: string[]
    exports?: string[]
    sections?: Array<{ name: string; size: number }>
    strings?: string[]
  },
  artifactsB: {
    imports?: string[]
    exports?: string[]
    sections?: Array<{ name: string; size: number }>
    strings?: string[]
  }
): StructuralDelta {
  return {
    imports: computeImportDelta(
      artifactsA.imports ?? [],
      artifactsB.imports ?? []
    ),
    exports: computeExportDelta(
      artifactsA.exports ?? [],
      artifactsB.exports ?? []
    ),
    sections: computeSectionDelta(
      artifactsA.sections ?? [],
      artifactsB.sections ?? []
    ),
    strings: computeStringDelta(
      artifactsA.strings ?? [],
      artifactsB.strings ?? []
    ),
  }
}

export function buildSummaryStats(result: BinaryDiffResult): BinaryDiffResult['summary_stats'] {
  return {
    functions_added: result.function_diff?.functions_added.length ?? 0,
    functions_removed: result.function_diff?.functions_removed.length ?? 0,
    functions_modified: result.function_diff?.functions_modified.length ?? 0,
    imports_added: result.structural_delta?.imports.added.length ?? 0,
    imports_removed: result.structural_delta?.imports.removed.length ?? 0,
    strings_added: result.structural_delta?.strings.added.length ?? 0,
    strings_removed: result.structural_delta?.strings.removed.length ?? 0,
    attack_techniques_added: result.attack_delta?.techniques_added.length ?? 0,
    attack_techniques_removed: result.attack_delta?.techniques_removed.length ?? 0,
  }
}
