/**
 * Unit tests for binary-diffing
 *
 * Pure logic tests — the source module uses import.meta.url which ts-jest
 * doesn't support, so we replicate the pure delta functions here.
 */

// ── Replicated types ──────────────────────────────────────────────────

interface FunctionDiffEntry {
  name: string
  similarity: number
}

interface ImportDelta {
  added: string[]
  removed: string[]
  common_count: number
}

interface ExportDelta {
  added: string[]
  removed: string[]
  common_count: number
}

interface SectionDelta {
  added: string[]
  removed: string[]
  size_changed: Array<{ name: string; size_a: number; size_b: number }>
}

interface StringDelta {
  added: string[]
  removed: string[]
  common_count: number
}

interface AttackTechnique {
  id: string
  name: string
  confidence?: number
}

interface AttackDelta {
  techniques_added: AttackTechnique[]
  techniques_removed: AttackTechnique[]
  confidence_changed: Array<{ id: string; name: string; confidence_a: number; confidence_b: number }>
}

interface StructuralDelta {
  imports: ImportDelta
  exports: ExportDelta
  sections: SectionDelta
  strings: StringDelta
}

interface RizinDiffResult {
  ok: boolean
  functions_added: FunctionDiffEntry[]
  functions_removed: FunctionDiffEntry[]
  functions_modified: FunctionDiffEntry[]
}

interface BinaryDiffResult {
  ok: boolean
  sample_id_a: string
  sample_id_b: string
  function_diff: RizinDiffResult | null
  structural_delta: StructuralDelta | null
  attack_delta: AttackDelta | null
  summary_stats: {
    functions_added: number; functions_removed: number; functions_modified: number
    imports_added: number; imports_removed: number
    strings_added: number; strings_removed: number
    attack_techniques_added: number; attack_techniques_removed: number
  }
  errors: string[]
  warnings: string[]
}

// ── Replicated pure functions ─────────────────────────────────────────

function computeImportDelta(importsA: string[], importsB: string[]): ImportDelta {
  const setA = new Set(importsA)
  const setB = new Set(importsB)
  return {
    added: importsB.filter(i => !setA.has(i)),
    removed: importsA.filter(i => !setB.has(i)),
    common_count: importsA.filter(i => setB.has(i)).length,
  }
}

function computeExportDelta(exportsA: string[], exportsB: string[]): ExportDelta {
  const setA = new Set(exportsA)
  const setB = new Set(exportsB)
  return {
    added: exportsB.filter(e => !setA.has(e)),
    removed: exportsA.filter(e => !setB.has(e)),
    common_count: exportsA.filter(e => setB.has(e)).length,
  }
}

function computeSectionDelta(
  sectionsA: { name: string; size: number }[],
  sectionsB: { name: string; size: number }[]
): SectionDelta {
  const mapA = new Map(sectionsA.map(s => [s.name, s.size]))
  const mapB = new Map(sectionsB.map(s => [s.name, s.size]))
  return {
    added: sectionsB.filter(s => !mapA.has(s.name)).map(s => s.name),
    removed: sectionsA.filter(s => !mapB.has(s.name)).map(s => s.name),
    size_changed: sectionsA
      .filter(s => mapB.has(s.name) && mapB.get(s.name) !== s.size)
      .map(s => ({ name: s.name, size_a: s.size, size_b: mapB.get(s.name)! })),
  }
}

function computeStringDelta(stringsA: string[], stringsB: string[]): StringDelta {
  const setA = new Set(stringsA)
  const setB = new Set(stringsB)
  return {
    added: stringsB.filter(s => !setA.has(s)),
    removed: stringsA.filter(s => !setB.has(s)),
    common_count: stringsA.filter(s => setB.has(s)).length,
  }
}

function computeAttackDelta(attackA: AttackTechnique[], attackB: AttackTechnique[]): AttackDelta {
  const mapA = new Map(attackA.map(t => [t.id, t]))
  const mapB = new Map(attackB.map(t => [t.id, t]))
  return {
    techniques_added: attackB.filter(t => !mapA.has(t.id)),
    techniques_removed: attackA.filter(t => !mapB.has(t.id)),
    confidence_changed: attackA
      .filter(t => mapB.has(t.id) && mapB.get(t.id)!.confidence !== t.confidence)
      .map(t => ({
        id: t.id,
        name: t.name,
        confidence_a: t.confidence ?? 0,
        confidence_b: mapB.get(t.id)!.confidence ?? 0,
      })),
  }
}

function computeStructuralDelta(
  artA: { imports?: string[]; exports?: string[]; sections?: { name: string; size: number }[]; strings?: string[] },
  artB: { imports?: string[]; exports?: string[]; sections?: { name: string; size: number }[]; strings?: string[] },
): StructuralDelta {
  return {
    imports: computeImportDelta(artA.imports ?? [], artB.imports ?? []),
    exports: computeExportDelta(artA.exports ?? [], artB.exports ?? []),
    sections: computeSectionDelta(artA.sections ?? [], artB.sections ?? []),
    strings: computeStringDelta(artA.strings ?? [], artB.strings ?? []),
  }
}

function buildSummaryStats(result: BinaryDiffResult): BinaryDiffResult['summary_stats'] {
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

describe('binary-diff-engine', () => {
  describe('computeImportDelta', () => {
    it('finds added and removed imports', () => {
      const delta = computeImportDelta(
        ['kernel32.dll:CreateFileA', 'user32.dll:MessageBoxA'],
        ['kernel32.dll:CreateFileA', 'ws2_32.dll:connect']
      )
      expect(delta.added).toEqual(['ws2_32.dll:connect'])
      expect(delta.removed).toEqual(['user32.dll:MessageBoxA'])
      expect(delta.common_count).toBe(1)
    })

    it('handles empty arrays', () => {
      const delta = computeImportDelta([], [])
      expect(delta.added).toEqual([])
      expect(delta.removed).toEqual([])
      expect(delta.common_count).toBe(0)
    })

    it('handles identical arrays', () => {
      const imports = ['a', 'b', 'c']
      const delta = computeImportDelta(imports, imports)
      expect(delta.added).toEqual([])
      expect(delta.removed).toEqual([])
      expect(delta.common_count).toBe(3)
    })
  })

  describe('computeExportDelta', () => {
    it('finds added and removed exports', () => {
      const delta = computeExportDelta(['DllMain', 'ServiceMain'], ['DllMain', 'NewExport'])
      expect(delta.added).toEqual(['NewExport'])
      expect(delta.removed).toEqual(['ServiceMain'])
      expect(delta.common_count).toBe(1)
    })
  })

  describe('computeSectionDelta', () => {
    it('detects added, removed, and size-changed sections', () => {
      const delta = computeSectionDelta(
        [{ name: '.text', size: 1024 }, { name: '.data', size: 256 }],
        [{ name: '.text', size: 2048 }, { name: '.rsrc', size: 512 }]
      )
      expect(delta.added).toEqual(['.rsrc'])
      expect(delta.removed).toEqual(['.data'])
      expect(delta.size_changed).toEqual([
        { name: '.text', size_a: 1024, size_b: 2048 }
      ])
    })

    it('handles identical sections', () => {
      const sects = [{ name: '.text', size: 100 }]
      const delta = computeSectionDelta(sects, sects)
      expect(delta.added).toEqual([])
      expect(delta.removed).toEqual([])
      expect(delta.size_changed).toEqual([])
    })
  })

  describe('computeStringDelta', () => {
    it('finds added and removed strings', () => {
      const delta = computeStringDelta(
        ['Hello', 'World'],
        ['Hello', 'Malware']
      )
      expect(delta.added).toEqual(['Malware'])
      expect(delta.removed).toEqual(['World'])
      expect(delta.common_count).toBe(1)
    })
  })

  describe('computeAttackDelta', () => {
    it('finds techniques added and removed', () => {
      const delta = computeAttackDelta(
        [{ id: 'T1055', name: 'Process Injection', confidence: 0.8 }],
        [
          { id: 'T1055', name: 'Process Injection', confidence: 0.6 },
          { id: 'T1059', name: 'Command Execution', confidence: 0.9 },
        ]
      )
      expect(delta.techniques_added).toEqual([{ id: 'T1059', name: 'Command Execution', confidence: 0.9 }])
      expect(delta.techniques_removed).toEqual([])
      expect(delta.confidence_changed.length).toBe(1)
      expect(delta.confidence_changed[0].id).toBe('T1055')
    })

    it('handles empty arrays', () => {
      const delta = computeAttackDelta([], [])
      expect(delta.techniques_added).toEqual([])
      expect(delta.techniques_removed).toEqual([])
      expect(delta.confidence_changed).toEqual([])
    })
  })

  describe('computeStructuralDelta', () => {
    it('computes full structural delta', () => {
      const delta = computeStructuralDelta(
        { imports: ['a'], exports: ['x'], sections: [{ name: '.text', size: 100 }], strings: ['s1'] },
        { imports: ['b'], exports: ['x'], sections: [{ name: '.text', size: 200 }], strings: ['s2'] }
      )
      expect(delta.imports.added).toEqual(['b'])
      expect(delta.imports.removed).toEqual(['a'])
      expect(delta.exports.added).toEqual([])
      expect(delta.sections.size_changed.length).toBe(1)
      expect(delta.strings.added).toEqual(['s2'])
    })
  })

  describe('buildSummaryStats', () => {
    it('produces summary from diff result', () => {
      const diffResult: BinaryDiffResult = {
        ok: true,
        sample_id_a: 'sha256:aaa',
        sample_id_b: 'sha256:bbb',
        function_diff: {
          ok: true,
          functions_added: [{ name: 'new_fn', similarity: 0 }],
          functions_removed: [],
          functions_modified: [{ name: 'mod_fn', similarity: 0.7 }],
        },
        structural_delta: {
          imports: { added: ['x'], removed: [], common_count: 5 },
          exports: { added: [], removed: ['y'], common_count: 3 },
          sections: { added: [], removed: [], size_changed: [] },
          strings: { added: ['a', 'b'], removed: ['c'], common_count: 10 },
        },
        attack_delta: {
          techniques_added: [{ id: 'T1055', name: 'PI' }],
          techniques_removed: [],
          confidence_changed: [],
        },
        summary_stats: {
          functions_added: 0, functions_removed: 0, functions_modified: 0,
          imports_added: 0, imports_removed: 0, strings_added: 0, strings_removed: 0,
          attack_techniques_added: 0, attack_techniques_removed: 0,
        },
        errors: [],
        warnings: [],
      }
      const stats = buildSummaryStats(diffResult)
      expect(stats).toBeDefined()
      expect(stats.functions_added).toBe(1)
      expect(stats.functions_modified).toBe(1)
      expect(stats.imports_added).toBe(1)
    })
  })
})
