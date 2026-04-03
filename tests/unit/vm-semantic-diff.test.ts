/**
 * Unit tests for Semantic Diff engine — cross-VM opcode table comparison.
 */

// ── Replicated types & logic from semantic-diff.ts ──────────────────

type DiffClass = 'IDENTICAL' | 'RENAMED' | 'TRAP' | 'UNIQUE_A' | 'UNIQUE_B'

interface HandlerSemantic {
  category: string
  operation: string
  confidence: number
}

interface OpcodeEntry {
  opcode: number
  mnemonic: string
  semantic: HandlerSemantic
  handlerBody: string
}

interface OpcodeTable {
  entries: OpcodeEntry[]
  dispatcherName: string
  instructionFormat: { opcodeBytes: number; operandPattern: string; totalMinSize: number }
}

interface OpcodeDiffEntry {
  opcodeA?: number
  opcodeB?: number
  mnemonicA?: string
  mnemonicB?: string
  diffClass: DiffClass
  trapDetail?: string
}

interface SemanticDiffReport {
  entries: OpcodeDiffEntry[]
  summary: {
    identical: number
    renamed: number
    traps: number
    uniqueA: number
    uniqueB: number
  }
}

function detectBitWidth(body: string): number | null {
  if (/0xFFFFFFFFFFFFFFFF/i.test(body)) return 64
  if (/0xFFFFFFFF/i.test(body)) return 32
  if (/0xFFFF\b/i.test(body)) return 16
  if (/0xFF\b/i.test(body)) return 8
  if (/uint64|QWORD/i.test(body)) return 64
  if (/uint32|DWORD/i.test(body)) return 32
  if (/uint16|WORD/i.test(body)) return 16
  if (/uint8|BYTE/i.test(body)) return 8
  return null
}

function diffOpcodeTables(tableA: OpcodeTable, tableB: OpcodeTable): SemanticDiffReport {
  const entries: OpcodeDiffEntry[] = []
  const summary = { identical: 0, renamed: 0, traps: 0, uniqueA: 0, uniqueB: 0 }

  const mapA = new Map<string, OpcodeEntry>()
  const mapB = new Map<string, OpcodeEntry>()
  for (const e of tableA.entries) mapA.set(e.semantic.category + ':' + e.semantic.operation, e)
  for (const e of tableB.entries) mapB.set(e.semantic.category + ':' + e.semantic.operation, e)

  const seenB = new Set<string>()

  for (const [key, entryA] of mapA) {
    const entryB = mapB.get(key)
    if (!entryB) {
      entries.push({
        opcodeA: entryA.opcode,
        mnemonicA: entryA.mnemonic,
        diffClass: 'UNIQUE_A',
      })
      summary.uniqueA++
      continue
    }
    seenB.add(key)

    if (entryA.opcode === entryB.opcode && entryA.mnemonic === entryB.mnemonic) {
      // Check for trap: same semantic but different bit width
      const bwA = detectBitWidth(entryA.handlerBody)
      const bwB = detectBitWidth(entryB.handlerBody)
      if (bwA !== null && bwB !== null && bwA !== bwB) {
        entries.push({
          opcodeA: entryA.opcode,
          opcodeB: entryB.opcode,
          mnemonicA: entryA.mnemonic,
          mnemonicB: entryB.mnemonic,
          diffClass: 'TRAP',
          trapDetail: `Bit-width mismatch: ${bwA} vs ${bwB}`,
        })
        summary.traps++
      } else {
        entries.push({
          opcodeA: entryA.opcode,
          opcodeB: entryB.opcode,
          mnemonicA: entryA.mnemonic,
          mnemonicB: entryB.mnemonic,
          diffClass: 'IDENTICAL',
        })
        summary.identical++
      }
    } else {
      // Same semantic, different opcode or mnemonic => RENAMED
      entries.push({
        opcodeA: entryA.opcode,
        opcodeB: entryB.opcode,
        mnemonicA: entryA.mnemonic,
        mnemonicB: entryB.mnemonic,
        diffClass: 'RENAMED',
      })
      summary.renamed++
    }
  }

  for (const [key, entryB] of mapB) {
    if (!seenB.has(key)) {
      entries.push({
        opcodeB: entryB.opcode,
        mnemonicB: entryB.mnemonic,
        diffClass: 'UNIQUE_B',
      })
      summary.uniqueB++
    }
  }

  return { entries, summary }
}

// ── Tests ──────────────────────────────────────────────────────────────

describe('Semantic Diff', () => {
  const mkEntry = (
    opcode: number, mnemonic: string, category: string, operation: string, body = ''
  ): OpcodeEntry => ({
    opcode, mnemonic,
    semantic: { category, operation, confidence: 0.8 },
    handlerBody: body,
  })

  const mkTable = (entries: OpcodeEntry[]): OpcodeTable => ({
    entries,
    dispatcherName: 'test',
    instructionFormat: { opcodeBytes: 1, operandPattern: 'reg,imm', totalMinSize: 3 },
  })

  describe('identical opcodes', () => {
    it('should detect identical entries', () => {
      const table = mkTable([
        mkEntry(0x01, 'ADD', 'arithmetic', 'ADD'),
        mkEntry(0x02, 'XOR', 'logic', 'XOR'),
      ])
      const report = diffOpcodeTables(table, table)
      expect(report.summary.identical).toBe(2)
      expect(report.summary.renamed).toBe(0)
      expect(report.summary.traps).toBe(0)
    })
  })

  describe('renamed opcodes', () => {
    it('should detect opcode renaming', () => {
      const tableA = mkTable([mkEntry(0x01, 'ADD', 'arithmetic', 'ADD')])
      const tableB = mkTable([mkEntry(0x05, 'PLUS', 'arithmetic', 'ADD')])
      const report = diffOpcodeTables(tableA, tableB)
      expect(report.summary.renamed).toBe(1)
    })
  })

  describe('trap detection', () => {
    it('should detect bit-width mismatch as trap', () => {
      const tableA = mkTable([
        mkEntry(0x10, 'ROL', 'rotate', 'ROL', 'val = (val << n) | (val >> (32 - n)); val &= 0xFFFFFFFF;'),
      ])
      const tableB = mkTable([
        mkEntry(0x10, 'ROL', 'rotate', 'ROL', 'val = (val << n) | (val >> (16 - n)); val &= 0xFFFF;'),
      ])
      const report = diffOpcodeTables(tableA, tableB)
      expect(report.summary.traps).toBe(1)
      expect(report.entries[0].trapDetail).toContain('Bit-width mismatch')
    })
  })

  describe('unique opcodes', () => {
    it('should detect opcodes unique to table A', () => {
      const tableA = mkTable([
        mkEntry(0x01, 'ADD', 'arithmetic', 'ADD'),
        mkEntry(0x02, 'MUL', 'arithmetic', 'MUL'),
      ])
      const tableB = mkTable([
        mkEntry(0x01, 'ADD', 'arithmetic', 'ADD'),
      ])
      const report = diffOpcodeTables(tableA, tableB)
      expect(report.summary.uniqueA).toBe(1)
    })

    it('should detect opcodes unique to table B', () => {
      const tableA = mkTable([mkEntry(0x01, 'ADD', 'arithmetic', 'ADD')])
      const tableB = mkTable([
        mkEntry(0x01, 'ADD', 'arithmetic', 'ADD'),
        mkEntry(0x03, 'NOP', 'special', 'NOP'),
      ])
      const report = diffOpcodeTables(tableA, tableB)
      expect(report.summary.uniqueB).toBe(1)
    })
  })

  describe('detectBitWidth', () => {
    it('should detect 32-bit from mask', () => {
      expect(detectBitWidth('x &= 0xFFFFFFFF;')).toBe(32)
    })

    it('should detect 16-bit from mask', () => {
      expect(detectBitWidth('x &= 0xFFFF;')).toBe(16)
    })

    it('should detect 8-bit from type', () => {
      expect(detectBitWidth('uint8 val = x;')).toBe(8)
    })

    it('should detect 64-bit from type', () => {
      expect(detectBitWidth('QWORD val = x;')).toBe(64)
    })

    it('should return null for unknown', () => {
      expect(detectBitWidth('int x = 5;')).toBeNull()
    })
  })
})
