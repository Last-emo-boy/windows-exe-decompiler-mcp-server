/**
 * Semantic Differentiator — compares two opcode tables to detect
 * semantic mismatches (traps) between nested VMs.
 *
 * Classification per opcode:
 *  - IDENTICAL: same mnemonic, same operand structure, same behavior
 *  - RENAMED:   different mnemonic, same semantic category
 *  - TRAP:      same mnemonic, different behavior (DANGEROUS)
 *  - UNIQUE:    only in one table
 */

import type { OpcodeEntry, OpcodeTable } from './opcode-extractor.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type DiffClass = 'IDENTICAL' | 'RENAMED' | 'TRAP' | 'UNIQUE_A' | 'UNIQUE_B'

export interface OpcodeDiffEntry {
  opcodeValue: number
  classification: DiffClass
  mnemonicA?: string
  mnemonicB?: string
  categoryA?: string
  categoryB?: string
  details: string[]
  isTrap: boolean
}

export interface SemanticDiffReport {
  entries: OpcodeDiffEntry[]
  totalOpcodes: number
  identicalCount: number
  renamedCount: number
  trapCount: number
  uniqueACount: number
  uniqueBCount: number
  traps: OpcodeDiffEntry[]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Detect bit-width differences in rotate operations from handler code.
 * Returns the detected bit-width or null if not found.
 */
function detectBitWidth(handlerCode: string): number | null {
  // Look for mask patterns: & 0xFFFF → 16-bit, & 0xFFFFFFFF → 32-bit, & 0xFF → 8-bit
  const maskPatterns: Array<{ mask: RegExp; width: number }> = [
    { mask: /&\s*0xFFFFFFFFFFFFFFFF/i, width: 64 },
    { mask: /&\s*0xFFFFFFFF(?![0-9A-Fa-f])/i, width: 32 },
    { mask: /&\s*0xFFFF(?![0-9A-Fa-f])/i, width: 16 },
    { mask: /&\s*0xFF(?![0-9A-Fa-f])/i, width: 8 },
  ]

  for (const { mask, width } of maskPatterns) {
    if (mask.test(handlerCode)) return width
  }

  // Look for explicit bit-width in variable types
  if (/\buint64\b|\bQWORD\b/i.test(handlerCode)) return 64
  if (/\buint32\b|\bDWORD\b/i.test(handlerCode)) return 32
  if (/\buint16\b|\bWORD\b(?!.*DWORD)/i.test(handlerCode)) return 16
  if (/\buint8\b|\bBYTE\b/i.test(handlerCode)) return 8

  return null
}

/**
 * Detect operand order in handler code (e.g., reg[op1] OP reg[op2] vs reg[op2] OP reg[op1]).
 */
function detectOperandOrder(handlerCode: string): string | null {
  // Look for patterns like reg[X] op reg[Y] and extract order
  const orderRe = /\breg\w*\[\s*(\w+)\s*\]\s*[+\-*/^&|]\s*\breg\w*\[\s*(\w+)\s*\]/
  const m = orderRe.exec(handlerCode)
  if (m) return `${m[1]},${m[2]}`
  return null
}

// ---------------------------------------------------------------------------
// Diff Engine
// ---------------------------------------------------------------------------

/**
 * Compare two opcode tables and produce a semantic diff report.
 */
export function diffOpcodeTables(tableA: OpcodeTable, tableB: OpcodeTable): SemanticDiffReport {
  const mapA = new Map<number, OpcodeEntry>()
  const mapB = new Map<number, OpcodeEntry>()
  for (const e of tableA) mapA.set(e.value, e)
  for (const e of tableB) mapB.set(e.value, e)

  const allOpcodes = new Set<number>([...mapA.keys(), ...mapB.keys()])
  const entries: OpcodeDiffEntry[] = []

  for (const oc of [...allOpcodes].sort((a, b) => a - b)) {
    const a = mapA.get(oc)
    const b = mapB.get(oc)

    if (a && !b) {
      entries.push({
        opcodeValue: oc,
        classification: 'UNIQUE_A',
        mnemonicA: a.mnemonic,
        categoryA: a.semanticCategory,
        details: [`Only in table A: ${a.mnemonic}`],
        isTrap: false,
      })
      continue
    }

    if (!a && b) {
      entries.push({
        opcodeValue: oc,
        classification: 'UNIQUE_B',
        mnemonicB: b.mnemonic,
        categoryB: b.semanticCategory,
        details: [`Only in table B: ${b.mnemonic}`],
        isTrap: false,
      })
      continue
    }

    if (!a || !b) continue

    const details: string[] = []
    let isTrap = false
    let classification: DiffClass = 'IDENTICAL'

    // Check mnemonic match
    const sameMnemonic = a.mnemonic === b.mnemonic
    const sameCategory = a.semanticCategory === b.semanticCategory

    if (!sameMnemonic && sameCategory) {
      classification = 'RENAMED'
      details.push(`Mnemonic: ${a.mnemonic} → ${b.mnemonic} (same category: ${a.semanticCategory})`)
    } else if (!sameMnemonic && !sameCategory) {
      classification = 'TRAP'
      isTrap = true
      details.push(`Mnemonic: ${a.mnemonic} → ${b.mnemonic}, Category: ${a.semanticCategory} → ${b.semanticCategory}`)
    }

    // Check operand structure
    if (a.operandCount !== b.operandCount) {
      if (sameMnemonic) {
        classification = 'TRAP'
        isTrap = true
      }
      details.push(`Operand count: ${a.operandCount} → ${b.operandCount}`)
    }

    // Deep semantic comparison for same-mnemonic ops
    if (sameMnemonic && (a.semanticCategory === 'rotate' || b.semanticCategory === 'rotate')) {
      const bwA = detectBitWidth(a.handlerCode)
      const bwB = detectBitWidth(b.handlerCode)
      if (bwA !== null && bwB !== null && bwA !== bwB) {
        classification = 'TRAP'
        isTrap = true
        details.push(`⚠ BIT-WIDTH TRAP: ${a.mnemonic} ${bwA}-bit vs ${bwB}-bit`)
      }
    }

    // Check operand order swap
    if (sameMnemonic && a.semanticCategory === b.semanticCategory) {
      const orderA = detectOperandOrder(a.handlerCode)
      const orderB = detectOperandOrder(b.handlerCode)
      if (orderA && orderB && orderA !== orderB) {
        classification = 'TRAP'
        isTrap = true
        details.push(`⚠ OPERAND ORDER TRAP: ${orderA} vs ${orderB}`)
      }
    }

    if (details.length === 0) {
      details.push('Identical semantics')
    }

    entries.push({
      opcodeValue: oc,
      classification,
      mnemonicA: a.mnemonic,
      mnemonicB: b.mnemonic,
      categoryA: a.semanticCategory,
      categoryB: b.semanticCategory,
      details,
      isTrap,
    })
  }

  const traps = entries.filter(e => e.isTrap)

  return {
    entries,
    totalOpcodes: allOpcodes.size,
    identicalCount: entries.filter(e => e.classification === 'IDENTICAL').length,
    renamedCount: entries.filter(e => e.classification === 'RENAMED').length,
    trapCount: traps.length,
    uniqueACount: entries.filter(e => e.classification === 'UNIQUE_A').length,
    uniqueBCount: entries.filter(e => e.classification === 'UNIQUE_B').length,
    traps,
  }
}
