/**
 * Disassembler Builder — dynamically constructs a disassembler from an opcode table
 * and disassembles raw VM bytecodes into readable instruction listings.
 */

import type { OpcodeTable, OpcodeEntry } from './opcode-extractor.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Disassembler {
  lookup: Map<number, OpcodeEntry>
  defaultInstrLen: number
}

export interface Instruction {
  address: number
  opcode: number
  mnemonic: string
  operands: number[]
  raw: number[]
  length: number
}

export interface DisassemblyResult {
  instructions: Instruction[]
  totalBytes: number
  coverage: number
  unknownOpcodes: number[]
}

// ---------------------------------------------------------------------------
// Build Disassembler
// ---------------------------------------------------------------------------

/**
 * Build a disassembler from an opcode table.
 */
export function buildDisassembler(table: OpcodeTable): Disassembler {
  const lookup = new Map<number, OpcodeEntry>()
  for (const entry of table) {
    lookup.set(entry.value, entry)
  }
  return { lookup, defaultInstrLen: 1 }
}

// ---------------------------------------------------------------------------
// Disassemble
// ---------------------------------------------------------------------------

/**
 * Disassemble raw bytecodes using the given disassembler.
 */
export function disassemble(
  bytecodes: Buffer | Uint8Array,
  disasm: Disassembler,
  baseAddress = 0
): DisassemblyResult {
  const instructions: Instruction[] = []
  const unknownOpcodes: number[] = []
  let pc = 0

  while (pc < bytecodes.length) {
    const opcode = bytecodes[pc]
    const entry = disasm.lookup.get(opcode)

    if (!entry) {
      // Unknown opcode — emit .byte directive
      instructions.push({
        address: baseAddress + pc,
        opcode,
        mnemonic: '.byte',
        operands: [opcode],
        raw: [opcode],
        length: 1,
      })
      if (!unknownOpcodes.includes(opcode)) unknownOpcodes.push(opcode)
      pc += 1
      continue
    }

    const instrLen = 1 + entry.operandSizes.reduce((a, b) => a + b, 0)
    const operands: number[] = []
    const raw: number[] = [opcode]

    let offset = 1
    for (const size of entry.operandSizes) {
      if (pc + offset + size > bytecodes.length) break
      let val = 0
      for (let i = 0; i < size; i++) {
        val |= bytecodes[pc + offset + i] << (i * 8)
        raw.push(bytecodes[pc + offset + i])
      }
      operands.push(val)
      offset += size
    }

    instructions.push({
      address: baseAddress + pc,
      opcode,
      mnemonic: entry.mnemonic,
      operands,
      raw,
      length: Math.min(instrLen, bytecodes.length - pc),
    })

    // Check for HALT — stop disassembling
    if (entry.mnemonic === 'HALT') {
      pc += instrLen
      break
    }

    pc += instrLen
  }

  const totalBytes = bytecodes.length
  const coveredBytes = instructions.reduce((s, i) => s + i.length, 0)

  return {
    instructions,
    totalBytes,
    coverage: totalBytes > 0 ? coveredBytes / totalBytes : 0,
    unknownOpcodes,
  }
}

/**
 * Format disassembly result as human-readable text listing.
 */
export function formatDisassembly(result: DisassemblyResult): string {
  const lines: string[] = []
  for (const instr of result.instructions) {
    const addr = `0x${instr.address.toString(16).padStart(4, '0')}`
    const rawHex = instr.raw.map(b => b.toString(16).padStart(2, '0')).join(' ')
    const ops = instr.operands.length > 0
      ? '  ' + instr.operands.map(o => `0x${o.toString(16)}`).join(', ')
      : ''
    lines.push(`${addr}:  ${rawHex.padEnd(16)}  ${instr.mnemonic}${ops}`)
  }
  lines.push('')
  lines.push(`; Total: ${result.instructions.length} instructions, ${result.totalBytes} bytes`)
  lines.push(`; Coverage: ${(result.coverage * 100).toFixed(1)}%`)
  if (result.unknownOpcodes.length > 0) {
    lines.push(`; Unknown opcodes: ${result.unknownOpcodes.map(o => `0x${o.toString(16)}`).join(', ')}`)
  }
  return lines.join('\n')
}
