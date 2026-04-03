/**
 * Unit tests for VM Opcode Extraction and Disassembler Builder
 */

// ── Replicated types and logic from opcode-extractor.ts ─────────────

type SemanticCategory =
  | 'arithmetic' | 'logic' | 'rotate' | 'memory'
  | 'control' | 'stack' | 'compare' | 'special' | 'unknown'

interface CaseEntry {
  caseValue: number
  body: string
}

interface HandlerSemantic {
  category: SemanticCategory
  operation: string
  confidence: number
}

const HANDLER_PATTERNS: Array<{ pattern: RegExp; category: SemanticCategory; operation: string; confidence: number }> = [
  { pattern: /\+\s*=|\badd\b/i, category: 'arithmetic', operation: 'ADD', confidence: 0.8 },
  { pattern: /-\s*=|\bsub\b/i, category: 'arithmetic', operation: 'SUB', confidence: 0.8 },
  { pattern: /\*\s*=|\bmul\b/i, category: 'arithmetic', operation: 'MUL', confidence: 0.7 },
  { pattern: /\/\s*=|\bdiv\b/i, category: 'arithmetic', operation: 'DIV', confidence: 0.7 },
  { pattern: /%\s*=|\bmod\b/i, category: 'arithmetic', operation: 'MOD', confidence: 0.7 },
  { pattern: /\^\s*=|\bxor\b/i, category: 'logic', operation: 'XOR', confidence: 0.8 },
  { pattern: /&\s*=|\band\b/i, category: 'logic', operation: 'AND', confidence: 0.7 },
  { pattern: /\|\s*=|\bor\b/i, category: 'logic', operation: 'OR', confidence: 0.7 },
  { pattern: /~\s*\w|\bnot\b/i, category: 'logic', operation: 'NOT', confidence: 0.7 },
  { pattern: /<<\s*=|\bshl\b|\bshift.*left/i, category: 'rotate', operation: 'SHL', confidence: 0.8 },
  { pattern: />>\s*=|\bshr\b|\bshift.*right/i, category: 'rotate', operation: 'SHR', confidence: 0.8 },
  { pattern: /\brol\b|\brotate.*left/i, category: 'rotate', operation: 'ROL', confidence: 0.9 },
  { pattern: /\bror\b|\brotate.*right/i, category: 'rotate', operation: 'ROR', confidence: 0.9 },
  { pattern: /\[\s*\w+\s*\]\s*=|\bstore\b|\bmov.*\[/i, category: 'memory', operation: 'STORE', confidence: 0.7 },
  { pattern: /=\s*\[\s*\w+\s*\]|\bload\b|\bmov.*=.*\[/i, category: 'memory', operation: 'LOAD', confidence: 0.7 },
  { pattern: /\bjmp\b|\bgoto\b|vpc\s*=|ip\s*=/i, category: 'control', operation: 'JMP', confidence: 0.8 },
  { pattern: /\bif\s*\(.*\)\s*(vpc|ip)\s*=|\bjnz\b|\bjz\b|\bjne\b|\bje\b/i, category: 'control', operation: 'JCC', confidence: 0.8 },
  { pattern: /running\s*=\s*0|return|halt|exit/i, category: 'control', operation: 'HALT', confidence: 0.8 },
  { pattern: /push\s*\(|\bpush\b/i, category: 'stack', operation: 'PUSH', confidence: 0.8 },
  { pattern: /pop\s*\(|\bpop\b/i, category: 'stack', operation: 'POP', confidence: 0.8 },
  { pattern: /\bcmp\b|\bcompare\b/i, category: 'compare', operation: 'CMP', confidence: 0.8 },
  { pattern: /\btest\b/i, category: 'compare', operation: 'TEST', confidence: 0.7 },
  { pattern: /\bnop\b/i, category: 'special', operation: 'NOP', confidence: 0.9 },
]

function classifyHandler(body: string): HandlerSemantic {
  for (const { pattern, category, operation, confidence } of HANDLER_PATTERNS) {
    if (pattern.test(body)) {
      return { category, operation, confidence }
    }
  }
  return { category: 'unknown', operation: 'UNKNOWN', confidence: 0 }
}

function extractSwitchCases(code: string): CaseEntry[] {
  const entries: CaseEntry[] = []
  const caseRegex = /case\s+(0x[0-9a-fA-F]+|\d+)\s*:([\s\S]*?)(?=case\s+|default\s*:|$)/g
  let match
  while ((match = caseRegex.exec(code)) !== null) {
    const val = match[1].startsWith('0x')
      ? parseInt(match[1], 16)
      : parseInt(match[1], 10)
    entries.push({ caseValue: val, body: match[2].trim() })
  }
  return entries
}

interface InstructionFormat {
  opcodeBytes: number
  operandPattern: string
  totalMinSize: number
}

function detectInstructionFormat(
  cases: CaseEntry[]
): InstructionFormat {
  let hasOperandFetch = false
  let maxOperands = 0

  for (const c of cases) {
    const fetches = (c.body.match(/bytecode\[|code\[|fetch/gi) || []).length
    if (fetches > 0) hasOperandFetch = true
    maxOperands = Math.max(maxOperands, fetches)
  }

  const opcodeBytes = 1
  const operandPattern = hasOperandFetch
    ? maxOperands > 1 ? 'reg,reg,imm' : 'reg,imm'
    : 'none'
  const totalMinSize = opcodeBytes + (hasOperandFetch ? maxOperands : 0)

  return { opcodeBytes, operandPattern, totalMinSize }
}

// ── Replicated disassembler logic ──────────────────────────────────

interface OpcodeEntry {
  opcode: number
  mnemonic: string
  semantic: HandlerSemantic
  handlerBody: string
}

interface OpcodeTable {
  entries: OpcodeEntry[]
  dispatcherName: string
  instructionFormat: InstructionFormat
}

interface Instruction {
  offset: number
  opcode: number
  mnemonic: string
  operands: number[]
  size: number
}

function buildDisassembler(table: OpcodeTable) {
  const map = new Map<number, OpcodeEntry>()
  for (const e of table.entries) map.set(e.opcode, e)
  return {
    opcodeMap: map,
    instrFormat: table.instructionFormat,
  }
}

function disassemble(disasm: ReturnType<typeof buildDisassembler>, bytecode: Buffer) {
  const instructions: Instruction[] = []
  let offset = 0

  while (offset < bytecode.length) {
    const opByte = bytecode[offset]
    const entry = disasm.opcodeMap.get(opByte)

    if (!entry) {
      instructions.push({
        offset,
        opcode: opByte,
        mnemonic: '.byte',
        operands: [opByte],
        size: 1,
      })
      offset++
      continue
    }

    const operands: number[] = []
    let size = 1
    const operandCount = disasm.instrFormat.totalMinSize - disasm.instrFormat.opcodeBytes
    for (let i = 0; i < operandCount && offset + 1 + i < bytecode.length; i++) {
      operands.push(bytecode[offset + 1 + i])
      size++
    }

    instructions.push({
      offset,
      opcode: opByte,
      mnemonic: entry.mnemonic,
      operands,
      size,
    })

    if (entry.semantic.operation === 'HALT') break
    offset += size
  }

  const knownBytes = instructions
    .filter(i => i.mnemonic !== '.byte')
    .reduce((s, i) => s + i.size, 0)

  return {
    instructions,
    coverage: {
      totalBytes: bytecode.length,
      decodedBytes: knownBytes,
      unknownBytes: bytecode.length - knownBytes,
    },
  }
}

// ── Tests ──────────────────────────────────────────────────────────────

describe('VM Opcode Extraction', () => {
  describe('extractSwitchCases', () => {
    it('should extract hex case values', () => {
      const code = `
        switch(op) {
          case 0x01: regs[0] += regs[1]; break;
          case 0x02: regs[0] -= regs[1]; break;
          case 0xFF: running = 0; break;
        }
      `
      const cases = extractSwitchCases(code)
      expect(cases.length).toBe(3)
      expect(cases[0].caseValue).toBe(0x01)
      expect(cases[1].caseValue).toBe(0x02)
      expect(cases[2].caseValue).toBe(0xFF)
    })

    it('should extract decimal case values', () => {
      const code = `switch(x) { case 1: foo(); break; case 2: bar(); break; }`
      const cases = extractSwitchCases(code)
      expect(cases.length).toBe(2)
      expect(cases[0].caseValue).toBe(1)
    })
  })

  describe('classifyHandler', () => {
    it('should classify addition', () => {
      expect(classifyHandler('regs[0] += regs[1];').category).toBe('arithmetic')
      expect(classifyHandler('regs[0] += regs[1];').operation).toBe('ADD')
    })

    it('should classify XOR', () => {
      expect(classifyHandler('regs[0] ^= regs[1];').category).toBe('logic')
      expect(classifyHandler('regs[0] ^= regs[1];').operation).toBe('XOR')
    })

    it('should classify jump', () => {
      expect(classifyHandler('vpc = target;').category).toBe('control')
      expect(classifyHandler('vpc = target;').operation).toBe('JMP')
    })

    it('should classify push/pop', () => {
      expect(classifyHandler('push(regs[0]);').category).toBe('stack')
      expect(classifyHandler('push(regs[0]);').operation).toBe('PUSH')
      expect(classifyHandler('val = pop();').operation).toBe('POP')
    })

    it('should classify halt', () => {
      expect(classifyHandler('running = 0;').operation).toBe('HALT')
    })

    it('should return unknown for unrecognized', () => {
      const r = classifyHandler('/* empty handler */')
      expect(r.category).toBe('unknown')
    })
  })

  describe('detectInstructionFormat', () => {
    it('should detect operand fetch', () => {
      const cases: CaseEntry[] = [
        { caseValue: 1, body: 'r = bytecode[pc+1]; r2 = bytecode[pc+2];' },
        { caseValue: 2, body: 'x = bytecode[pc+1];' },
      ]
      const fmt = detectInstructionFormat(cases)
      expect(fmt.opcodeBytes).toBe(1)
      expect(fmt.totalMinSize).toBeGreaterThan(1)
    })

    it('should detect no operands', () => {
      const cases: CaseEntry[] = [
        { caseValue: 1, body: 'x += y;' },
      ]
      const fmt = detectInstructionFormat(cases)
      expect(fmt.operandPattern).toBe('none')
    })
  })
})

describe('Disassembler Builder', () => {
  const table: OpcodeTable = {
    dispatcherName: 'vm_exec',
    instructionFormat: { opcodeBytes: 1, operandPattern: 'reg,imm', totalMinSize: 3 },
    entries: [
      { opcode: 0x01, mnemonic: 'ADD', semantic: { category: 'arithmetic', operation: 'ADD', confidence: 0.8 }, handlerBody: '' },
      { opcode: 0x02, mnemonic: 'SUB', semantic: { category: 'arithmetic', operation: 'SUB', confidence: 0.8 }, handlerBody: '' },
      { opcode: 0xFF, mnemonic: 'HALT', semantic: { category: 'control', operation: 'HALT', confidence: 0.8 }, handlerBody: '' },
    ],
  }

  it('should disassemble known opcodes', () => {
    const disasm = buildDisassembler(table)
    // 0x01 r0 0x05 0x02 r1 0x03 0xFF
    const bytecode = Buffer.from([0x01, 0x00, 0x05, 0x02, 0x01, 0x03, 0xFF])
    const result = disassemble(disasm, bytecode)

    expect(result.instructions.length).toBeGreaterThanOrEqual(3)
    expect(result.instructions[0].mnemonic).toBe('ADD')
    expect(result.instructions[0].operands).toEqual([0x00, 0x05])
    expect(result.instructions[1].mnemonic).toBe('SUB')
  })

  it('should handle unknown opcodes as .byte', () => {
    const disasm = buildDisassembler(table)
    const bytecode = Buffer.from([0xAA, 0xFF])
    const result = disassemble(disasm, bytecode)

    expect(result.instructions[0].mnemonic).toBe('.byte')
    expect(result.instructions[0].opcode).toBe(0xAA)
  })

  it('should stop at HALT', () => {
    const disasm = buildDisassembler(table)
    const bytecode = Buffer.from([0xFF, 0x01, 0x00, 0x00])
    const result = disassemble(disasm, bytecode)

    // Should stop after HALT, not continue
    expect(result.instructions.length).toBe(1)
    expect(result.instructions[0].mnemonic).toBe('HALT')
  })

  it('should report coverage stats', () => {
    const disasm = buildDisassembler(table)
    const bytecode = Buffer.from([0x01, 0x00, 0x05, 0xFF])
    const result = disassemble(disasm, bytecode)

    expect(result.coverage.totalBytes).toBe(4)
    expect(result.coverage.decodedBytes).toBeGreaterThan(0)
  })
})
