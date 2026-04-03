/**
 * Opcode Extractor — parses switch-case structures from decompiled C-like code
 * and classifies handler semantics to build an opcode table.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CaseEntry {
  caseValue: number
  handlerCode: string
}

export type SemanticCategory =
  | 'arithmetic'
  | 'logic'
  | 'rotate'
  | 'memory'
  | 'control'
  | 'stack'
  | 'compare'
  | 'special'

export interface HandlerSemantic {
  mnemonic: string
  category: SemanticCategory
  confidence: number
  operandHint: string
}

export interface InstructionFormat {
  fixedLength: boolean
  baseLength: number
  operandSizes: Map<number, number[]>
}

export interface OpcodeEntry {
  value: number
  mnemonic: string
  operandCount: number
  operandSizes: number[]
  handlerCode: string
  semanticCategory: SemanticCategory
  confidence: number
}

export type OpcodeTable = OpcodeEntry[]

// ---------------------------------------------------------------------------
// Switch-Case Extraction
// ---------------------------------------------------------------------------

/**
 * Extract switch-case entries from decompiled C-like code.
 * Returns array of { caseValue, handlerCode } for each case.
 */
export function extractSwitchCases(decompiledCode: string): CaseEntry[] {
  const entries: CaseEntry[] = []
  // Match: case 0x1A: ... (up to next case, default, or closing brace)
  const caseRe = /\bcase\s+(0x[\da-fA-F]+|\d+)\s*:([\s\S]*?)(?=\bcase\s+(?:0x[\da-fA-F]+|\d+)\s*:|\bdefault\s*:|}\s*$)/g
  let m: RegExpExecArray | null
  while ((m = caseRe.exec(decompiledCode)) !== null) {
    const value = parseInt(m[1], m[1].startsWith('0x') ? 16 : 10)
    const body = m[2].trim().replace(/\bbreak\s*;\s*$/, '').trim()
    entries.push({ caseValue: value, handlerCode: body })
  }
  return entries
}

// ---------------------------------------------------------------------------
// Handler Semantic Classification
// ---------------------------------------------------------------------------

interface PatternDef {
  mnemonic: string
  category: SemanticCategory
  patterns: RegExp[]
  confidence: number
}

const HANDLER_PATTERNS: PatternDef[] = [
  // Arithmetic
  { mnemonic: 'ADD', category: 'arithmetic', patterns: [/\+=/, /=\s*\w+\s*\+\s*\w+/], confidence: 75 },
  { mnemonic: 'SUB', category: 'arithmetic', patterns: [/-=/, /=\s*\w+\s*-\s*\w+/], confidence: 75 },
  { mnemonic: 'MUL', category: 'arithmetic', patterns: [/\*=/, /=\s*\w+\s*\*\s*\w+/], confidence: 70 },
  { mnemonic: 'DIV', category: 'arithmetic', patterns: [/\/=/, /=\s*\w+\s*\/\s*\w+/], confidence: 70 },
  { mnemonic: 'MOD', category: 'arithmetic', patterns: [/%=/, /=\s*\w+\s*%\s*\w+/], confidence: 70 },
  { mnemonic: 'NEG', category: 'arithmetic', patterns: [/=\s*-\s*\w+\s*;/], confidence: 65 },
  { mnemonic: 'INC', category: 'arithmetic', patterns: [/\+\+\w+|\w+\+\+/], confidence: 70 },
  { mnemonic: 'DEC', category: 'arithmetic', patterns: [/--\w+|\w+--/], confidence: 70 },

  // Logic
  { mnemonic: 'XOR', category: 'logic', patterns: [/\^=/, /=\s*\w+\s*\^\s*\w+/], confidence: 80 },
  { mnemonic: 'AND', category: 'logic', patterns: [/&=(?!&)/, /=\s*\w+\s*&(?!&)\s*\w+/], confidence: 75 },
  { mnemonic: 'OR', category: 'logic', patterns: [/\|=(?!\|)/, /=\s*\w+\s*\|(?!\|)\s*\w+/], confidence: 75 },
  { mnemonic: 'NOT', category: 'logic', patterns: [/=\s*~\s*\w+/], confidence: 75 },
  { mnemonic: 'SHL', category: 'logic', patterns: [/<<=/, /=\s*\w+\s*<<\s*\w+/], confidence: 80 },
  { mnemonic: 'SHR', category: 'logic', patterns: [/>>=/, /=\s*\w+\s*>>\s*\w+/], confidence: 80 },

  // Rotate
  { mnemonic: 'ROL', category: 'rotate', patterns: [/\bROL\b/i, /<<.*\|.*>>/], confidence: 85 },
  { mnemonic: 'ROR', category: 'rotate', patterns: [/\bROR\b/i, />>.*\|.*<</], confidence: 85 },

  // Memory
  { mnemonic: 'MOV', category: 'memory', patterns: [/\breg\w*\s*\[\s*\w+\s*\]\s*=\s*\w+/], confidence: 70 },
  { mnemonic: 'LOAD', category: 'memory', patterns: [/=\s*\*\s*\(/, /=\s*\w+\[\w+\]/], confidence: 70 },
  { mnemonic: 'STORE', category: 'memory', patterns: [/\*\s*\(\s*\w+\s*\)\s*=/, /\w+\[\w+\]\s*=/], confidence: 70 },

  // Control
  { mnemonic: 'JMP', category: 'control', patterns: [/\bpc\s*=\s*/, /\bip\s*=\s*/, /\bgoto\b/], confidence: 80 },
  { mnemonic: 'JZ', category: 'control', patterns: [/if\s*\(\s*\w+\s*==\s*0\s*\)\s*\{?\s*\w*(pc|ip)\w*\s*=/], confidence: 75 },
  { mnemonic: 'JNZ', category: 'control', patterns: [/if\s*\(\s*\w+\s*!=\s*0\s*\)\s*\{?\s*\w*(pc|ip)\w*\s*=/], confidence: 75 },

  // Stack
  { mnemonic: 'PUSH', category: 'stack', patterns: [/\bsp\b.*--|\bstack\b.*\bsp\b/i], confidence: 70 },
  { mnemonic: 'POP', category: 'stack', patterns: [/\bsp\b.*\+\+|=.*\bstack\b.*\bsp\b/i], confidence: 70 },

  // Compare
  { mnemonic: 'CMP', category: 'compare', patterns: [/\bif\s*\(\s*\w+\s*[=!<>]=?\s*\w+\s*\)/, /\bflags?\b.*=.*[<>=!]/i], confidence: 75 },
  { mnemonic: 'TEST', category: 'compare', patterns: [/\bif\s*\(\s*\w+\s*&\s*\w+\s*\)/], confidence: 70 },

  // Special
  { mnemonic: 'NOP', category: 'special', patterns: [/^\s*;?\s*$/, /\bbreak\s*;?\s*$/], confidence: 60 },
  { mnemonic: 'HALT', category: 'special', patterns: [/\breturn\b/, /\bexit\b/, /\brunning\s*=\s*(0|false)\b/], confidence: 70 },
  { mnemonic: 'SYSCALL', category: 'special', patterns: [/\bcall\b|\bfunc_\w+\s*\(/, /\binvoke\b/i], confidence: 60 },
]

/**
 * Classify a handler code block into a semantic category + mnemonic.
 */
export function classifyHandler(handlerCode: string): HandlerSemantic {
  let bestMatch: HandlerSemantic = {
    mnemonic: 'UNKNOWN',
    category: 'special',
    confidence: 0,
    operandHint: '',
  }

  for (const pat of HANDLER_PATTERNS) {
    for (const re of pat.patterns) {
      if (re.test(handlerCode)) {
        if (pat.confidence > bestMatch.confidence) {
          bestMatch = {
            mnemonic: pat.mnemonic,
            category: pat.category,
            confidence: pat.confidence,
            operandHint: handlerCode.slice(0, 80),
          }
        }
        break
      }
    }
  }

  return bestMatch
}

// ---------------------------------------------------------------------------
// Instruction Format Detection
// ---------------------------------------------------------------------------

/**
 * Detect the instruction encoding format by analyzing operand fetch patterns.
 */
export function detectInstructionFormat(cases: CaseEntry[]): InstructionFormat {
  const operandSizes = new Map<number, number[]>()

  for (const c of cases) {
    // Count distinct array accesses like buf[pc+1], buf[pc+2], etc.
    const offsets: number[] = []
    const offsetRe = /\[\s*\w*(pc|ip|ptr|cursor)\w*\s*\+\s*(\d+)\s*\]/gi
    let m: RegExpExecArray | null
    while ((m = offsetRe.exec(c.handlerCode)) !== null) {
      offsets.push(parseInt(m[2]))
    }

    if (offsets.length > 0) {
      // Each offset after 0 is an operand byte
      operandSizes.set(c.caseValue, offsets.map(() => 1)) // assume 1-byte each for now
    } else {
      operandSizes.set(c.caseValue, [])
    }
  }

  // Determine if fixed-length: all have same operand count
  const counts = [...operandSizes.values()].map(v => v.length)
  const allSame = counts.length > 0 && counts.every(c => c === counts[0])

  return {
    fixedLength: allSame && counts.length > 1,
    baseLength: 1, // opcode is always 1 byte minimum
    operandSizes,
  }
}

// ---------------------------------------------------------------------------
// Full Opcode Table Builder
// ---------------------------------------------------------------------------

/**
 * Build a complete opcode table from decompiled dispatcher code.
 */
export function buildOpcodeTable(decompiledCode: string): OpcodeTable {
  const cases = extractSwitchCases(decompiledCode)
  const format = detectInstructionFormat(cases)
  const table: OpcodeTable = []

  for (const c of cases) {
    const sem = classifyHandler(c.handlerCode)
    const opSizes = format.operandSizes.get(c.caseValue) ?? []

    table.push({
      value: c.caseValue,
      mnemonic: sem.mnemonic,
      operandCount: opSizes.length,
      operandSizes: opSizes,
      handlerCode: c.handlerCode,
      semanticCategory: sem.category,
      confidence: sem.confidence,
    })
  }

  return table
}
