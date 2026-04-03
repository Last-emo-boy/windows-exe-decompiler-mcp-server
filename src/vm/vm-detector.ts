/**
 * VM Detection Engine — identifies fetch-decode-execute loop patterns in decompiled code.
 *
 * Heuristic scoring:
 *   1. Loop+Switch pattern (while/for containing switch with many cases)
 *   2. Bytecode fetch pattern (array dereference at loop-controlled index)
 *   3. Program counter increment pattern
 *   4. Handler regularity (similar structure across cases)
 *   5. Opcode range contiguity
 *
 * Each heuristic contributes 0-20 points.  Total ≥60 = high confidence VM.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface VMScore {
  total: number
  loopSwitch: number
  bytecodeFetch: number
  pcIncrement: number
  handlerRegularity: number
  opcodeRange: number
  matchedSnippets: string[]
}

export type VMComponentRole =
  | 'dispatcher'
  | 'handler'
  | 'bytecodeArray'
  | 'opcodeTable'
  | 'vmContext'

export interface VMComponent {
  functionName: string
  functionAddress: string
  role: VMComponentRole
  confidence: number
  score: VMScore
  snippet: string
}

export interface VMDetectionResult {
  components: VMComponent[]
  vmDetected: boolean
  highestScore: number
}

// ---------------------------------------------------------------------------
// Individual Heuristics
// ---------------------------------------------------------------------------

/**
 * Detect a main loop containing a switch statement with many cases.
 * Looks for `while`, `for`, `do` loops that immediately contain `switch(...)`.
 */
export function detectLoopSwitchPattern(code: string): { score: number; snippets: string[] } {
  const snippets: string[] = []
  let score = 0

  // Pattern: while/for/do ... { ... switch ... case ... case ...
  const loopSwitchRe = /\b(while|for|do)\b[^{]*\{[^}]*\bswitch\s*\(/gs
  const loopMatches = code.match(loopSwitchRe)
  if (loopMatches && loopMatches.length > 0) {
    score += 10
    snippets.push(loopMatches[0].slice(0, 120))
  }

  // Count case labels — more cases = more likely VM dispatcher
  const caseLabels = code.match(/\bcase\s+(0x[\da-fA-F]+|\d+)\s*:/g)
  if (caseLabels) {
    const count = caseLabels.length
    if (count >= 20) score += 10
    else if (count >= 10) score += 7
    else if (count >= 5) score += 4
    if (count >= 5) snippets.push(`${count} case labels detected`)
  }

  return { score: Math.min(score, 20), snippets }
}

/**
 * Detect bytecode array dereference patterns: buf[pc], *pc, *(ptr + offset).
 */
export function detectBytecodeFetch(code: string): { score: number; snippets: string[] } {
  const snippets: string[] = []
  let score = 0

  // Array index access patterns: buf[pc], bytecode[ip], code[counter]
  const arrayFetchRe = /\b\w+\s*\[\s*\w*(pc|ip|counter|idx|index|ptr|cursor)\w*\s*\]/gi
  const arrayMatches = code.match(arrayFetchRe)
  if (arrayMatches && arrayMatches.length > 0) {
    score += 12
    snippets.push(arrayMatches[0])
  }

  // Pointer dereference with increment: *pc++, *(ptr++), *ip++
  const ptrDerefRe = /\*\s*\(?\s*\w*(pc|ip|ptr|cursor)\w*\s*\+\+\s*\)?/gi
  const ptrMatches = code.match(ptrDerefRe)
  if (ptrMatches && ptrMatches.length > 0) {
    score += 10
    snippets.push(ptrMatches[0])
  }

  // Cast + dereference: *(uint8_t*)(base + offset)
  const castDerefRe = /\*\s*\(\s*(u?int\d+_t|BYTE|WORD|DWORD)\s*\*\s*\)\s*\(\s*\w+\s*\+\s*\w+\s*\)/gi
  const castMatches = code.match(castDerefRe)
  if (castMatches && castMatches.length > 0) {
    score += 8
    snippets.push(castMatches[0])
  }

  return { score: Math.min(score, 20), snippets }
}

/**
 * Detect program counter increment patterns: pc++, ip += N, counter = counter + 1.
 */
export function detectPCIncrement(code: string): { score: number; snippets: string[] } {
  const snippets: string[] = []
  let score = 0

  // Direct increment: pc++, ip++, ++pc
  const incRe = /\+\+\s*\w*(pc|ip|counter|cursor)\w*|\w*(pc|ip|counter|cursor)\w*\s*\+\+/gi
  const incMatches = code.match(incRe)
  if (incMatches && incMatches.length > 0) {
    score += 12
    snippets.push(incMatches[0])
  }

  // Assignment increment: pc += N, ip = ip + sizeof(...)
  const addAssignRe = /\w*(pc|ip|counter|cursor)\w*\s*\+=\s*\d+/gi
  const addMatches = code.match(addAssignRe)
  if (addMatches && addMatches.length > 0) {
    score += 10
    snippets.push(addMatches[0])
  }

  // Generic increment: var = var + expr (where var looks like a counter)
  const genIncRe = /\b(pc|ip|counter|cursor|ptr)\b\s*=\s*\1\s*\+/gi
  const genMatches = code.match(genIncRe)
  if (genMatches && genMatches.length > 0) {
    score += 8
    snippets.push(genMatches[0])
  }

  return { score: Math.min(score, 20), snippets }
}

/**
 * Detect handler regularity — switch cases with similar structure.
 * Looks for multiple cases that each access operands and update state.
 */
export function detectHandlerRegularity(code: string): { score: number; snippets: string[] } {
  const snippets: string[] = []
  let score = 0

  // Extract case bodies
  const caseBodyRe = /\bcase\s+(?:0x[\da-fA-F]+|\d+)\s*:([\s\S]*?)(?=\bcase\s|\bdefault\s*:|$)/g
  const bodies: string[] = []
  let m: RegExpExecArray | null
  while ((m = caseBodyRe.exec(code)) !== null) {
    bodies.push(m[1].trim())
  }

  if (bodies.length < 3) return { score: 0, snippets }

  // Check for common patterns across handlers
  let operandFetchCount = 0
  let stateUpdateCount = 0
  let breakCount = 0

  for (const body of bodies) {
    if (/\[\s*\w*(pc|ip|ptr)\w*\s*[+\]]/.test(body)) operandFetchCount++
    if (/\b(reg|state|ctx|vm|stack)\w*\s*[\[.]/.test(body)) stateUpdateCount++
    if (/\bbreak\b/.test(body)) breakCount++
  }

  const total = bodies.length
  if (operandFetchCount / total >= 0.5) {
    score += 8
    snippets.push(`${operandFetchCount}/${total} handlers fetch operands`)
  }
  if (stateUpdateCount / total >= 0.4) {
    score += 7
    snippets.push(`${stateUpdateCount}/${total} handlers update state`)
  }
  if (breakCount / total >= 0.7) {
    score += 5
    snippets.push(`${breakCount}/${total} handlers have break`)
  }

  return { score: Math.min(score, 20), snippets }
}

/**
 * Check opcode range contiguity — VM opcodes tend to be in a compact range.
 */
export function detectOpcodeRange(code: string): { score: number; snippets: string[] } {
  const snippets: string[] = []
  let score = 0

  const caseValueRe = /\bcase\s+(0x[\da-fA-F]+|\d+)\s*:/g
  const values: number[] = []
  let m: RegExpExecArray | null
  while ((m = caseValueRe.exec(code)) !== null) {
    values.push(parseInt(m[1], m[1].startsWith('0x') ? 16 : 10))
  }

  if (values.length < 5) return { score: 0, snippets }

  values.sort((a, b) => a - b)
  const min = values[0]
  const max = values[values.length - 1]
  const range = max - min + 1
  const density = values.length / range

  if (density >= 0.8) {
    score += 15
    snippets.push(`Dense opcode range: ${values.length} opcodes in [${min}..${max}] (${(density * 100).toFixed(0)}%)`)
  } else if (density >= 0.5) {
    score += 10
    snippets.push(`Moderate opcode range: ${values.length} opcodes in [${min}..${max}] (${(density * 100).toFixed(0)}%)`)
  } else if (density >= 0.3) {
    score += 5
    snippets.push(`Sparse opcode range: ${values.length} opcodes in [${min}..${max}] (${(density * 100).toFixed(0)}%)`)
  }

  // Bonus: starts from 0
  if (min === 0) {
    score += 5
    snippets.push('Opcode range starts from 0')
  }

  return { score: Math.min(score, 20), snippets }
}

// ---------------------------------------------------------------------------
// Composite Scoring
// ---------------------------------------------------------------------------

/**
 * Score a single decompiled function as a potential VM dispatcher.
 */
export function scoreVMCandidate(decompiledCode: string): VMScore {
  const ls = detectLoopSwitchPattern(decompiledCode)
  const bf = detectBytecodeFetch(decompiledCode)
  const pi = detectPCIncrement(decompiledCode)
  const hr = detectHandlerRegularity(decompiledCode)
  const or = detectOpcodeRange(decompiledCode)

  return {
    loopSwitch: ls.score,
    bytecodeFetch: bf.score,
    pcIncrement: pi.score,
    handlerRegularity: hr.score,
    opcodeRange: or.score,
    total: ls.score + bf.score + pi.score + hr.score + or.score,
    matchedSnippets: [
      ...ls.snippets,
      ...bf.snippets,
      ...pi.snippets,
      ...hr.snippets,
      ...or.snippets,
    ],
  }
}

/**
 * Classify a function's most likely VM component role based on its score profile.
 */
function classifyRole(score: VMScore): VMComponentRole {
  // High loop+switch + many handlers → dispatcher
  if (score.loopSwitch >= 10 && score.opcodeRange >= 5) return 'dispatcher'
  // High handler regularity without loop → may be an individual handler
  if (score.handlerRegularity >= 10 && score.loopSwitch < 5) return 'handler'
  // High bytecode fetch without switch → bytecode array access
  if (score.bytecodeFetch >= 10 && score.loopSwitch < 5) return 'bytecodeArray'
  // Default to dispatcher if total is high
  if (score.total >= 40) return 'dispatcher'
  return 'vmContext'
}

export interface DecompiledFunc {
  name: string
  address: string
  decompiled_code: string
}

/**
 * Score and classify all functions for VM components.
 */
export function classifyVMComponents(
  functions: DecompiledFunc[],
  minConfidence = 30
): VMComponent[] {
  const results: VMComponent[] = []

  for (const fn of functions) {
    if (!fn.decompiled_code || fn.decompiled_code.length < 50) continue
    const score = scoreVMCandidate(fn.decompiled_code)
    if (score.total < minConfidence) continue

    results.push({
      functionName: fn.name,
      functionAddress: fn.address,
      role: classifyRole(score),
      confidence: Math.min(score.total, 100),
      score,
      snippet: fn.decompiled_code.slice(0, 300),
    })
  }

  // Sort by confidence descending
  results.sort((a, b) => b.confidence - a.confidence)
  return results
}
