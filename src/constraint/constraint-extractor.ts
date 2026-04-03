/**
 * Constraint Extractor — extracts mathematical constraints from VM execution traces.
 *
 * Scans trace for CMP/TEST steps, back-traces data flow to build symbolic expressions
 * in terms of input variables (s0, s1, ...).
 */

import type { ExecutionStep, ExtractedConstraint } from '../vm/vm-emulator.js'

// ---------------------------------------------------------------------------
// Constraint Expression IR
// ---------------------------------------------------------------------------

export type ConstraintExpr =
  | { kind: 'var'; name: string }
  | { kind: 'const'; value: bigint }
  | { kind: 'binop'; op: string; left: ConstraintExpr; right: ConstraintExpr }
  | { kind: 'unary'; op: string; child: ConstraintExpr }
  | { kind: 'rotate'; dir: 'left' | 'right'; child: ConstraintExpr; bits: ConstraintExpr; width: number }
  | { kind: 'func'; name: string; args: ConstraintExpr[] }

// Constructors
export function cVar(name: string): ConstraintExpr { return { kind: 'var', name } }
export function cConst(value: bigint | number): ConstraintExpr { return { kind: 'const', value: BigInt(value) } }
export function cBinop(op: string, left: ConstraintExpr, right: ConstraintExpr): ConstraintExpr {
  return { kind: 'binop', op, left, right }
}
export function cUnary(op: string, child: ConstraintExpr): ConstraintExpr {
  return { kind: 'unary', op, child }
}
export function cRotate(dir: 'left' | 'right', child: ConstraintExpr, bits: ConstraintExpr, width: number): ConstraintExpr {
  return { kind: 'rotate', dir, child, bits, width }
}
export function cFunc(name: string, args: ConstraintExpr[]): ConstraintExpr {
  return { kind: 'func', name, args }
}

// ---------------------------------------------------------------------------
// Serializers
// ---------------------------------------------------------------------------

/**
 * Serialize constraint expression as human-readable string.
 */
export function exprToString(e: ConstraintExpr): string {
  switch (e.kind) {
    case 'var': return e.name
    case 'const': return `0x${e.value.toString(16)}`
    case 'binop': return `(${exprToString(e.left)} ${e.op} ${exprToString(e.right)})`
    case 'unary': return `(${e.op}${exprToString(e.child)})`
    case 'rotate': return `ROT${e.dir === 'left' ? 'L' : 'R'}(${exprToString(e.child)}, ${exprToString(e.bits)}, ${e.width})`
    case 'func': return `${e.name}(${e.args.map(exprToString).join(', ')})`
  }
}

/**
 * Serialize constraint expression as Z3 Python code.
 */
export function exprToZ3py(e: ConstraintExpr, bitWidth = 32): string {
  switch (e.kind) {
    case 'var': return e.name
    case 'const': return `BitVecVal(0x${e.value.toString(16)}, ${bitWidth})`
    case 'binop': {
      const l = exprToZ3py(e.left, bitWidth)
      const r = exprToZ3py(e.right, bitWidth)
      const opMap: Record<string, string> = {
        '+': `${l} + ${r}`,
        '-': `${l} - ${r}`,
        '*': `${l} * ${r}`,
        '/': `UDiv(${l}, ${r})`,
        '%': `URem(${l}, ${r})`,
        '^': `${l} ^ ${r}`,
        '&': `${l} & ${r}`,
        '|': `${l} | ${r}`,
        '<<': `${l} << ${r}`,
        '>>': `LShR(${l}, ${r})`,
        'ADD': `${l} + ${r}`,
        'SUB': `${l} - ${r}`,
        'MUL': `${l} * ${r}`,
        'XOR': `${l} ^ ${r}`,
        'AND': `${l} & ${r}`,
        'OR': `${l} | ${r}`,
        'SHL': `${l} << ${r}`,
        'SHR': `LShR(${l}, ${r})`,
      }
      return opMap[e.op] ?? `${l} ${e.op} ${r}`
    }
    case 'unary': {
      const c = exprToZ3py(e.child, bitWidth)
      if (e.op === 'NOT' || e.op === '~') return `~${c}`
      if (e.op === 'NEG' || e.op === '-') return `-${c}`
      return `${e.op}(${c})`
    }
    case 'rotate': {
      const c = exprToZ3py(e.child, bitWidth)
      const b = exprToZ3py(e.bits, bitWidth)
      if (e.dir === 'left') return `RotateLeft(${c}, ${b})`
      return `RotateRight(${c}, ${b})`
    }
    case 'func': {
      const args = e.args.map(a => exprToZ3py(a, bitWidth)).join(', ')
      return `${e.name}(${args})`
    }
  }
}

// ---------------------------------------------------------------------------
// Structured Constraint
// ---------------------------------------------------------------------------

export interface Constraint {
  leftExpr: ConstraintExpr
  operator: string
  rightExpr: ConstraintExpr
  sourcePC: number
  raw: string
}

// ---------------------------------------------------------------------------
// Extraction from Trace
// ---------------------------------------------------------------------------

/**
 * Parse a simple expression string into ConstraintExpr.
 * Handles: 0x... constants, variable names, simple binary ops.
 */
export function parseExprString(s: string): ConstraintExpr {
  s = s.trim()

  // Constant
  if (/^0x[\da-fA-F]+$/.test(s)) {
    return cConst(BigInt(s))
  }
  if (/^\d+$/.test(s)) {
    return cConst(BigInt(s))
  }

  // Parenthesized binary op: (A op B)
  if (s.startsWith('(') && s.endsWith(')')) {
    const inner = s.slice(1, -1)
    // Find the operator at the top level
    const ops = ['+', '-', '*', '/', '%', '^', '&', '|', '<<', '>>', 'ADD', 'SUB', 'MUL', 'XOR', 'AND', 'OR', 'SHL', 'SHR']
    let depth = 0
    for (let i = 0; i < inner.length; i++) {
      if (inner[i] === '(') depth++
      else if (inner[i] === ')') depth--
      if (depth === 0) {
        for (const op of ops) {
          if (inner.substring(i).startsWith(` ${op} `)) {
            const left = inner.substring(0, i).trim()
            const right = inner.substring(i + op.length + 2).trim()
            return cBinop(op, parseExprString(left), parseExprString(right))
          }
        }
      }
    }
    // Couldn't parse inner — treat as variable
    return cVar(inner)
  }

  // ROTL/ROTR
  const rotMatch = /^ROT([LR])\((.+),\s*(.+),\s*(\d+)\)$/.exec(s)
  if (rotMatch) {
    return cRotate(
      rotMatch[1] === 'L' ? 'left' : 'right',
      parseExprString(rotMatch[2]),
      parseExprString(rotMatch[3]),
      parseInt(rotMatch[4])
    )
  }

  // Variable
  return cVar(s)
}

/**
 * Extract structured constraints from a VM execution trace.
 */
export function extractConstraints(trace: ExecutionStep[]): Constraint[] {
  const constraints: Constraint[] = []

  for (const step of trace) {
    if (!step.constraintEmitted) continue
    const ec = step.constraintEmitted

    constraints.push({
      leftExpr: parseExprString(ec.leftExpr),
      operator: ec.operator,
      rightExpr: parseExprString(ec.rightValue),
      sourcePC: ec.sourcePC,
      raw: `${ec.leftExpr} ${ec.operator} ${ec.rightValue}`,
    })
  }

  return constraints
}

/**
 * Generate Z3 Python script for solving the constraints.
 */
export function constraintsToZ3Script(constraints: Constraint[], bitWidth = 32): string {
  const lines: string[] = [
    'from z3 import *',
    '',
  ]

  // Collect all variables
  const vars = new Set<string>()
  function collectVars(e: ConstraintExpr): void {
    if (e.kind === 'var') vars.add(e.name)
    if (e.kind === 'binop') { collectVars(e.left); collectVars(e.right) }
    if (e.kind === 'unary') collectVars(e.child)
    if (e.kind === 'rotate') { collectVars(e.child); collectVars(e.bits) }
    if (e.kind === 'func') e.args.forEach(collectVars)
  }
  for (const c of constraints) {
    collectVars(c.leftExpr)
    collectVars(c.rightExpr)
  }

  // Declare variables
  for (const v of [...vars].sort()) {
    lines.push(`${v} = BitVec('${v}', ${bitWidth})`)
  }
  lines.push('')

  // Add constraints
  lines.push('s = Solver()')
  for (let i = 0; i < constraints.length; i++) {
    const c = constraints[i]
    const left = exprToZ3py(c.leftExpr, bitWidth)
    const right = exprToZ3py(c.rightExpr, bitWidth)
    lines.push(`s.add(${left} ${c.operator} ${right})  # PC=0x${c.sourcePC.toString(16)}`)
  }
  lines.push('')

  // Solve
  lines.push('if s.check() == sat:')
  lines.push('    m = s.model()')
  for (const v of [...vars].sort()) {
    lines.push(`    print(f"${v} = {m[${v}]}")`)
  }
  lines.push('else:')
  lines.push('    print("UNSAT")')

  return lines.join('\n')
}
