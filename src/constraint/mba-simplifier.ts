/**
 * MBA (Mixed Boolean-Arithmetic) Simplifier — reduces obfuscated
 * expressions to their canonical forms using algebraic identity rules.
 *
 * Common MBA identities:
 *   (a + b) - 2*(a & b)          → a ^ b
 *   (a & b) + (a | b)            → a + b
 *   (a ^ b) + 2*(a & b)          → a + b
 *   (a | b) - (a & b)            → a ^ b
 *   ~(~a & ~b)                   → a | b
 *   ~(~a | ~b)                   → a & b
 *   (a & b) | (a & ~b)           → a
 *   a ^ (a & b)                  → a & ~b
 *   (a | b) & (a | ~b)           → a
 *   (a ^ -1) + 1                 → -a   (two's complement negate)
 */

// ---------------------------------------------------------------------------
// Expression AST
// ---------------------------------------------------------------------------

export type MBAExpr =
  | { kind: 'var'; name: string }
  | { kind: 'const'; value: bigint }
  | { kind: 'binop'; op: string; left: MBAExpr; right: MBAExpr }
  | { kind: 'unary'; op: string; child: MBAExpr }

export function mVar(name: string): MBAExpr { return { kind: 'var', name } }
export function mConst(value: bigint | number): MBAExpr { return { kind: 'const', value: BigInt(value) } }
export function mBinop(op: string, left: MBAExpr, right: MBAExpr): MBAExpr { return { kind: 'binop', op, left, right } }
export function mUnary(op: string, child: MBAExpr): MBAExpr { return { kind: 'unary', op, child } }

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/** Deep structural equality. */
export function exprEqual(a: MBAExpr, b: MBAExpr): boolean {
  if (a.kind !== b.kind) return false
  switch (a.kind) {
    case 'var':   return (b as typeof a).name === a.name
    case 'const': return (b as typeof a).value === a.value
    case 'binop': {
      const bb = b as typeof a
      return a.op === bb.op && exprEqual(a.left, bb.left) && exprEqual(a.right, bb.right)
    }
    case 'unary': {
      const bu = b as typeof a
      return a.op === bu.op && exprEqual(a.child, bu.child)
    }
  }
}

/** Check equality ignoring operand order (for commutative ops). */
function commEqual(a: MBAExpr, b: MBAExpr): boolean {
  if (a.kind !== 'binop' || b.kind !== 'binop') return exprEqual(a, b)
  if (a.op !== b.op) return false
  return (exprEqual(a.left, b.left) && exprEqual(a.right, b.right)) ||
         (exprEqual(a.left, b.right) && exprEqual(a.right, b.left))
}

/** Pretty-print. */
export function exprToString(e: MBAExpr): string {
  switch (e.kind) {
    case 'var':   return e.name
    case 'const': return e.value < 0 ? `(${e.value.toString()})` : `0x${e.value.toString(16)}`
    case 'binop': return `(${exprToString(e.left)} ${e.op} ${exprToString(e.right)})`
    case 'unary': return `${e.op}(${exprToString(e.child)})`
  }
}

/** Count nodes in the expression tree. */
export function nodeCount(e: MBAExpr): number {
  switch (e.kind) {
    case 'var':
    case 'const': return 1
    case 'binop': return 1 + nodeCount(e.left) + nodeCount(e.right)
    case 'unary': return 1 + nodeCount(e.child)
  }
}

// ---------------------------------------------------------------------------
// Simplification Rules
// ---------------------------------------------------------------------------

type Rule = (e: MBAExpr) => MBAExpr | null

/** Constant folding. */
const foldConstants: Rule = (e) => {
  if (e.kind !== 'binop') return null
  if (e.left.kind !== 'const' || e.right.kind !== 'const') return null
  const a = e.left.value
  const b = e.right.value
  switch (e.op) {
    case '+':  return mConst(a + b)
    case '-':  return mConst(a - b)
    case '*':  return mConst(a * b)
    case '&':  return mConst(a & b)
    case '|':  return mConst(a | b)
    case '^':  return mConst(a ^ b)
    default:   return null
  }
}

/** Identity rules: x + 0, x & -1, x ^ 0, x | 0, x * 1, x - 0 */
const identityRules: Rule = (e) => {
  if (e.kind !== 'binop') return null
  const { op, left, right } = e

  const isZero = (n: MBAExpr) => n.kind === 'const' && n.value === 0n
  const isOne = (n: MBAExpr) => n.kind === 'const' && n.value === 1n
  const isNegOne = (n: MBAExpr) => n.kind === 'const' && n.value === -1n

  if (op === '+' && isZero(right)) return left
  if (op === '+' && isZero(left))  return right
  if (op === '-' && isZero(right)) return left
  if (op === '*' && isOne(right))  return left
  if (op === '*' && isOne(left))   return right
  if (op === '*' && isZero(right)) return mConst(0)
  if (op === '*' && isZero(left))  return mConst(0)
  if (op === '&' && isNegOne(right)) return left
  if (op === '&' && isNegOne(left))  return right
  if (op === '&' && isZero(right)) return mConst(0)
  if (op === '&' && isZero(left))  return mConst(0)
  if (op === '|' && isZero(right)) return left
  if (op === '|' && isZero(left))  return right
  if (op === '^' && isZero(right)) return left
  if (op === '^' && isZero(left))  return right
  return null
}

/** x op x simplifications. */
const selfRules: Rule = (e) => {
  if (e.kind !== 'binop') return null
  if (!exprEqual(e.left, e.right)) return null
  switch (e.op) {
    case '^': return mConst(0)      // x ^ x = 0
    case '-': return mConst(0)      // x - x = 0
    case '&': return e.left         // x & x = x
    case '|': return e.left         // x | x = x
    default:  return null
  }
}

/** Double negation: ~~x → x */
const doubleNeg: Rule = (e) => {
  if (e.kind !== 'unary' || e.op !== '~') return null
  if (e.child.kind === 'unary' && e.child.op === '~') return e.child.child
  return null
}

/** (a + b) - 2*(a & b) → a ^ b */
const mbaXorFromAdd: Rule = (e) => {
  if (e.kind !== 'binop' || e.op !== '-') return null
  const { left, right } = e
  if (left.kind !== 'binop' || left.op !== '+') return null
  if (right.kind !== 'binop' || right.op !== '*') return null

  const factor = right.left.kind === 'const' ? right.left : right.right
  const andExpr = right.left.kind === 'const' ? right.right : right.left
  if (factor.kind !== 'const' || factor.value !== 2n) return null
  if (andExpr.kind !== 'binop' || andExpr.op !== '&') return null

  if (commEqual(mBinop('&', left.left, left.right), andExpr)) {
    return mBinop('^', left.left, left.right)
  }
  return null
}

/** (a & b) + (a | b) → a + b */
const mbaAddFromBool: Rule = (e) => {
  if (e.kind !== 'binop' || e.op !== '+') return null
  const { left, right } = e
  if (left.kind !== 'binop' || right.kind !== 'binop') return null

  // Check both orderings: (a&b)+(a|b) and (a|b)+(a&b)
  let andPart: MBAExpr | null = null
  let orPart: MBAExpr | null = null
  if (left.op === '&' && right.op === '|') { andPart = left; orPart = right }
  else if (left.op === '|' && right.op === '&') { andPart = right; orPart = left }
  else return null

  if (andPart.kind !== 'binop' || orPart.kind !== 'binop') return null
  if (commEqual(andPart, mBinop('&', orPart.left, orPart.right))) {
    return mBinop('+', orPart.left, orPart.right)
  }
  return null
}

/** (a ^ b) + 2*(a & b) → a + b */
const mbaAddFromXor: Rule = (e) => {
  if (e.kind !== 'binop' || e.op !== '+') return null
  const { left, right } = e

  let xorPart: MBAExpr | null = null
  let mulPart: MBAExpr | null = null
  if (left.kind === 'binop' && left.op === '^' && right.kind === 'binop' && right.op === '*') {
    xorPart = left; mulPart = right
  } else if (right.kind === 'binop' && right.op === '^' && left.kind === 'binop' && left.op === '*') {
    xorPart = right; mulPart = left
  } else return null

  if (mulPart.kind !== 'binop') return null
  const factor = mulPart.left.kind === 'const' ? mulPart.left : mulPart.right
  const andExpr = mulPart.left.kind === 'const' ? mulPart.right : mulPart.left
  if (factor.kind !== 'const' || factor.value !== 2n) return null
  if (andExpr.kind !== 'binop' || andExpr.op !== '&') return null

  if (xorPart.kind !== 'binop') return null
  if (commEqual(mBinop('&', xorPart.left, xorPart.right), andExpr)) {
    return mBinop('+', xorPart.left, xorPart.right)
  }
  return null
}

/** (a | b) - (a & b) → a ^ b */
const mbaXorFromOr: Rule = (e) => {
  if (e.kind !== 'binop' || e.op !== '-') return null
  const { left, right } = e
  if (left.kind !== 'binop' || left.op !== '|') return null
  if (right.kind !== 'binop' || right.op !== '&') return null
  if (commEqual(left, mBinop('|', right.left, right.right))) {
    return mBinop('^', left.left, left.right)
  }
  return null
}

/** DeMorgan: ~(~a & ~b) → a | b, ~(~a | ~b) → a & b */
const deMorgan: Rule = (e) => {
  if (e.kind !== 'unary' || e.op !== '~') return null
  const inner = e.child
  if (inner.kind !== 'binop') return null
  if (inner.op !== '&' && inner.op !== '|') return null

  const leftIsNot = inner.left.kind === 'unary' && inner.left.op === '~'
  const rightIsNot = inner.right.kind === 'unary' && inner.right.op === '~'
  if (!leftIsNot || !rightIsNot) return null

  const a = (inner.left as { kind: 'unary'; op: string; child: MBAExpr }).child
  const b = (inner.right as { kind: 'unary'; op: string; child: MBAExpr }).child

  if (inner.op === '&') return mBinop('|', a, b)
  if (inner.op === '|') return mBinop('&', a, b)
  return null
}

/** (a ^ -1) + 1 → -a   (two's complement negate) */
const twosComplement: Rule = (e) => {
  if (e.kind !== 'binop' || e.op !== '+') return null
  if (e.right.kind !== 'const' || e.right.value !== 1n) return null
  if (e.left.kind !== 'binop' || e.left.op !== '^') return null
  if (e.left.right.kind === 'const' && e.left.right.value === -1n) {
    return mUnary('-', e.left.left)
  }
  return null
}

// Collect all rules
const RULES: Rule[] = [
  foldConstants,
  identityRules,
  selfRules,
  doubleNeg,
  mbaXorFromAdd,
  mbaAddFromBool,
  mbaAddFromXor,
  mbaXorFromOr,
  deMorgan,
  twosComplement,
]

// ---------------------------------------------------------------------------
// Simplifier Engine
// ---------------------------------------------------------------------------

/**
 * Single-pass bottom-up simplification.
 */
function simplifyOnce(e: MBAExpr): MBAExpr {
  // Recurse into children first
  let current: MBAExpr
  switch (e.kind) {
    case 'var':
    case 'const':
      current = e
      break
    case 'binop':
      current = mBinop(e.op, simplifyOnce(e.left), simplifyOnce(e.right))
      break
    case 'unary':
      current = mUnary(e.op, simplifyOnce(e.child))
      break
  }

  // Try each rule
  for (const rule of RULES) {
    const result = rule(current)
    if (result !== null) return result
  }
  return current
}

export interface SimplifyResult {
  original: string
  simplified: string
  originalNodes: number
  simplifiedNodes: number
  reductionPercent: number
  iterations: number
}

/**
 * Simplify an MBA expression, iterating to a fixpoint (or maxIter).
 */
export function simplify(expr: MBAExpr, maxIter = 20): SimplifyResult {
  const originalStr = exprToString(expr)
  const originalNodes = nodeCount(expr)
  let current = expr
  let iter = 0

  for (iter = 0; iter < maxIter; iter++) {
    const next = simplifyOnce(current)
    if (exprEqual(next, current)) break
    current = next
  }

  const simplifiedStr = exprToString(current)
  const simplifiedNodes = nodeCount(current)
  const reductionPercent = originalNodes > 0
    ? Math.round((1 - simplifiedNodes / originalNodes) * 100)
    : 0

  return {
    original: originalStr,
    simplified: simplifiedStr,
    originalNodes,
    simplifiedNodes,
    reductionPercent,
    iterations: iter,
  }
}

/**
 * Parse a simple expression string into an MBAExpr.
 * Supports: variables, hex/dec constants, binary ops (+,-,*,&,|,^), unary (~,-), parentheses.
 */
export function parseExpression(input: string): MBAExpr {
  let pos = 0
  const s = input.replace(/\s+/g, '')

  function peek(): string { return s[pos] ?? '' }
  function consume(): string { return s[pos++] }

  function parseAtom(): MBAExpr {
    if (peek() === '~') {
      consume()
      return mUnary('~', parseAtom())
    }
    if (peek() === '(') {
      consume() // '('
      const inner = parseOr()
      if (peek() === ')') consume()
      return inner
    }
    if (peek() === '0' && s[pos + 1] === 'x') {
      const start = pos
      pos += 2
      while (/[0-9a-fA-F]/.test(peek())) pos++
      return mConst(BigInt(s.slice(start, pos)))
    }
    if (/[0-9]/.test(peek())) {
      const start = pos
      while (/[0-9]/.test(peek())) pos++
      return mConst(BigInt(s.slice(start, pos)))
    }
    if (/[a-zA-Z_]/.test(peek())) {
      const start = pos
      while (/[a-zA-Z0-9_]/.test(peek())) pos++
      return mVar(s.slice(start, pos))
    }
    throw new Error(`Unexpected character '${peek()}' at position ${pos}`)
  }

  function parseMul(): MBAExpr {
    let left = parseAtom()
    while (peek() === '*') {
      consume()
      left = mBinop('*', left, parseAtom())
    }
    return left
  }

  function parseAdd(): MBAExpr {
    let left = parseMul()
    while (peek() === '+' || peek() === '-') {
      const op = consume()
      left = mBinop(op, left, parseMul())
    }
    return left
  }

  function parseAnd(): MBAExpr {
    let left = parseAdd()
    while (peek() === '&') {
      consume()
      left = mBinop('&', left, parseAdd())
    }
    return left
  }

  function parseXor(): MBAExpr {
    let left = parseAnd()
    while (peek() === '^') {
      consume()
      left = mBinop('^', left, parseAnd())
    }
    return left
  }

  function parseOr(): MBAExpr {
    let left = parseXor()
    while (peek() === '|') {
      consume()
      left = mBinop('|', left, parseXor())
    }
    return left
  }

  return parseOr()
}
