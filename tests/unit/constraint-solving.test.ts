/**
 * Unit tests for the constraint solving pipeline:
 *   - Constraint extraction
 *   - Z3 script generation
 *   - Keygen synthesis
 *   - MBA simplification
 */

// ── MBA Simplifier replicated logic ─────────────────────────────────

type MBAExpr =
  | { kind: 'var'; name: string }
  | { kind: 'const'; value: bigint }
  | { kind: 'binop'; op: string; left: MBAExpr; right: MBAExpr }
  | { kind: 'unary'; op: string; child: MBAExpr }

function mVar(name: string): MBAExpr { return { kind: 'var', name } }
function mConst(value: bigint | number): MBAExpr { return { kind: 'const', value: BigInt(value) } }
function mBinop(op: string, left: MBAExpr, right: MBAExpr): MBAExpr { return { kind: 'binop', op, left, right } }
function mUnary(op: string, child: MBAExpr): MBAExpr { return { kind: 'unary', op, child } }

function exprEqual(a: MBAExpr, b: MBAExpr): boolean {
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

function commEqual(a: MBAExpr, b: MBAExpr): boolean {
  if (a.kind !== 'binop' || b.kind !== 'binop') return exprEqual(a, b)
  if (a.op !== b.op) return false
  return (exprEqual(a.left, b.left) && exprEqual(a.right, b.right)) ||
         (exprEqual(a.left, b.right) && exprEqual(a.right, b.left))
}

function mbaExprToString(e: MBAExpr): string {
  switch (e.kind) {
    case 'var':   return e.name
    case 'const': return e.value < 0 ? `(${e.value.toString()})` : `0x${e.value.toString(16)}`
    case 'binop': return `(${mbaExprToString(e.left)} ${e.op} ${mbaExprToString(e.right)})`
    case 'unary': return `${e.op}(${mbaExprToString(e.child)})`
  }
}

function nodeCount(e: MBAExpr): number {
  switch (e.kind) {
    case 'var': case 'const': return 1
    case 'binop': return 1 + nodeCount(e.left) + nodeCount(e.right)
    case 'unary': return 1 + nodeCount(e.child)
  }
}

type Rule = (e: MBAExpr) => MBAExpr | null

const foldConstants: Rule = (e) => {
  if (e.kind !== 'binop') return null
  if (e.left.kind !== 'const' || e.right.kind !== 'const') return null
  const a = e.left.value, b = e.right.value
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

const identityRules: Rule = (e) => {
  if (e.kind !== 'binop') return null
  const { op, left, right } = e
  const isZero = (n: MBAExpr) => n.kind === 'const' && n.value === 0n
  const isOne = (n: MBAExpr) => n.kind === 'const' && n.value === 1n
  if (op === '+' && isZero(right)) return left
  if (op === '+' && isZero(left))  return right
  if (op === '-' && isZero(right)) return left
  if (op === '*' && isOne(right))  return left
  if (op === '*' && isOne(left))   return right
  if (op === '*' && isZero(right)) return mConst(0)
  if (op === '*' && isZero(left))  return mConst(0)
  if (op === '^' && isZero(right)) return left
  if (op === '^' && isZero(left))  return right
  return null
}

const selfRules: Rule = (e) => {
  if (e.kind !== 'binop') return null
  if (!exprEqual(e.left, e.right)) return null
  switch (e.op) {
    case '^': return mConst(0)
    case '-': return mConst(0)
    case '&': return e.left
    case '|': return e.left
    default:  return null
  }
}

const doubleNeg: Rule = (e) => {
  if (e.kind !== 'unary' || e.op !== '~') return null
  if (e.child.kind === 'unary' && e.child.op === '~') return e.child.child
  return null
}

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

const RULES: Rule[] = [foldConstants, identityRules, selfRules, doubleNeg, mbaXorFromAdd, mbaXorFromOr, deMorgan]

function simplifyOnce(e: MBAExpr): MBAExpr {
  let current: MBAExpr
  switch (e.kind) {
    case 'var': case 'const': current = e; break
    case 'binop': current = mBinop(e.op, simplifyOnce(e.left), simplifyOnce(e.right)); break
    case 'unary': current = mUnary(e.op, simplifyOnce(e.child)); break
  }
  for (const rule of RULES) {
    const result = rule(current)
    if (result !== null) return result
  }
  return current
}

function simplify(expr: MBAExpr, maxIter = 20) {
  const originalStr = mbaExprToString(expr)
  const originalNodes = nodeCount(expr)
  let current = expr
  let iter = 0
  for (iter = 0; iter < maxIter; iter++) {
    const next = simplifyOnce(current)
    if (exprEqual(next, current)) break
    current = next
  }
  return {
    original: originalStr,
    simplified: mbaExprToString(current),
    simplifiedExpr: current,
    originalNodes,
    simplifiedNodes: nodeCount(current),
    iterations: iter,
  }
}

// ── Expression parser (minimal) ─────────────────────────────────────

function parseExpression(input: string): MBAExpr {
  let pos = 0
  const s = input.replace(/\s+/g, '')

  function peek(): string { return s[pos] ?? '' }
  function consume(): string { return s[pos++] }

  function parseAtom(): MBAExpr {
    if (peek() === '~') { consume(); return mUnary('~', parseAtom()) }
    if (peek() === '(') { consume(); const inner = parseOr(); if (peek() === ')') consume(); return inner }
    if (peek() === '0' && s[pos + 1] === 'x') {
      const start = pos; pos += 2
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
    while (peek() === '*') { consume(); left = mBinop('*', left, parseAtom()) }
    return left
  }
  function parseAdd(): MBAExpr {
    let left = parseMul()
    while (peek() === '+' || peek() === '-') { const op = consume(); left = mBinop(op, left, parseMul()) }
    return left
  }
  function parseAnd(): MBAExpr {
    let left = parseAdd()
    while (peek() === '&') { consume(); left = mBinop('&', left, parseAdd()) }
    return left
  }
  function parseXor(): MBAExpr {
    let left = parseAnd()
    while (peek() === '^') { consume(); left = mBinop('^', left, parseAnd()) }
    return left
  }
  function parseOr(): MBAExpr {
    let left = parseXor()
    while (peek() === '|') { consume(); left = mBinop('|', left, parseXor()) }
    return left
  }

  return parseOr()
}

// ── Tests ──────────────────────────────────────────────────────────────

describe('Constraint Solving Pipeline', () => {
  describe('MBA Simplifier', () => {
    describe('constant folding', () => {
      it('should fold 3 + 5 → 8', () => {
        const expr = mBinop('+', mConst(3), mConst(5))
        const r = simplify(expr)
        expect(r.simplified).toBe('0x8')
      })

      it('should fold 0xFF ^ 0xFF → 0', () => {
        const expr = mBinop('^', mConst(0xFF), mConst(0xFF))
        const r = simplify(expr)
        expect(r.simplified).toBe('0x0')
      })
    })

    describe('identity rules', () => {
      it('should simplify x + 0 → x', () => {
        const expr = mBinop('+', mVar('x'), mConst(0))
        const r = simplify(expr)
        expect(r.simplified).toBe('x')
      })

      it('should simplify 0 + x → x', () => {
        const expr = mBinop('+', mConst(0), mVar('x'))
        const r = simplify(expr)
        expect(r.simplified).toBe('x')
      })

      it('should simplify x * 1 → x', () => {
        const expr = mBinop('*', mVar('x'), mConst(1))
        const r = simplify(expr)
        expect(r.simplified).toBe('x')
      })

      it('should simplify x * 0 → 0', () => {
        const expr = mBinop('*', mVar('x'), mConst(0))
        const r = simplify(expr)
        expect(r.simplified).toBe('0x0')
      })

      it('should simplify x ^ 0 → x', () => {
        const expr = mBinop('^', mVar('x'), mConst(0))
        const r = simplify(expr)
        expect(r.simplified).toBe('x')
      })
    })

    describe('self rules', () => {
      it('should simplify x ^ x → 0', () => {
        const expr = mBinop('^', mVar('a'), mVar('a'))
        const r = simplify(expr)
        expect(r.simplified).toBe('0x0')
      })

      it('should simplify x - x → 0', () => {
        const expr = mBinop('-', mVar('a'), mVar('a'))
        const r = simplify(expr)
        expect(r.simplified).toBe('0x0')
      })

      it('should simplify x & x → x', () => {
        const expr = mBinop('&', mVar('a'), mVar('a'))
        const r = simplify(expr)
        expect(r.simplified).toBe('a')
      })

      it('should simplify x | x → x', () => {
        const expr = mBinop('|', mVar('a'), mVar('a'))
        const r = simplify(expr)
        expect(r.simplified).toBe('a')
      })
    })

    describe('double negation', () => {
      it('should simplify ~~x → x', () => {
        const expr = mUnary('~', mUnary('~', mVar('x')))
        const r = simplify(expr)
        expect(r.simplified).toBe('x')
      })
    })

    describe('MBA identity: (a+b) - 2*(a&b) → a^b', () => {
      it('should simplify the MBA XOR pattern', () => {
        const a = mVar('a')
        const b = mVar('b')
        const expr = mBinop('-',
          mBinop('+', a, b),
          mBinop('*', mConst(2), mBinop('&', a, b))
        )
        const r = simplify(expr)
        expect(r.simplified).toBe('(a ^ b)')
      })
    })

    describe('MBA identity: (a|b) - (a&b) → a^b', () => {
      it('should simplify', () => {
        const a = mVar('a')
        const b = mVar('b')
        const expr = mBinop('-',
          mBinop('|', a, b),
          mBinop('&', a, b)
        )
        const r = simplify(expr)
        expect(r.simplified).toBe('(a ^ b)')
      })
    })

    describe('DeMorgan', () => {
      it('should simplify ~(~a & ~b) → a | b', () => {
        const expr = mUnary('~',
          mBinop('&', mUnary('~', mVar('a')), mUnary('~', mVar('b')))
        )
        const r = simplify(expr)
        expect(r.simplified).toBe('(a | b)')
      })

      it('should simplify ~(~a | ~b) → a & b', () => {
        const expr = mUnary('~',
          mBinop('|', mUnary('~', mVar('a')), mUnary('~', mVar('b')))
        )
        const r = simplify(expr)
        expect(r.simplified).toBe('(a & b)')
      })
    })

    describe('reduction tracking', () => {
      it('should report node reduction', () => {
        const expr = mBinop('+', mVar('x'), mConst(0))
        const r = simplify(expr)
        expect(r.simplifiedNodes).toBeLessThan(r.originalNodes)
      })
    })
  })

  describe('Expression Parser', () => {
    it('should parse simple variable', () => {
      const e = parseExpression('x')
      expect(e.kind).toBe('var')
      expect((e as { kind: 'var'; name: string }).name).toBe('x')
    })

    it('should parse hex constant', () => {
      const e = parseExpression('0xFF')
      expect(e.kind).toBe('const')
      expect((e as { kind: 'const'; value: bigint }).value).toBe(255n)
    })

    it('should parse binary operations', () => {
      const e = parseExpression('a + b')
      expect(e.kind).toBe('binop')
    })

    it('should parse nested operations', () => {
      const e = parseExpression('(a + b) - 2 * (a & b)')
      expect(e.kind).toBe('binop')
    })

    it('should parse unary NOT', () => {
      const e = parseExpression('~x')
      expect(e.kind).toBe('unary')
      expect((e as { kind: 'unary'; op: string; child: MBAExpr }).op).toBe('~')
    })

    it('should parse and simplify round-trip', () => {
      const expr = parseExpression('(a + b) - 2 * (a & b)')
      const r = simplify(expr)
      expect(r.simplified).toBe('(a ^ b)')
    })
  })

  describe('Keygen Synthesis', () => {
    // Replicated types from keygen-synthesizer.ts
    interface ConstraintExpr {
      kind: string
      [key: string]: unknown
    }

    interface Constraint {
      leftExpr: ConstraintExpr
      operator: string
      rightExpr: ConstraintExpr
      sourcePC: number
      raw?: string
    }

    interface DependencyNode {
      variable: string
      dependsOn: string[]
      needsBruteForce: boolean
    }

    function collectVars(e: ConstraintExpr): Set<string> {
      const vars = new Set<string>()
      function walk(node: ConstraintExpr): void {
        if (node.kind === 'var') vars.add(node.name as string)
        if (node.kind === 'binop') { walk(node.left as ConstraintExpr); walk(node.right as ConstraintExpr) }
        if (node.kind === 'unary') walk(node.child as ConstraintExpr)
      }
      walk(e)
      return vars
    }

    function hasNonInvertible(e: ConstraintExpr): boolean {
      if (e.kind === 'func') {
        const name = (e.name as string || '').toUpperCase()
        return ['CRC16', 'CRC32', 'MD5', 'SHA1', 'SHA256', 'HASH'].some(n => name.includes(n))
      }
      if (e.kind === 'binop') return hasNonInvertible(e.left as ConstraintExpr) || hasNonInvertible(e.right as ConstraintExpr)
      if (e.kind === 'unary') return hasNonInvertible(e.child as ConstraintExpr)
      return false
    }

    it('should collect variables from expressions', () => {
      const expr: ConstraintExpr = {
        kind: 'binop', op: '+',
        left: { kind: 'var', name: 'x' },
        right: { kind: 'var', name: 'y' },
      }
      const vars = collectVars(expr)
      expect(vars.has('x')).toBe(true)
      expect(vars.has('y')).toBe(true)
      expect(vars.size).toBe(2)
    })

    it('should detect non-invertible functions', () => {
      const crcExpr: ConstraintExpr = {
        kind: 'func', name: 'CRC32', args: [{ kind: 'var', name: 'input' }],
      }
      expect(hasNonInvertible(crcExpr)).toBe(true)
    })

    it('should not flag invertible operations', () => {
      const addExpr: ConstraintExpr = {
        kind: 'binop', op: '+',
        left: { kind: 'var', name: 'x' },
        right: { kind: 'const', value: 5 },
      }
      expect(hasNonInvertible(addExpr)).toBe(false)
    })
  })

  describe('Z3 Script Generation', () => {
    // Replicated constraint-to-Z3 serialization
    interface ConstraintExpr {
      kind: string
      [key: string]: unknown
    }

    function exprToZ3py(e: ConstraintExpr): string {
      switch (e.kind) {
        case 'var': return e.name as string
        case 'const': return `BitVecVal(${e.value}, 32)`
        case 'binop': {
          const l = exprToZ3py(e.left as ConstraintExpr)
          const r = exprToZ3py(e.right as ConstraintExpr)
          const ops: Record<string, string> = {
            '+': '+', '-': '-', '*': '*', '^': '^', '&': '&', '|': '|',
            'ADD': '+', 'SUB': '-', 'MUL': '*', 'XOR': '^', 'AND': '&', 'OR': '|',
          }
          const op = ops[e.op as string] ?? String(e.op)
          return `(${l} ${op} ${r})`
        }
        default: return `UNKNOWN(${e.kind})`
      }
    }

    it('should serialize variable to Z3', () => {
      expect(exprToZ3py({ kind: 'var', name: 'r0' })).toBe('r0')
    })

    it('should serialize constant to Z3', () => {
      expect(exprToZ3py({ kind: 'const', value: 42 })).toBe('BitVecVal(42, 32)')
    })

    it('should serialize binary op to Z3', () => {
      const expr: ConstraintExpr = {
        kind: 'binop', op: 'XOR',
        left: { kind: 'var', name: 'r0' },
        right: { kind: 'const', value: 0xFF },
      }
      expect(exprToZ3py(expr)).toBe('(r0 ^ BitVecVal(255, 32))')
    })

    it('should handle nested expressions', () => {
      const expr: ConstraintExpr = {
        kind: 'binop', op: '+',
        left: {
          kind: 'binop', op: 'XOR',
          left: { kind: 'var', name: 'a' },
          right: { kind: 'var', name: 'b' },
        },
        right: { kind: 'const', value: 1 },
      }
      expect(exprToZ3py(expr)).toBe('((a ^ b) + BitVecVal(1, 32))')
    })
  })
})
