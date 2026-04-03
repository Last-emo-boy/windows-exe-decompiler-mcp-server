/**
 * Keygen Synthesizer — analyzes constraint dependency chains and generates
 * forward-computable keygen code (Python).
 *
 * Detects when constraints form a forward chain (s0 → s1 → ... → sN)
 * that can be solved sequentially without SMT, and flags non-invertible
 * operations (hash, CRC) that require brute-force.
 */

import type { Constraint, ConstraintExpr } from './constraint-extractor.js'
import { exprToString } from './constraint-extractor.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DependencyNode {
  variable: string
  dependsOn: string[]
  constraint?: Constraint
  assignedValue?: string
  needsBruteForce: boolean
  reason?: string
}

export interface KeygenResult {
  feasible: boolean
  forwardComputable: boolean
  dependencyOrder: string[]
  nodes: DependencyNode[]
  pythonCode: string
  bruteForceVars: string[]
  notes: string[]
}

// ---------------------------------------------------------------------------
// Dependency Analysis
// ---------------------------------------------------------------------------

/**
 * Collect all variable names from a constraint expression.
 */
function collectVars(e: ConstraintExpr): Set<string> {
  const vars = new Set<string>()
  function walk(node: ConstraintExpr): void {
    switch (node.kind) {
      case 'var': vars.add(node.name); break
      case 'const': break
      case 'binop': walk(node.left); walk(node.right); break
      case 'unary': walk(node.child); break
      case 'rotate': walk(node.child); walk(node.bits); break
      case 'func': node.args.forEach(walk); break
    }
  }
  walk(e)
  return vars
}

/**
 * Check if an expression contains non-invertible operations.
 */
function hasNonInvertible(e: ConstraintExpr): { has: boolean; reason: string } {
  switch (e.kind) {
    case 'func': {
      const nonInv = ['CRC16', 'CRC32', 'MD5', 'SHA1', 'SHA256', 'HASH']
      if (nonInv.some(n => e.name.toUpperCase().includes(n))) {
        return { has: true, reason: `Non-invertible function: ${e.name}` }
      }
      break
    }
    case 'binop': {
      const left = hasNonInvertible(e.left)
      if (left.has) return left
      return hasNonInvertible(e.right)
    }
    case 'unary': return hasNonInvertible(e.child)
    case 'rotate': return hasNonInvertible(e.child)
    default: break
  }
  return { has: false, reason: '' }
}

/**
 * Build a dependency graph from constraints.
 * Each constraint: leftExpr == rightExpr → the variable(s) in leftExpr
 * depend on variable(s) in rightExpr.
 */
function buildDependencyGraph(constraints: Constraint[]): DependencyNode[] {
  const nodes: DependencyNode[] = []
  const seen = new Set<string>()

  for (const c of constraints) {
    const leftVars = collectVars(c.leftExpr)
    const rightVars = collectVars(c.rightExpr)

    // Primary variable: the main variable being constrained
    for (const v of leftVars) {
      if (seen.has(v)) continue
      seen.add(v)

      const deps = new Set<string>()
      // Depends on all other variables in the left expression
      for (const lv of leftVars) {
        if (lv !== v) deps.add(lv)
      }
      // If right is a constant, this variable can be assigned directly
      const rightIsConst = rightVars.size === 0

      const nonInv = hasNonInvertible(c.leftExpr)

      nodes.push({
        variable: v,
        dependsOn: [...deps],
        constraint: c,
        assignedValue: rightIsConst ? exprToString(c.rightExpr) : undefined,
        needsBruteForce: nonInv.has,
        reason: nonInv.has ? nonInv.reason : undefined,
      })
    }
  }

  return nodes
}

/**
 * Topological sort of dependency nodes.
 * Returns variable names in dependency order (independent first).
 */
function topologicalSort(nodes: DependencyNode[]): string[] {
  const nodeMap = new Map<string, DependencyNode>()
  for (const n of nodes) nodeMap.set(n.variable, n)

  const visited = new Set<string>()
  const order: string[] = []

  function visit(name: string): void {
    if (visited.has(name)) return
    visited.add(name)
    const node = nodeMap.get(name)
    if (node) {
      for (const dep of node.dependsOn) {
        visit(dep)
      }
    }
    order.push(name)
  }

  for (const n of nodes) visit(n.variable)
  return order
}

// ---------------------------------------------------------------------------
// Keygen Code Generation
// ---------------------------------------------------------------------------

function constraintExprToPython(e: ConstraintExpr): string {
  switch (e.kind) {
    case 'var': return e.name
    case 'const': return `0x${e.value.toString(16)}`
    case 'binop': {
      const l = constraintExprToPython(e.left)
      const r = constraintExprToPython(e.right)
      const pyOp: Record<string, string> = {
        '+': '+', '-': '-', '*': '*', '/': '//', '%': '%',
        '^': '^', '&': '&', '|': '|', '<<': '<<', '>>': '>>',
        'ADD': '+', 'SUB': '-', 'MUL': '*', 'XOR': '^',
        'AND': '&', 'OR': '|', 'SHL': '<<', 'SHR': '>>',
      }
      return `(${l} ${pyOp[e.op] ?? e.op} ${r})`
    }
    case 'unary': {
      const c = constraintExprToPython(e.child)
      if (e.op === 'NOT' || e.op === '~') return `(~${c})`
      if (e.op === 'NEG' || e.op === '-') return `(-${c})`
      return `${e.op}(${c})`
    }
    case 'rotate': {
      const c = constraintExprToPython(e.child)
      const b = constraintExprToPython(e.bits)
      const m = `0x${'F'.repeat(e.width / 4)}`
      if (e.dir === 'left') {
        return `(((${c} << ${b}) | (${c} >> (${e.width} - ${b}))) & ${m})`
      }
      return `(((${c} >> ${b}) | (${c} << (${e.width} - ${b}))) & ${m})`
    }
    case 'func': {
      const args = e.args.map(constraintExprToPython).join(', ')
      return `${e.name}(${args})`
    }
  }
}

/**
 * Synthesize a Python keygen from constraints.
 */
export function synthesizeKeygen(
  constraints: Constraint[],
  bitWidth = 32
): KeygenResult {
  const notes: string[] = []
  const graph = buildDependencyGraph(constraints)
  const order = topologicalSort(graph)
  const bruteForceVars = graph.filter(n => n.needsBruteForce).map(n => n.variable)

  const forwardComputable = bruteForceVars.length === 0
  if (bruteForceVars.length > 0) {
    notes.push(`Variables requiring brute-force: ${bruteForceVars.join(', ')}`)
  }

  // Generate Python code
  const mask = `0x${'F'.repeat(bitWidth / 4)}`
  const lines: string[] = [
    '#!/usr/bin/env python3',
    '"""Auto-generated keygen from constraint analysis."""',
    '',
    `MASK = ${mask}`,
    '',
  ]

  // Helper functions
  lines.push('def rol(val, bits, width):')
  lines.push('    bits = bits % width')
  lines.push('    return ((val << bits) | (val >> (width - bits))) & ((1 << width) - 1)')
  lines.push('')
  lines.push('def ror(val, bits, width):')
  lines.push('    bits = bits % width')
  lines.push('    return ((val >> bits) | (val << (width - bits))) & ((1 << width) - 1)')
  lines.push('')

  lines.push('def keygen():')

  const nodeMap = new Map<string, DependencyNode>()
  for (const n of graph) nodeMap.set(n.variable, n)

  for (const varName of order) {
    const node = nodeMap.get(varName)
    if (!node) continue

    if (node.assignedValue) {
      lines.push(`    ${varName} = ${node.assignedValue}  # directly constrained`)
    } else if (node.constraint) {
      // Try to express as forward computation
      const expr = constraintExprToPython(node.constraint.rightExpr)
      if (node.needsBruteForce) {
        lines.push(`    # WARNING: ${node.reason}`)
        lines.push(`    # ${varName} requires brute-force or SMT solving`)
        lines.push(`    # Attempting brute-force search over the valid range`)
        const depsList = node.dependsOn.length > 0 ? node.dependsOn.join(', ') : ''
        const checkExpr = node.constraint ? constraintExprToPython(node.constraint.rightExpr) : '0'
        lines.push(`    for _candidate in range(0, min(0x10000, MASK + 1)):`)
        lines.push(`        ${varName} = _candidate`)
        lines.push(`        if (${checkExpr}) & MASK == (${varName}) & MASK:`)
        lines.push(`            break`)
        lines.push(`    else:`)
        lines.push(`        ${varName} = 0  # brute-force exhausted; consider SMT (z3) for wider ranges`)
      } else {
        lines.push(`    ${varName} = (${expr}) & MASK`)
      }
    }
  }

  lines.push('')
  lines.push(`    return {${order.map(v => `'${v}': ${v}`).join(', ')}}`)
  lines.push('')
  lines.push('if __name__ == "__main__":')
  lines.push('    result = keygen()')
  lines.push('    for k, v in result.items():')
  lines.push('        print(f"{k} = 0x{v:0' + `${bitWidth / 4}` + 'x}")')

  return {
    feasible: true,
    forwardComputable,
    dependencyOrder: order,
    nodes: graph,
    pythonCode: lines.join('\n'),
    bruteForceVars,
    notes,
  }
}
