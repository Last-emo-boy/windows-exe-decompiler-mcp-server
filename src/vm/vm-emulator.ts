/**
 * VM Emulator — concrete and symbolic execution of custom VM bytecodes.
 *
 * Supports:
 * - Concrete mode: evaluates actual numeric values
 * - Symbolic mode: builds expression trees, extracts CMP constraints
 * - Loop detection, self-modifying code, step tracing
 */

import type { OpcodeTable, OpcodeEntry } from './opcode-extractor.js'

// ---------------------------------------------------------------------------
// Expression IR (for symbolic mode)
// ---------------------------------------------------------------------------

export type SymbolicExpr =
  | { kind: 'const'; value: bigint }
  | { kind: 'var'; name: string }
  | { kind: 'binop'; op: string; left: SymbolicExpr; right: SymbolicExpr }
  | { kind: 'unary'; op: string; child: SymbolicExpr }
  | { kind: 'rotate'; dir: 'left' | 'right'; child: SymbolicExpr; bits: SymbolicExpr; width: number }
  | { kind: 'func'; name: string; args: SymbolicExpr[] }

export function constExpr(v: bigint | number): SymbolicExpr {
  return { kind: 'const', value: BigInt(v) }
}
export function varExpr(name: string): SymbolicExpr {
  return { kind: 'var', name }
}
export function binop(op: string, left: SymbolicExpr, right: SymbolicExpr): SymbolicExpr {
  return { kind: 'binop', op, left, right }
}
export function unary(op: string, child: SymbolicExpr): SymbolicExpr {
  return { kind: 'unary', op, child }
}
export function rotateExpr(dir: 'left' | 'right', child: SymbolicExpr, bits: SymbolicExpr, width: number): SymbolicExpr {
  return { kind: 'rotate', dir, child, bits, width }
}

export function exprToString(e: SymbolicExpr): string {
  switch (e.kind) {
    case 'const': return `0x${e.value.toString(16)}`
    case 'var': return e.name
    case 'binop': return `(${exprToString(e.left)} ${e.op} ${exprToString(e.right)})`
    case 'unary': return `(${e.op}${exprToString(e.child)})`
    case 'rotate': return `ROT${e.dir === 'left' ? 'L' : 'R'}(${exprToString(e.child)}, ${exprToString(e.bits)}, ${e.width})`
    case 'func': return `${e.name}(${e.args.map(exprToString).join(', ')})`
  }
}

// ---------------------------------------------------------------------------
// VM State
// ---------------------------------------------------------------------------

export type VMValue = bigint | SymbolicExpr

export interface VMFlags {
  zero: boolean
  carry: boolean
  sign: boolean
  overflow: boolean
}

export interface ExecutionStep {
  pc: number
  opcode: number
  mnemonic: string
  operands: number[]
  stateDelta: Record<string, string>
  constraintEmitted?: ExtractedConstraint
}

export interface ExtractedConstraint {
  leftExpr: string
  operator: string
  rightValue: string
  sourcePC: number
}

export interface VMState {
  registers: Map<string, VMValue>
  memory: Uint8Array
  pc: number
  flags: VMFlags
  trace: ExecutionStep[]
  constraints: ExtractedConstraint[]
  mode: 'concrete' | 'symbolic'
  bitWidth: number
}

export interface EmulateOptions {
  mode: 'concrete' | 'symbolic'
  maxSteps: number
  initialRegisters?: Record<string, bigint | string>
  bitWidth?: number
  memorySize?: number
}

export interface EmulationResult {
  trace: ExecutionStep[]
  finalRegisters: Record<string, string>
  constraints: ExtractedConstraint[]
  steps: number
  terminationReason: 'halt' | 'maxSteps' | 'loop' | 'outOfBounds' | 'unknownOpcode'
}

// ---------------------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------------------

export function createVMState(options: EmulateOptions): VMState {
  const bitWidth = options.bitWidth ?? 32
  const memSize = options.memorySize ?? 65536
  const regs = new Map<string, VMValue>()

  if (options.initialRegisters) {
    for (const [name, val] of Object.entries(options.initialRegisters)) {
      if (typeof val === 'string') {
        // symbolic variable
        regs.set(name, varExpr(val))
      } else {
        regs.set(name, options.mode === 'symbolic' ? varExpr(name) : val)
      }
    }
  }

  return {
    registers: regs,
    memory: new Uint8Array(memSize),
    pc: 0,
    flags: { zero: false, carry: false, sign: false, overflow: false },
    trace: [],
    constraints: [],
    mode: options.mode,
    bitWidth,
  }
}

function mask(bitWidth: number): bigint {
  return (1n << BigInt(bitWidth)) - 1n
}

function getConcreteValue(v: VMValue): bigint {
  if (typeof v === 'bigint') return v
  if (v.kind === 'const') return v.value
  return 0n // fallback for symbolic in concrete context
}

function resolveReg(state: VMState, name: string): VMValue {
  return state.registers.get(name) ?? (state.mode === 'symbolic' ? varExpr(name) : 0n)
}

function setReg(state: VMState, name: string, value: VMValue): void {
  state.registers.set(name, value)
}

function valueToString(v: VMValue): string {
  if (typeof v === 'bigint') return `0x${v.toString(16)}`
  return exprToString(v)
}

// ---------------------------------------------------------------------------
// Concrete Operations
// ---------------------------------------------------------------------------

function concreteOp(op: string, a: bigint, b: bigint, bw: number): bigint {
  const m = mask(bw)
  switch (op) {
    case 'ADD': return (a + b) & m
    case 'SUB': return (a - b + (1n << BigInt(bw))) & m
    case 'MUL': return (a * b) & m
    case 'DIV': return b !== 0n ? a / b : 0n
    case 'MOD': return b !== 0n ? a % b : 0n
    case 'XOR': return (a ^ b) & m
    case 'AND': return (a & b) & m
    case 'OR': return (a | b) & m
    case 'SHL': return (a << b) & m
    case 'SHR': return (a >> b) & m
    case 'ROL': {
      const shift = Number(b) % bw
      return ((a << BigInt(shift)) | (a >> BigInt(bw - shift))) & m
    }
    case 'ROR': {
      const shift = Number(b) % bw
      return ((a >> BigInt(shift)) | (a << BigInt(bw - shift))) & m
    }
    default: return a
  }
}

function concreteUnary(op: string, a: bigint, bw: number): bigint {
  const m = mask(bw)
  switch (op) {
    case 'NOT': return (~a) & m
    case 'NEG': return ((-a) + (1n << BigInt(bw))) & m
    case 'INC': return (a + 1n) & m
    case 'DEC': return (a - 1n + (1n << BigInt(bw))) & m
    default: return a
  }
}

// ---------------------------------------------------------------------------
// Symbolic Operations
// ---------------------------------------------------------------------------

function symbolicOp(op: string, a: VMValue, b: VMValue, bw: number): VMValue {
  const ae: SymbolicExpr = typeof a === 'bigint' ? constExpr(a) : a
  const be: SymbolicExpr = typeof b === 'bigint' ? constExpr(b) : b

  if (op === 'ROL' || op === 'ROR') {
    return rotateExpr(op === 'ROL' ? 'left' : 'right', ae, be, bw)
  }

  // Constant folding
  if (ae.kind === 'const' && be.kind === 'const') {
    return constExpr(concreteOp(op, ae.value, be.value, bw))
  }

  return binop(op, ae, be)
}

// ---------------------------------------------------------------------------
// Execute Single Step
// ---------------------------------------------------------------------------

function executeStep(
  state: VMState,
  entry: OpcodeEntry,
  operands: number[]
): void {
  const bw = state.bitWidth
  const delta: Record<string, string> = {}

  // Map operands to register names (r0, r1, ...) or immediate values
  const dstReg = operands.length > 0 ? `r${operands[0]}` : 'r0'
  const srcVal = operands.length > 1
    ? (operands[1] < 16 ? resolveReg(state, `r${operands[1]}`) : (state.mode === 'symbolic' ? constExpr(operands[1]) : BigInt(operands[1])))
    : (state.mode === 'symbolic' ? constExpr(0) : 0n)

  const cat = entry.semanticCategory
  const mnem = entry.mnemonic

  if (cat === 'arithmetic' || cat === 'logic' || cat === 'rotate') {
    const dst = resolveReg(state, dstReg)
    let result: VMValue
    if (state.mode === 'concrete') {
      result = concreteOp(mnem, getConcreteValue(dst), getConcreteValue(srcVal), bw)
    } else {
      result = symbolicOp(mnem, dst, srcVal, bw)
    }
    setReg(state, dstReg, result)
    delta[dstReg] = valueToString(result)
  } else if (mnem === 'NOT' || mnem === 'NEG' || mnem === 'INC' || mnem === 'DEC') {
    const dst = resolveReg(state, dstReg)
    if (state.mode === 'concrete') {
      const result = concreteUnary(mnem, getConcreteValue(dst), bw)
      setReg(state, dstReg, result)
      delta[dstReg] = valueToString(result)
    } else {
      const ae: SymbolicExpr = typeof dst === 'bigint' ? constExpr(dst) : dst
      const result = unary(mnem, ae)
      setReg(state, dstReg, result)
      delta[dstReg] = valueToString(result)
    }
  } else if (mnem === 'MOV' || mnem === 'LOAD') {
    setReg(state, dstReg, srcVal)
    delta[dstReg] = valueToString(srcVal)
  } else if (mnem === 'STORE') {
    const addr = operands.length > 0 ? operands[0] : 0
    const val = resolveReg(state, operands.length > 1 ? `r${operands[1]}` : 'r0')
    if (state.mode === 'concrete' && addr < state.memory.length) {
      state.memory[addr] = Number(getConcreteValue(val) & 0xFFn)
      delta[`mem[${addr}]`] = valueToString(val)
    }
  } else if (mnem === 'CMP' || mnem === 'TEST') {
    const dst = resolveReg(state, dstReg)
    if (state.mode === 'concrete') {
      const a = getConcreteValue(dst)
      const b = getConcreteValue(srcVal)
      state.flags.zero = a === b
      state.flags.carry = a < b
      state.flags.sign = ((a - b) & (1n << BigInt(bw - 1))) !== 0n
    }
    // Emit constraint in symbolic mode
    const constraint: ExtractedConstraint = {
      leftExpr: valueToString(dst),
      operator: mnem === 'TEST' ? '&' : '==',
      rightValue: valueToString(srcVal),
      sourcePC: state.pc,
    }
    state.constraints.push(constraint)
    delta['flags'] = `Z=${state.flags.zero ? 1 : 0}`
    // Return constraint to attach to step
    ;(delta as Record<string, unknown>)['__constraint'] = constraint
  } else if (mnem === 'JMP') {
    const target = operands.length > 0 ? operands[0] : 0
    state.pc = target
    delta['pc'] = `0x${target.toString(16)}`
    return // don't advance PC normally
  } else if (mnem === 'JZ') {
    if (state.flags.zero) {
      const target = operands.length > 0 ? operands[0] : 0
      state.pc = target
      delta['pc'] = `0x${target.toString(16)}`
      return
    }
  } else if (mnem === 'JNZ') {
    if (!state.flags.zero) {
      const target = operands.length > 0 ? operands[0] : 0
      state.pc = target
      delta['pc'] = `0x${target.toString(16)}`
      return
    }
  } else if (mnem === 'PUSH') {
    // stack operations — simplified
    const sp = getConcreteValue(resolveReg(state, 'sp'))
    const newSp = sp - BigInt(bw / 8)
    setReg(state, 'sp', state.mode === 'symbolic' ? constExpr(newSp) : newSp)
    delta['sp'] = `0x${newSp.toString(16)}`
  } else if (mnem === 'POP') {
    const sp = getConcreteValue(resolveReg(state, 'sp'))
    const newSp = sp + BigInt(bw / 8)
    setReg(state, 'sp', state.mode === 'symbolic' ? constExpr(newSp) : newSp)
    delta['sp'] = `0x${newSp.toString(16)}`
  }
  // NOP, HALT handled by caller
}

// ---------------------------------------------------------------------------
// Main Emulation Loop
// ---------------------------------------------------------------------------

export function emulate(
  bytecodes: Buffer | Uint8Array,
  table: OpcodeTable,
  options: EmulateOptions
): EmulationResult {
  const state = createVMState(options)

  // Build lookup
  const lookup = new Map<number, OpcodeEntry>()
  for (const e of table) lookup.set(e.value, e)

  const visitedPCs = new Set<number>()
  let steps = 0
  let terminationReason: EmulationResult['terminationReason'] = 'maxSteps'

  while (steps < options.maxSteps) {
    if (state.pc < 0 || state.pc >= bytecodes.length) {
      terminationReason = 'outOfBounds'
      break
    }

    // Loop detection
    if (visitedPCs.has(state.pc)) {
      // Allow revisiting a few times for loops, but bail after 3 cycles
      let count = 0
      for (const step of state.trace) {
        if (step.pc === state.pc) count++
      }
      if (count >= 3) {
        terminationReason = 'loop'
        break
      }
    }
    visitedPCs.add(state.pc)

    const opcode = bytecodes[state.pc]
    const entry = lookup.get(opcode)
    if (!entry) {
      terminationReason = 'unknownOpcode'
      break
    }

    // Read operands
    const operands: number[] = []
    let offset = 1
    for (const size of entry.operandSizes) {
      if (state.pc + offset + size > bytecodes.length) break
      let val = 0
      for (let i = 0; i < size; i++) {
        val |= bytecodes[state.pc + offset + i] << (i * 8)
      }
      operands.push(val)
      offset += size
    }

    const instrLen = 1 + entry.operandSizes.reduce((a, b) => a + b, 0)

    // Handle HALT before executing
    if (entry.mnemonic === 'HALT') {
      state.trace.push({
        pc: state.pc,
        opcode,
        mnemonic: 'HALT',
        operands,
        stateDelta: {},
      })
      terminationReason = 'halt'
      steps++
      break
    }

    const pcBefore = state.pc
    executeStep(state, entry, operands)

    const step: ExecutionStep = {
      pc: pcBefore,
      opcode,
      mnemonic: entry.mnemonic,
      operands,
      stateDelta: {},
    }

    // Capture constraint if emitted
    if (state.constraints.length > 0) {
      step.constraintEmitted = state.constraints[state.constraints.length - 1]
    }

    state.trace.push(step)
    steps++

    // If PC wasn't modified by a jump, advance it
    if (state.pc === pcBefore) {
      state.pc += instrLen
    }
  }

  // Build final register snapshot
  const finalRegisters: Record<string, string> = {}
  for (const [name, val] of state.registers) {
    finalRegisters[name] = valueToString(val)
  }

  return {
    trace: state.trace,
    finalRegisters,
    constraints: state.constraints,
    steps,
    terminationReason,
  }
}
