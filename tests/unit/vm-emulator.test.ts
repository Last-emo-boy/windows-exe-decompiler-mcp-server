/**
 * Unit tests for VM Emulator — concrete and symbolic execution
 */

// ── Replicated types & logic from vm-emulator.ts ────────────────────

type SymbolicExpr =
  | { kind: 'const'; value: bigint }
  | { kind: 'var'; name: string }
  | { kind: 'binop'; op: string; left: SymbolicExpr; right: SymbolicExpr }
  | { kind: 'unary'; op: string; child: SymbolicExpr }
  | { kind: 'rotate'; dir: 'left' | 'right'; child: SymbolicExpr; bits: SymbolicExpr; width: number }

interface VMValue {
  concrete: bigint
  symbolic?: SymbolicExpr
}

interface VMFlags {
  zero: boolean
  carry: boolean
  sign: boolean
}

interface ExecutionStep {
  pc: number
  mnemonic: string
  operands: number[]
  regsBefore: Map<string, VMValue>
  regsAfter: Map<string, VMValue>
  flags: VMFlags
  constraintEmitted?: { leftExpr: SymbolicExpr; operator: string; rightExpr: SymbolicExpr; raw: string }
}

interface VMState {
  registers: Map<string, VMValue>
  memory: Map<number, VMValue>
  stack: VMValue[]
  pc: number
  flags: VMFlags
  halted: boolean
}

function constExpr(v: bigint): SymbolicExpr { return { kind: 'const', value: v } }
function varExpr(n: string): SymbolicExpr { return { kind: 'var', name: n } }
function binop(op: string, l: SymbolicExpr, r: SymbolicExpr): SymbolicExpr { return { kind: 'binop', op, left: l, right: r } }

function exprToString(e: SymbolicExpr): string {
  switch (e.kind) {
    case 'const': return `0x${e.value.toString(16)}`
    case 'var':   return e.name
    case 'binop': return `(${exprToString(e.left)} ${e.op} ${exprToString(e.right)})`
    case 'unary': return `${e.op}(${exprToString(e.child)})`
    case 'rotate': return `rot${e.dir === 'left' ? 'l' : 'r'}(${exprToString(e.child)}, ${exprToString(e.bits)}, ${e.width})`
  }
}

function createVMState(): VMState {
  return {
    registers: new Map(),
    memory: new Map(),
    stack: [],
    pc: 0,
    flags: { zero: false, carry: false, sign: false },
    halted: false,
  }
}

function mask(value: bigint, bitWidth: number): bigint {
  return value & ((1n << BigInt(bitWidth)) - 1n)
}

function concreteOp(op: string, a: bigint, b: bigint, bitWidth: number): bigint {
  const m = (1n << BigInt(bitWidth)) - 1n
  switch (op) {
    case 'ADD': return (a + b) & m
    case 'SUB': return (a - b) & m
    case 'MUL': return (a * b) & m
    case 'XOR': return (a ^ b) & m
    case 'AND': return (a & b) & m
    case 'OR':  return (a | b) & m
    case 'SHL': return (a << b) & m
    case 'SHR': return (a >> b) & m
    case 'ROL': {
      const bits = b % BigInt(bitWidth)
      return ((a << bits) | (a >> (BigInt(bitWidth) - bits))) & m
    }
    case 'ROR': {
      const bits = b % BigInt(bitWidth)
      return ((a >> bits) | (a << (BigInt(bitWidth) - bits))) & m
    }
    default: return a
  }
}

// ── Tests ──────────────────────────────────────────────────────────────

describe('VM Emulator', () => {
  describe('concrete operations', () => {
    it('should compute ADD correctly', () => {
      expect(concreteOp('ADD', 10n, 20n, 32)).toBe(30n)
    })

    it('should handle overflow with mask', () => {
      expect(concreteOp('ADD', 0xFFFFFFFFn, 1n, 32)).toBe(0n)
    })

    it('should compute SUB correctly', () => {
      expect(concreteOp('SUB', 20n, 10n, 32)).toBe(10n)
    })

    it('should compute XOR correctly', () => {
      expect(concreteOp('XOR', 0xAAn, 0x55n, 8)).toBe(0xFFn)
    })

    it('should compute AND correctly', () => {
      expect(concreteOp('AND', 0xFFn, 0x0Fn, 8)).toBe(0x0Fn)
    })

    it('should compute SHL correctly', () => {
      expect(concreteOp('SHL', 1n, 4n, 32)).toBe(16n)
    })

    it('should compute SHR correctly', () => {
      expect(concreteOp('SHR', 16n, 4n, 32)).toBe(1n)
    })

    it('should compute ROL correctly (32-bit)', () => {
      expect(concreteOp('ROL', 0x80000001n, 1n, 32)).toBe(0x00000003n)
    })

    it('should compute ROR correctly (32-bit)', () => {
      expect(concreteOp('ROR', 0x00000003n, 1n, 32)).toBe(0x80000001n)
    })

    it('should compute MUL correctly', () => {
      expect(concreteOp('MUL', 100n, 200n, 32)).toBe(20000n)
    })
  })

  describe('symbolic expression building', () => {
    it('should build simple expressions', () => {
      const expr = binop('ADD', varExpr('r0'), constExpr(5n))
      expect(exprToString(expr)).toBe('(r0 ADD 0x5)')
    })

    it('should build nested expressions', () => {
      const inner = binop('XOR', varExpr('r0'), varExpr('r1'))
      const outer = binop('ADD', inner, constExpr(1n))
      expect(exprToString(outer)).toBe('((r0 XOR r1) ADD 0x1)')
    })
  })

  describe('VMState', () => {
    it('should create empty state', () => {
      const state = createVMState()
      expect(state.pc).toBe(0)
      expect(state.halted).toBe(false)
      expect(state.stack.length).toBe(0)
      expect(state.registers.size).toBe(0)
    })

    it('should track register values', () => {
      const state = createVMState()
      state.registers.set('r0', { concrete: 42n })
      expect(state.registers.get('r0')!.concrete).toBe(42n)
    })

    it('should track flags', () => {
      const state = createVMState()
      state.flags.zero = true
      expect(state.flags.zero).toBe(true)
    })
  })

  describe('mask function', () => {
    it('should mask to 8 bits', () => {
      expect(mask(0x1FFn, 8)).toBe(0xFFn)
    })

    it('should mask to 16 bits', () => {
      expect(mask(0x1FFFFn, 16)).toBe(0xFFFFn)
    })

    it('should mask to 32 bits', () => {
      expect(mask(0x1FFFFFFFFn, 32)).toBe(0xFFFFFFFFn)
    })
  })
})
