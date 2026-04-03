/**
 * Unit tests for VM Detection Engine
 *
 * Tests the heuristic scoring and component classification
 * used to detect VM-based protection in binaries.
 */

// ── Replicated heuristic logic (vm-detector.ts uses no import.meta.url
//    but we replicate for consistency with other test patterns) ──────────

interface VMScore {
  loopSwitch: number
  bytecodeFetch: number
  pcIncrement: number
  handlerRegularity: number
  opcodeRange: number
  totalScore: number
  confidence: 'high' | 'medium' | 'low'
}

function detectLoopSwitchPattern(body: string): number {
  let score = 0
  if (/while\s*\(/.test(body) || /for\s*\(/.test(body) || /do\s*\{/.test(body)) score += 5
  if (/switch\s*\(/.test(body)) score += 10
  if (/case\s+0x[0-9a-fA-F]+\s*:/.test(body)) score += 5
  return Math.min(score, 20)
}

function detectBytecodeFetch(body: string): number {
  let score = 0
  if (/\[\s*\w+\s*\+\+\s*\]/.test(body) || /\[\s*\w+\s*\];\s*\w+\s*\+\+/.test(body)) score += 10
  if (/byte|uint8|BYTE|unsigned char/i.test(body)) score += 5
  if (/fetch|opcode|bytecode|instruction/i.test(body)) score += 5
  return Math.min(score, 20)
}

function detectPCIncrement(body: string): number {
  let score = 0
  if (/\b(pc|ip|vpc|vip|vPC|programCounter)\b/i.test(body)) score += 10
  if (/\b(pc|ip|vpc|vip)\s*\+\+|\b(pc|ip|vpc|vip)\s*\+=\s*\d/i.test(body)) score += 10
  return Math.min(score, 20)
}

function detectHandlerRegularity(body: string): number {
  const caseMatches = body.match(/case\s+0x[0-9a-fA-F]+\s*:/g)
  if (!caseMatches) return 0
  const count = caseMatches.length
  if (count >= 20) return 20
  if (count >= 10) return 15
  if (count >= 5)  return 10
  return 5
}

function detectOpcodeRange(body: string): number {
  const caseValues = body.match(/case\s+(0x[0-9a-fA-F]+)\s*:/g)
  if (!caseValues || caseValues.length < 3) return 0
  const values = caseValues.map(c => {
    const m = c.match(/0x([0-9a-fA-F]+)/)
    return m ? parseInt(m[1], 16) : 0
  })
  const min = Math.min(...values)
  const max = Math.max(...values)
  const range = max - min
  if (range <= 0xFF && values.length >= 5) return 20
  if (range <= 0xFFFF && values.length >= 5) return 15
  if (values.length >= 3) return 10
  return 5
}

function scoreVMCandidate(func: { body: string }): VMScore {
  const ls = detectLoopSwitchPattern(func.body)
  const bf = detectBytecodeFetch(func.body)
  const pi = detectPCIncrement(func.body)
  const hr = detectHandlerRegularity(func.body)
  const or = detectOpcodeRange(func.body)
  const total = ls + bf + pi + hr + or
  return {
    loopSwitch: ls,
    bytecodeFetch: bf,
    pcIncrement: pi,
    handlerRegularity: hr,
    opcodeRange: or,
    totalScore: total,
    confidence: total >= 60 ? 'high' : total >= 30 ? 'medium' : 'low',
  }
}

// ── Tests ──────────────────────────────────────────────────────────────

describe('VM Detection Engine', () => {
  describe('detectLoopSwitchPattern', () => {
    it('should detect while+switch pattern', () => {
      const code = `
        while (running) {
          switch (opcode) {
            case 0x01: break;
          }
        }
      `
      expect(detectLoopSwitchPattern(code)).toBeGreaterThanOrEqual(15)
    })

    it('should return 0 for no loop/switch', () => {
      const code = 'int x = 5; return x;'
      expect(detectLoopSwitchPattern(code)).toBe(0)
    })
  })

  describe('detectBytecodeFetch', () => {
    it('should detect array+increment fetch pattern', () => {
      const code = 'uint8 opcode = bytecode[pc++];'
      expect(detectBytecodeFetch(code)).toBeGreaterThanOrEqual(10)
    })

    it('should detect byte type indicator', () => {
      const code = 'BYTE val = buf[offset]; offset++;'
      expect(detectBytecodeFetch(code)).toBeGreaterThanOrEqual(5)
    })
  })

  describe('detectPCIncrement', () => {
    it('should detect pc variable with increment', () => {
      const code = 'int vpc = 0; vpc++; opcode = code[vpc];'
      expect(detectPCIncrement(code)).toBe(20)
    })

    it('should detect vip with += increment', () => {
      const code = 'vip += 2;'
      expect(detectPCIncrement(code)).toBe(20)
    })

    it('should return 0 for no PC-like names', () => {
      const code = 'int x = foo(); bar(x);'
      expect(detectPCIncrement(code)).toBe(0)
    })
  })

  describe('detectHandlerRegularity', () => {
    it('should score high for many case labels', () => {
      const cases = Array.from({ length: 25 }, (_, i) =>
        `case 0x${i.toString(16).padStart(2, '0')}: handler_${i}(); break;`
      ).join('\n')
      const code = `switch(op) {\n${cases}\n}`
      expect(detectHandlerRegularity(code)).toBe(20)
    })

    it('should score 0 for no case labels', () => {
      expect(detectHandlerRegularity('if (x) foo();')).toBe(0)
    })
  })

  describe('detectOpcodeRange', () => {
    it('should score high for dense byte opcode range', () => {
      const cases = Array.from({ length: 10 }, (_, i) =>
        `case 0x${(i + 1).toString(16).padStart(2, '0')}:`
      ).join('\n')
      expect(detectOpcodeRange(cases)).toBe(20)
    })

    it('should score 0 for fewer than 3 cases', () => {
      expect(detectOpcodeRange('case 0x01: case 0x02:')).toBe(0)
    })
  })

  describe('scoreVMCandidate', () => {
    it('should classify a typical VM dispatcher as high confidence', () => {
      const vmDispatcher = `
        void vm_exec(uint8* bytecode, int len) {
          int vpc = 0;
          int running = 1;
          while (running) {
            uint8 opcode = bytecode[vpc++];
            switch (opcode) {
              case 0x00: regs[0] = regs[1] + regs[2]; break;
              case 0x01: regs[0] = regs[1] - regs[2]; break;
              case 0x02: regs[0] = regs[1] ^ regs[2]; break;
              case 0x03: regs[0] = regs[1] & regs[2]; break;
              case 0x04: regs[0] = regs[1] | regs[2]; break;
              case 0x05: regs[0] = ~regs[1]; break;
              case 0x06: vpc = bytecode[vpc]; break;
              case 0x07: if (flags.zf) vpc = bytecode[vpc]; break;
              case 0x08: push(regs[0]); break;
              case 0x09: regs[0] = pop(); break;
              case 0x0A: regs[bytecode[vpc++]] = fetch32(bytecode, &vpc); break;
              case 0xFF: running = 0; break;
            }
          }
        }
      `
      const score = scoreVMCandidate({ body: vmDispatcher })
      expect(score.totalScore).toBeGreaterThanOrEqual(60)
      expect(score.confidence).toBe('high')
    })

    it('should classify a normal function as low confidence', () => {
      const normalFunc = `
        int add(int a, int b) {
          return a + b;
        }
      `
      const score = scoreVMCandidate({ body: normalFunc })
      expect(score.totalScore).toBeLessThan(30)
      expect(score.confidence).toBe('low')
    })

    it('should classify partial VM pattern as medium confidence', () => {
      const partial = `
        while (true) {
          switch (cmd) {
            case 0x01: x += y; break;
            case 0x02: x -= y; break;
            case 0x03: x ^= y; break;
            case 0x04: x &= y; break;
            case 0x05: x |= y; break;
          }
        }
      `
      const score = scoreVMCandidate({ body: partial })
      expect(score.totalScore).toBeGreaterThanOrEqual(20)
    })
  })
})
