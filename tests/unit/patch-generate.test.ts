/**
 * Unit tests for patch.generate tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { PatchGenerateInputSchema } from '../../src/plugins/crackme/tools/patch-generate.js'

describe('patch.generate tool', () => {
  describe('Input validation', () => {
    test('should accept valid input with NOP patch', () => {
      const result = PatchGenerateInputSchema.safeParse({
        sample_id: 'sha256:abc123',
        patches: [{ address: '0x401234', type: 'nop', size: 2 }],
      })
      expect(result.success).toBe(true)
    })

    test('should accept valid input with jmp_always patch', () => {
      const result = PatchGenerateInputSchema.safeParse({
        sample_id: 'sha256:abc123',
        patches: [{ address: '0x401234', type: 'jmp_always' }],
      })
      expect(result.success).toBe(true)
    })

    test('should reject input without patches', () => {
      const result = PatchGenerateInputSchema.safeParse({ sample_id: 'sha256:abc123' })
      expect(result.success).toBe(false)
    })

    test('should reject empty patches array', () => {
      const result = PatchGenerateInputSchema.safeParse({
        sample_id: 'sha256:abc123',
        patches: [],
      })
      expect(result.success).toBe(false)
    })
  })
})
