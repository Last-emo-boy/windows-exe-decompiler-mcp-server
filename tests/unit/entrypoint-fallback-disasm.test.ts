/**
 * Unit tests for entrypoint.fallback.disasm utility
 */

import { describe, test, expect } from '@jest/globals'
import { runEntrypointFallbackDisasm } from '../../src/tools/entrypoint-fallback-disasm.js'

describe('entrypoint.fallback.disasm utility', () => {
  describe('runEntrypointFallbackDisasm', () => {
    test('should be a function', () => {
      expect(typeof runEntrypointFallbackDisasm).toBe('function')
    })
  })
})
