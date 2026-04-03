/**
 * Unit tests for rust.demangle utility
 */

import { describe, test, expect } from '@jest/globals'
import { demangleRustSymbol, normalizeRustName, boundedPreview, normalizeSymbolList } from '../../src/tools/rust-demangle.js'

describe('rust.demangle utility', () => {
  describe('demangleRustSymbol', () => {
    test('should be a function', () => {
      expect(typeof demangleRustSymbol).toBe('function')
    })
  })

  describe('normalizeRustName', () => {
    test('should be a function', () => {
      expect(typeof normalizeRustName).toBe('function')
    })
  })

  describe('boundedPreview', () => {
    test('should be a function', () => {
      expect(typeof boundedPreview).toBe('function')
    })
  })

  describe('normalizeSymbolList', () => {
    test('should be a function', () => {
      expect(typeof normalizeSymbolList).toBe('function')
    })
  })
})
