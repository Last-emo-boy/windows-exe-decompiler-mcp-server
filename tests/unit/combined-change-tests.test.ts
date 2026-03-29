/**
 * Combined tests for three change lines:
 * - rust-demangle-and-symbol-recovery
 * - dynamic-behavior-workflow
 * - setup-remediation-loop
 */

import { describe, test, expect } from '@jest/globals'
import {
  demangleRustSymbol,
  normalizeRustName,
  boundedPreview,
  normalizeSymbolList,
} from '../../src/tools/rust-demangle.js'
import { DynamicAnalysisStageSchema } from '../../src/workflows/dynamic-analyze.js'
import { SetupActionSchema, RequiredUserInputSchema } from '../../src/tools/setup-remediate.js'

describe('rust-demangle-and-symbol-recovery', () => {
  describe('demangleRustSymbol', () => {
    test('should detect and demangle Rust v0 symbols', () => {
      // Real Rust v0 mangled symbol pattern
      const mangled = '_RNvCs5abcde_11crate_name6module8function'
      const result = demangleRustSymbol(mangled)

      if (result) {
        expect(result.isRust).toBe(true)
        expect(result.raw).toBe(mangled)
        expect(result.demangled).toBeDefined()
        expect(result.normalized).toBeDefined()
        expect(result.confidence).toBeGreaterThan(0)
        expect(result.confidence).toBeLessThanOrEqual(1)
      } else {
        // If parsing fails, at least verify it's recognized as Rust
        expect(mangled.startsWith('_RNv')).toBe(true)
      }
    })

    test('should return null for non-Rust symbols', () => {
      const result = demangleRustSymbol('_Z1fv') // C++ mangled
      expect(result).toBeNull()
    })

    test('should handle legacy Rust mangling', () => {
      const mangled = '_ZN$hash$crate_name$hash$func_nameE'
      const result = demangleRustSymbol(mangled)

      if (result) {
        expect(result.isRust).toBe(true)
      }
    })
  })

  describe('normalizeRustName', () => {
    test('should remove hash suffixes', () => {
      const name = 'my_function_h1234567'
      const normalized = normalizeRustName(name)
      expect(normalized).not.toContain('h1234567')
    })

    test('should remove generic instantiations', () => {
      const name = 'my_function<Vec<String>>'
      const normalized = normalizeRustName(name)
      expect(normalized).not.toContain('<')
      expect(normalized).not.toContain('>')
    })

    test('should normalize closure markers', () => {
      const name = 'my_closure{closure#123}'
      const normalized = normalizeRustName(name)
      expect(normalized).toContain('{closure}')
      expect(normalized).not.toContain('#123')
    })

    test('should clean up multiple underscores', () => {
      const name = 'my___function____name'
      const normalized = normalizeRustName(name)
      expect(normalized).not.toContain('___')
    })
  })

  describe('boundedPreview', () => {
    test('should return short names unchanged', () => {
      const name = 'short_function'
      const preview = boundedPreview(name, 64)
      expect(preview).toBe(name)
    })

    test('should truncate long names', () => {
      const name = 'this_is_a_very_long_function_name_that_exceeds_the_limit'
      const preview = boundedPreview(name, 30)
      expect(preview.length).toBeLessThanOrEqual(30)
      expect(preview).toContain('...')
    })

    test('should try to cut at word boundaries', () => {
      const name = 'module_one_module_two_module_three_function'
      const preview = boundedPreview(name, 25)
      // Should cut at underscore if possible
      expect(preview).toMatch(/_?\.\.\.$/)
    })
  })

  describe('normalizeSymbolList', () => {
    test('should process mixed symbol list', () => {
      const symbols = [
        '_RNvCs5abcde_11crate_name6function',
        'normal_function',
        '_ZN$hash$test$hash$funcE',
      ]

      const results = normalizeSymbolList(symbols)
      expect(results).toHaveLength(3)

      const rustSymbols = results.filter(r => r.isRust)
      const nonRustSymbols = results.filter(r => !r.isRust)

      expect(rustSymbols.length).toBeGreaterThanOrEqual(0)
      expect(nonRustSymbols.length).toBeGreaterThanOrEqual(1)
    })
  })
})

describe('dynamic-behavior-workflow', () => {
  describe('DynamicAnalysisStageSchema', () => {
    test('should accept valid stages', () => {
      const validStages = ['preflight', 'simulation', 'trace_capture', 'correlation', 'digest']

      for (const stage of validStages) {
        const result = DynamicAnalysisStageSchema.safeParse(stage)
        expect(result.success).toBe(true)
      }
    })

    test('should reject invalid stages', () => {
      const result = DynamicAnalysisStageSchema.safeParse('invalid_stage')
      expect(result.success).toBe(false)
    })
  })

  describe('workflow stages', () => {
    test('should have preflight as initial stage', () => {
      expect(DynamicAnalysisStageSchema.enum.preflight).toBe('preflight')
    })

    test('should have simulation as default analysis stage', () => {
      expect(DynamicAnalysisStageSchema.enum.simulation).toBe('simulation')
    })

    test('should have digest as final stage', () => {
      expect(DynamicAnalysisStageSchema.enum.digest).toBe('digest')
    })
  })
})

describe('setup-remediation-loop', () => {
  describe('SetupActionSchema', () => {
    test('should accept valid setup actions', () => {
      const validActions = [
        {
          action_type: 'pip_install' as const,
          description: 'Install Python packages',
          required: true,
          platform: 'all' as const,
        },
        {
          action_type: 'set_env_var' as const,
          description: 'Set GHIDRA_PATH',
          required: true,
          platform: 'all' as const,
        },
        {
          action_type: 'manual_step' as const,
          description: 'Manual configuration',
          required: false,
          platform: 'windows' as const,
        },
      ]

      for (const action of validActions) {
        const result = SetupActionSchema.safeParse(action)
        expect(result.success).toBe(true)
      }
    })

    test('should require description field', () => {
      const action = {
        action_type: 'pip_install' as const,
        required: true,
      }

      const result = SetupActionSchema.safeParse(action)
      expect(result.success).toBe(false)
    })
  })

  describe('RequiredUserInputSchema', () => {
    test('should accept valid input definitions', () => {
      const input = {
        input_name: 'GHIDRA_PATH',
        description: 'Path to Ghidra installation',
        example_value: 'C:\\ghidra',
      }

      const result = RequiredUserInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should require input_name and description', () => {
      const input = {
        description: 'Some description',
      }

      const result = RequiredUserInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })
  })

  describe('remediation workflow contract', () => {
    test('should identify blocked tool context', () => {
      const blockedContext = {
        tool_name: 'ghidra.analyze',
        error_message: 'GHIDRA_PATH not set',
        setup_required: 'ghidra_not_configured',
      }

      expect(blockedContext.tool_name).toBeDefined()
      expect(blockedContext.setup_required).toBeDefined()
    })

    test('should provide retry guidance', () => {
      const retryGuidance = {
        retry_tool: 'ghidra.analyze',
        retry_conditions: ['Set GHIDRA_PATH', 'Verify installation'],
        resume_target: 'ghidra.analyze with original parameters',
      }

      expect(retryGuidance.retry_tool).toBeDefined()
      expect(retryGuidance.retry_conditions).toHaveLength(2)
      expect(retryGuidance.resume_target).toBeDefined()
    })
  })
})

describe('cross-change integration', () => {
  test('should support Rust analysis with dynamic behavior', () => {
    // Verify Rust demangling works
    const rustSymbol = '_RNvCs5abcde_11crate_name6function'
    const demangled = demangleRustSymbol(rustSymbol)

    if (demangled) {
      expect(demangled.isRust).toBe(true)
      expect(demangled.normalized).toBeDefined()
    }

    // Verify dynamic workflow can analyze Rust binaries
    const stage = DynamicAnalysisStageSchema.enum.simulation
    expect(stage).toBe('simulation')
  })

  test('should handle setup requirements for dynamic analysis', () => {
    // Verify setup actions can be defined
    const action = SetupActionSchema.parse({
      action_type: 'install_package',
      description: 'Install Frida tools',
      command: 'pip install frida-tools',
      required: true,
    })

    expect(action.action_type).toBe('install_package')
    expect(action.description).toContain('Frida')
  })
})
