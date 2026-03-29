/**
 * Unit tests for setup-guidance helpers (Frida-focused)
 */

import { describe, test, expect } from '@jest/globals'
import {
  SetupActionSchema,
  RequiredUserInputSchema,
  buildCoreLinuxToolchainSetupActions,
  buildDynamicDependencyRequiredUserInputs,
  buildHeavyBackendSetupActions,
  buildFridaSetupActions,
  buildFridaRequiredUserInputs,
  buildDynamicDependencySetupActions,
  mergeSetupActions,
  mergeRequiredUserInputs,
  inferSetupGuidanceFromMessages,
  collectSetupGuidanceFromWorkerResult,
} from '../../src/setup-guidance.js'

describe('SetupActionSchema', () => {
  test('should accept valid setup action with all fields', () => {
    const input = {
      id: 'install_frida',
      required: false,
      kind: 'pip_install' as const,
      title: 'Install Frida',
      summary: 'Install Frida runtime for dynamic instrumentation',
      command: 'python -m pip install frida',
      env_var: null,
      value_hint: null,
      examples: ['python -m pip install frida'],
      applies_to: ['frida.runtime.instrument', 'system.health'],
    }

    const result = SetupActionSchema.parse(input)
    expect(result.id).toBe('install_frida')
    expect(result.kind).toBe('pip_install')
    expect(result.examples).toHaveLength(1)
  })

  test('should accept minimal setup action', () => {
    const input = {
      id: 'verify_frida',
      required: false,
      kind: 'verify_install' as const,
      title: 'Verify Frida',
      summary: 'Verify Frida installation',
    }

    const result = SetupActionSchema.parse(input)
    expect(result.id).toBe('verify_frida')
    expect(result.examples).toEqual([])
    expect(result.applies_to).toEqual([])
  })

  test('should accept all valid action kinds', () => {
    const validKinds = ['pip_install', 'install_package', 'set_env', 'provide_path', 'verify_install']

    validKinds.forEach((kind) => {
      const input = {
        id: `test_${kind}`,
        required: false,
        kind: kind as any,
        title: 'Test',
        summary: 'Test',
      }
      const result = SetupActionSchema.parse(input)
      expect(result.kind).toBe(kind)
    })
  })

  test('should reject invalid kind', () => {
    const input = {
      id: 'test_invalid',
      required: false,
      kind: 'invalid_kind',
      title: 'Test',
      summary: 'Test',
    }
    expect(() => SetupActionSchema.parse(input)).toThrow()
  })
})

describe('RequiredUserInputSchema', () => {
  test('should accept valid required user input', () => {
    const input = {
      key: 'frida_path',
      label: 'Frida server binary path',
      summary: 'Path to Frida server',
      required: false,
      env_vars: ['FRIDA_PATH'],
      examples: ['C:\\frida-server'],
    }

    const result = RequiredUserInputSchema.parse(input)
    expect(result.key).toBe('frida_path')
    expect(result.env_vars).toHaveLength(1)
    expect(result.examples).toHaveLength(1)
  })

  test('should accept minimal required user input', () => {
    const input = {
      key: 'frida_script_root',
      label: 'Frida scripts directory',
      summary: 'Path to custom scripts',
      required: false,
    }

    const result = RequiredUserInputSchema.parse(input)
    expect(result.key).toBe('frida_script_root')
    expect(result.env_vars).toEqual([])
    expect(result.examples).toEqual([])
  })
})

describe('buildFridaSetupActions', () => {
  test('should return Frida-specific setup actions', () => {
    const actions = buildFridaSetupActions()

    expect(actions.length).toBeGreaterThan(0)
    expect(actions.map((a) => a.id)).toContain('install_frida_runtime')
    expect(actions.map((a) => a.id)).toContain('install_frida_tools_package')
    expect(actions.map((a) => a.id)).toContain('verify_frida_install')
    expect(actions.map((a) => a.id)).toContain('set_frida_script_root')
  })

  test('should have correct structure for each action', () => {
    const actions = buildFridaSetupActions()

    actions.forEach((action) => {
      expect(action.id).toBeDefined()
      expect(typeof action.required).toBe('boolean')
      expect(['pip_install', 'set_env', 'provide_path', 'verify_install']).toContain(action.kind)
      expect(typeof action.title).toBe('string')
      expect(typeof action.summary).toBe('string')
      expect(Array.isArray(action.examples)).toBe(true)
      expect(Array.isArray(action.applies_to)).toBe(true)
    })
  })

  test('should include pip_install actions with command', () => {
    const actions = buildFridaSetupActions()
    const pipActions = actions.filter((a) => a.kind === 'pip_install')

    pipActions.forEach((action) => {
      expect(action.command).toBeDefined()
      expect(action.command?.includes('pip install')).toBe(true)
    })
  })

  test('should include set_env actions with env_var', () => {
    const actions = buildFridaSetupActions()
    const envActions = actions.filter((a) => a.kind === 'set_env')

    envActions.forEach((action) => {
      expect(action.env_var).toBeDefined()
    })
  })
})

describe('buildFridaRequiredUserInputs', () => {
  test('should return Frida-specific required user inputs', () => {
    const inputs = buildFridaRequiredUserInputs()

    expect(inputs.length).toBeGreaterThan(0)
    const keys = inputs.map((i) => i.key)
    expect(keys).toContain('frida_path')
    expect(keys).toContain('frida_script_root')
  })

  test('should have correct structure for each input', () => {
    const inputs = buildFridaRequiredUserInputs()

    inputs.forEach((input) => {
      expect(input.key).toBeDefined()
      expect(typeof input.label).toBe('string')
      expect(typeof input.summary).toBe('string')
      expect(typeof input.required).toBe('boolean')
      expect(Array.isArray(input.env_vars)).toBe(true)
      expect(Array.isArray(input.examples)).toBe(true)
    })
  })
})

describe('buildDynamicDependencySetupActions', () => {
  test('should include Frida-related actions', () => {
    const actions = buildDynamicDependencySetupActions()
    const actionIds = actions.map((a) => a.id)

    expect(actionIds).toContain('install_frida')
    expect(actionIds).toContain('install_frida_tools')
    expect(actionIds).toContain('install_speakeasy_emulator')
    expect(actionIds).toContain('install_psutil')
  })

  test('should have commands for pip_install actions', () => {
    const actions = buildDynamicDependencySetupActions()
    const pipActions = actions.filter((a) => a.kind === 'pip_install')

    pipActions.forEach((action) => {
      expect(action.command).toBeDefined()
      expect(action.command?.includes('pip install')).toBe(true)
    })
  })
})

describe('buildCoreLinuxToolchainSetupActions', () => {
  test('should include Linux core toolchain actions', () => {
    const actions = buildCoreLinuxToolchainSetupActions()
    const actionIds = actions.map((a) => a.id)

    expect(actionIds).toContain('install_graphviz_package')
    expect(actionIds).toContain('install_rizin_package')
    expect(actionIds).toContain('install_yarax_package')
    expect(actionIds).toContain('install_upx_package')
    expect(actionIds).toContain('install_wine_package')
    expect(actionIds).toContain('install_frida_tools_cli')
  })
})

describe('buildDynamicDependencyRequiredUserInputs', () => {
  test('should include Qiling rootfs input', () => {
    const inputs = buildDynamicDependencyRequiredUserInputs()
    expect(inputs.map((item) => item.key)).toContain('qiling_rootfs_path')
  })
})

describe('buildHeavyBackendSetupActions', () => {
  test('should include RetDec actions', () => {
    const actions = buildHeavyBackendSetupActions()
    expect(actions.map((item) => item.id)).toContain('install_retdec_backend')
    expect(actions.map((item) => item.id)).toContain('set_retdec_path')
    expect(actions.map((item) => item.id)).toContain('verify_retdec_install')
  })
})

describe('mergeSetupActions', () => {
  test('should merge multiple action groups without duplicates', () => {
    const group1 = [
      { id: 'action1', required: true, kind: 'pip_install' as const, title: 'A1', summary: 'S1', examples: [], applies_to: [] },
      { id: 'action2', required: false, kind: 'set_env' as const, title: 'A2', summary: 'S2', examples: [], applies_to: [] },
    ]
    const group2 = [
      { id: 'action2', required: true, kind: 'set_env' as const, title: 'A2 Updated', summary: 'S2 Updated', examples: [], applies_to: [] },
      { id: 'action3', required: false, kind: 'verify_install' as const, title: 'A3', summary: 'S3', examples: [], applies_to: [] },
    ]

    const merged = mergeSetupActions(group1, group2)

    expect(merged.length).toBe(3)
    expect(merged.map((a) => a.id)).toContain('action1')
    expect(merged.map((a) => a.id)).toContain('action2')
    expect(merged.map((a) => a.id)).toContain('action3')

    // group2 should override group1 for action2
    const action2 = merged.find((a) => a.id === 'action2')
    expect(action2?.title).toBe('A2 Updated')
  })

  test('should handle empty groups', () => {
    const merged = mergeSetupActions([], [])
    expect(merged.length).toBe(0)
  })

  test('should handle single group', () => {
    const group = [
      { id: 'solo', required: true, kind: 'pip_install' as const, title: 'Solo', summary: 'Solo', examples: [], applies_to: [] },
    ]
    const merged = mergeSetupActions(group)
    expect(merged.length).toBe(1)
    expect(merged[0].id).toBe('solo')
  })
})

describe('mergeRequiredUserInputs', () => {
  test('should merge multiple input groups without duplicates', () => {
    const group1 = [
      { key: 'input1', label: 'I1', summary: 'S1', required: true, env_vars: [], examples: [] },
      { key: 'input2', label: 'I2', summary: 'S2', required: false, env_vars: [], examples: [] },
    ]
    const group2 = [
      { key: 'input2', label: 'I2 Updated', summary: 'S2 Updated', required: true, env_vars: [], examples: [] },
      { key: 'input3', label: 'I3', summary: 'S3', required: false, env_vars: [], examples: [] },
    ]

    const merged = mergeRequiredUserInputs(group1, group2)

    expect(merged.length).toBe(3)
    expect(merged.map((i) => i.key)).toContain('input1')
    expect(merged.map((i) => i.key)).toContain('input2')
    expect(merged.map((i) => i.key)).toContain('input3')

    // group2 should override group1 for input2
    const input2 = merged.find((i) => i.key === 'input2')
    expect(input2?.label).toBe('I2 Updated')
  })

  test('should handle empty groups', () => {
    const merged = mergeRequiredUserInputs([], [])
    expect(merged.length).toBe(0)
  })
})

describe('inferSetupGuidanceFromMessages', () => {
  test('should infer Frida setup actions from ModuleNotFoundError', () => {
    const messages = ['ModuleNotFoundError: No module named frida']
    const result = inferSetupGuidanceFromMessages(messages)

    expect(result.setupActions.length).toBeGreaterThan(0)
    expect(result.setupActions.map((a) => a.id)).toContain('install_frida_runtime')
  })

  test('should infer Frida setup actions from frida-related errors', () => {
    const messages = ['Error: frida is not installed', 'pip install frida']
    const result = inferSetupGuidanceFromMessages(messages)

    expect(result.setupActions.map((a) => a.id)).toContain('install_frida_runtime')
    expect(result.requiredUserInputs.map((i) => i.key)).toContain('frida_path')
  })

  test('should infer Linux full-stack setup actions from Docker toolchain errors', () => {
    const messages = ['Graphviz not found', 'qiling module missing', 'retdec-decompiler unavailable']
    const result = inferSetupGuidanceFromMessages(messages)

    expect(result.setupActions.map((a) => a.id)).toContain('install_graphviz_package')
    expect(result.setupActions.map((a) => a.id)).toContain('install_qiling_runtime')
    expect(result.setupActions.map((a) => a.id)).toContain('install_retdec_backend')
    expect(result.requiredUserInputs.map((i) => i.key)).toContain('qiling_rootfs_path')
  })

  test('should infer Ghidra setup actions from Ghidra-related messages', () => {
    const messages = ['analyzeHeadless.bat not found', 'GHIDRA_PATH not set']
    const result = inferSetupGuidanceFromMessages(messages)

    expect(result.setupActions.map((a) => a.id)).toContain('set_ghidra_path')
    expect(result.requiredUserInputs.map((i) => i.key)).toContain('ghidra_install_dir')
  })

  test('should infer Java setup actions from Java-related errors', () => {
    const messages = ['UnsupportedClassVersionError', 'JAVA_HOME not configured']
    const result = inferSetupGuidanceFromMessages(messages)

    expect(result.setupActions.map((a) => a.id)).toContain('install_java_21')
    expect(result.requiredUserInputs.map((i) => i.key)).toContain('java_home')
  })

  test('should infer static analysis setup actions from Python worker errors', () => {
    const messages = ['python worker failed', 'no module named pefile']
    const result = inferSetupGuidanceFromMessages(messages)

    expect(result.setupActions.map((a) => a.id)).toContain('install_pefile')
    expect(result.setupActions.map((a) => a.id)).toContain('install_lief')
  })

  test('should infer capa rules path from capa-related messages', () => {
    const messages = ['CAPA_RULES_PATH not found', 'capa rules directory missing']
    const result = inferSetupGuidanceFromMessages(messages)

    expect(result.setupActions.map((a) => a.id)).toContain('set_capa_rules_path')
    expect(result.requiredUserInputs.map((i) => i.key)).toContain('capa_rules_path')
  })

  test('should infer DIE path from Detect It Easy-related messages', () => {
    const messages = ['diec.exe not found', 'DIE_PATH environment variable missing']
    const result = inferSetupGuidanceFromMessages(messages)

    expect(result.setupActions.map((a) => a.id)).toContain('set_die_path')
    expect(result.requiredUserInputs.map((i) => i.key)).toContain('die_path')
  })

  test('should handle empty messages', () => {
    const result = inferSetupGuidanceFromMessages([])

    expect(result.setupActions.length).toBe(0)
    expect(result.requiredUserInputs.length).toBe(0)
  })

  test('should infer multiple setup types from combined messages', () => {
    const messages = [
      'ModuleNotFoundError: No module named frida',
      'UnsupportedClassVersionError: Java version',
    ]
    const result = inferSetupGuidanceFromMessages(messages)

    // Should include both Frida and Java setup
    expect(result.setupActions.map((a) => a.id)).toContain('install_frida_runtime')
    expect(result.setupActions.map((a) => a.id)).toContain('install_java_21')
    expect(result.requiredUserInputs.map((i) => i.key)).toContain('java_home')
  })
})

describe('collectSetupGuidanceFromWorkerResult', () => {
  test('should return empty when result is null', () => {
    const result = collectSetupGuidanceFromWorkerResult(null)

    expect(result.setupActions.length).toBe(0)
    expect(result.requiredUserInputs.length).toBe(0)
  })

  test('should return empty when result is undefined', () => {
    const result = collectSetupGuidanceFromWorkerResult(undefined as any)

    expect(result.setupActions.length).toBe(0)
    expect(result.requiredUserInputs.length).toBe(0)
  })

  test('should extract setup_actions from worker result data', () => {
    const workerResult = {
      ok: false,
      data: {
        setup_actions: [
          {
            id: 'test_action',
            required: false,
            kind: 'pip_install' as const,
            title: 'Test Action',
            summary: 'Test summary',
            examples: [],
            applies_to: [],
          },
        ],
      },
      errors: [],
      warnings: [],
    }

    const result = collectSetupGuidanceFromWorkerResult(workerResult as any)

    expect(result.setupActions.length).toBe(1)
    expect(result.setupActions[0].id).toBe('test_action')
  })

  test('should extract required_user_inputs from worker result data', () => {
    const workerResult = {
      ok: false,
      data: {
        required_user_inputs: [
          {
            key: 'test_input',
            label: 'Test Input',
            summary: 'Test summary',
            required: false,
          },
        ],
      },
      errors: [],
      warnings: [],
    }

    const result = collectSetupGuidanceFromWorkerResult(workerResult as any)

    expect(result.requiredUserInputs.length).toBe(1)
    expect(result.requiredUserInputs[0].key).toBe('test_input')
  })

  test('should infer additional setup guidance from errors', () => {
    const workerResult = {
      ok: false,
      data: {},
      errors: ['ModuleNotFoundError: No module named frida'],
      warnings: [],
    }

    const result = collectSetupGuidanceFromWorkerResult(workerResult as any)

    expect(result.setupActions.map((a) => a.id)).toContain('install_frida_runtime')
  })

  test('should infer additional setup guidance from warnings', () => {
    const workerResult = {
      ok: true,
      data: {},
      errors: [],
      warnings: ['UnsupportedClassVersionError: Java 21 required'],
    }

    const result = collectSetupGuidanceFromWorkerResult(workerResult as any)

    expect(result.setupActions.map((a) => a.id)).toContain('install_java_21')
  })

  test('should merge explicit and inferred setup actions', () => {
    const workerResult = {
      ok: false,
      data: {
        setup_actions: [
          {
            id: 'explicit_action',
            required: false,
            kind: 'pip_install' as const,
            title: 'Explicit',
            summary: 'Explicit action',
            examples: [],
            applies_to: [],
          },
        ],
      },
      errors: ['ModuleNotFoundError: No module named frida'],
      warnings: [],
    }

    const result = collectSetupGuidanceFromWorkerResult(workerResult as any)

    expect(result.setupActions.map((a) => a.id)).toContain('explicit_action')
    expect(result.setupActions.map((a) => a.id)).toContain('install_frida_runtime')
  })

  test('should validate setup actions against schema', () => {
    const workerResult = {
      ok: false,
      data: {
        setup_actions: [
          {
            id: 'valid_action',
            required: false,
            kind: 'pip_install' as const,
            title: 'Valid',
            summary: 'Valid action',
            examples: [],
            applies_to: [],
          },
        ],
      },
      errors: [],
      warnings: [],
    }

    const result = collectSetupGuidanceFromWorkerResult(workerResult as any)

    expect(() => {
      result.setupActions.forEach((action) => SetupActionSchema.parse(action))
    }).not.toThrow()
  })

  test('should validate required user inputs against schema', () => {
    const workerResult = {
      ok: false,
      data: {
        required_user_inputs: [
          {
            key: 'valid_input',
            label: 'Valid',
            summary: 'Valid input',
            required: false,
          },
        ],
      },
      errors: [],
      warnings: [],
    }

    const result = collectSetupGuidanceFromWorkerResult(workerResult as any)

    expect(() => {
      result.requiredUserInputs.forEach((input) => RequiredUserInputSchema.parse(input))
    }).not.toThrow()
  })
})
