import { describe, test, expect } from '@jest/globals'
import { createSystemSetupGuideHandler } from '../../src/tools/system-setup-guide.js'

describe('system.setup.guide tool', () => {
  test('should return first-run bootstrap actions for all focus', async () => {
    const handler = createSystemSetupGuideHandler()
    const result = await handler({})

    expect(result.ok).toBe(true)
    const data = result.data as {
      focus: string
      setup_actions: Array<{ id: string }>
      required_user_inputs: Array<{ key: string }>
    }

    expect(data.focus).toBe('all')
    expect(data.setup_actions.map((item) => item.id)).toContain('install_python_requirements')
    expect(data.setup_actions.map((item) => item.id)).toContain('set_java_home')
    expect(data.setup_actions.map((item) => item.id)).toContain('set_ghidra_path')
    expect(data.required_user_inputs.map((item) => item.key)).toContain('java_home')
    expect(data.required_user_inputs.map((item) => item.key)).toContain('ghidra_install_dir')
  })

  test('should narrow to java-specific setup guidance', async () => {
    const handler = createSystemSetupGuideHandler()
    const result = await handler({ focus: 'java' })

    expect(result.ok).toBe(true)
    const data = result.data as {
      focus: string
      setup_actions: Array<{ id: string }>
      required_user_inputs: Array<{ key: string }>
    }

    expect(data.focus).toBe('java')
    expect(data.setup_actions.map((item) => item.id)).toContain('set_java_home')
    expect(data.setup_actions.map((item) => item.id)).not.toContain('set_ghidra_path')
    expect(data.required_user_inputs.map((item) => item.key)).toContain('java_home')
    expect(data.required_user_inputs.map((item) => item.key)).not.toContain('ghidra_install_dir')
  })

  test('should narrow to ghidra-specific setup guidance', async () => {
    const handler = createSystemSetupGuideHandler()
    const result = await handler({ focus: 'ghidra', include_optional: false })

    expect(result.ok).toBe(true)
    const data = result.data as {
      focus: string
      setup_actions: Array<{ id: string }>
      required_user_inputs: Array<{ key: string }>
    }

    expect(data.focus).toBe('ghidra')
    expect(data.setup_actions.map((item) => item.id)).toContain('set_ghidra_path')
    expect(data.setup_actions.map((item) => item.id)).not.toContain('install_pyghidra')
    expect(data.required_user_inputs.map((item) => item.key)).toContain('ghidra_install_dir')
  })
})
