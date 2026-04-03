/**
 * Unit tests for Plugin SDK and PluginManager
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import type { Plugin, PluginHooks, PluginContext } from '../../src/plugins.js'

// ══════════════════════════════════════════════════════════════════════════
// Helpers — lightweight stubs
// ══════════════════════════════════════════════════════════════════════════

function createMockServer() {
  const tools = new Map<string, any>()
  return {
    registerTool: jest.fn((def: any, handler: any) => { tools.set(def.name, { def, handler }) }),
    unregisterTool: jest.fn((name: string) => tools.delete(name)),
    tools,
  }
}

function createMockDeps() {
  return {
    workspaceManager: {},
    database: {},
    config: { workers: { ghidra: { enabled: false }, static: { enabled: false }, dotnet: { enabled: false }, sandbox: { enabled: false }, frida: { enabled: false } } },
    storageManager: {},
  } as any
}

function makePlugin(overrides: Partial<Plugin> = {}): Plugin {
  return {
    id: 'test-plugin',
    name: 'Test Plugin',
    version: '1.0.0',
    description: 'A test plugin',
    register: jest.fn(() => ['test-plugin.hello']),
    ...overrides,
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════════

describe('Plugin SDK types', () => {
  test('Plugin interface has required fields', () => {
    const p = makePlugin()
    expect(p.id).toBe('test-plugin')
    expect(p.name).toBe('Test Plugin')
    expect(typeof p.register).toBe('function')
  })

  test('Plugin with all optional fields', () => {
    const hooks: PluginHooks = {
      onBeforeToolCall: jest.fn() as any,
      onAfterToolCall: jest.fn() as any,
      onToolError: jest.fn() as any,
    }
    const p = makePlugin({
      description: 'Full plugin',
      version: '2.0.0',
      dependencies: ['other-plugin'],
      configSchema: [{ envVar: 'TEST_VAR', description: 'test', required: false }],
      hooks,
      teardown: jest.fn() as any,
    })
    expect(p.dependencies).toEqual(['other-plugin'])
    expect(p.configSchema).toHaveLength(1)
    expect(p.hooks).toBeDefined()
    expect(p.teardown).toBeDefined()
  })
})

describe('Plugin check()', () => {
  test('check returning true allows loading', async () => {
    const p = makePlugin({ check: () => true })
    expect(await p.check!()).toBe(true)
  })

  test('check returning false skips loading', async () => {
    const p = makePlugin({ check: () => false })
    expect(await p.check!()).toBe(false)
  })

  test('async check works', async () => {
    const p = makePlugin({ check: async () => true })
    expect(await p.check!()).toBe(true)
  })

  test('no check means always loadable', () => {
    const p = makePlugin()
    expect(p.check).toBeUndefined()
  })
})

describe('Plugin register()', () => {
  test('register receives server and deps', () => {
    const server = createMockServer()
    const deps = createMockDeps()
    const registerFn = jest.fn(() => ['test.tool']) as any
    const p = makePlugin({ register: registerFn })

    const result = p.register(server as any, deps)

    expect(registerFn).toHaveBeenCalledWith(server, deps)
    expect(result).toEqual(['test.tool'])
  })

  test('register can return void', () => {
    const p = makePlugin({ register: jest.fn(() => undefined) as any })
    const server = createMockServer()
    const deps = createMockDeps()

    const result = p.register(server as any, deps)

    expect(result).toBeUndefined()
  })

  test('register tool is callable via mock server', () => {
    const server = createMockServer()
    const deps = createMockDeps()
    const p = makePlugin({
      register(srv: any) {
        srv.registerTool(
          { name: 'test-plugin.analyze', description: 'Test', inputSchema: {} },
          async () => ({ content: [{ type: 'text', text: 'ok' }] })
        )
        return ['test-plugin.analyze']
      },
    })

    p.register(server as any, deps)

    expect(server.registerTool).toHaveBeenCalledTimes(1)
    expect(server.tools.has('test-plugin.analyze')).toBe(true)
  })
})

describe('Plugin hooks', () => {
  test('onBeforeToolCall fires', async () => {
    const onBefore = jest.fn() as any
    const p = makePlugin({ hooks: { onBeforeToolCall: onBefore } })

    await p.hooks!.onBeforeToolCall!('test.tool', { foo: 'bar' })

    expect(onBefore).toHaveBeenCalledWith('test.tool', { foo: 'bar' })
  })

  test('onAfterToolCall receives elapsed time', async () => {
    const onAfter = jest.fn() as any
    const p = makePlugin({ hooks: { onAfterToolCall: onAfter } })

    await p.hooks!.onAfterToolCall!('test.tool', {}, 42)

    expect(onAfter).toHaveBeenCalledWith('test.tool', {}, 42)
  })

  test('onToolError receives error', async () => {
    const onError = jest.fn() as any
    const p = makePlugin({ hooks: { onToolError: onError } })

    const err = new Error('boom')
    await p.hooks!.onToolError!('test.tool', err)

    expect(onError).toHaveBeenCalledWith('test.tool', err)
  })
})

describe('Plugin teardown', () => {
  test('teardown is callable', async () => {
    const teardown = jest.fn() as any
    const p = makePlugin({ teardown })

    await p.teardown!()

    expect(teardown).toHaveBeenCalled()
  })

  test('async teardown works', async () => {
    let cleaned = false
    const p = makePlugin({ teardown: async () => { cleaned = true } })

    await p.teardown!()

    expect(cleaned).toBe(true)
  })
})

describe('Plugin configSchema', () => {
  test('configSchema validates structure', () => {
    const p = makePlugin({
      configSchema: [
        { envVar: 'TOOL_PATH', description: 'Path to tool', required: true },
        { envVar: 'TOOL_TIMEOUT', description: 'Timeout in seconds', required: false, defaultValue: '30' },
      ],
    })

    expect(p.configSchema).toHaveLength(2)
    expect(p.configSchema![0].required).toBe(true)
    expect(p.configSchema![1].defaultValue).toBe('30')
  })
})

describe('Plugin dependencies', () => {
  test('empty dependencies', () => {
    const p = makePlugin({ dependencies: [] })
    expect(p.dependencies).toEqual([])
  })

  test('multiple dependencies', () => {
    const p = makePlugin({ dependencies: ['ghidra', 'frida'] })
    expect(p.dependencies).toEqual(['ghidra', 'frida'])
  })
})

// ══════════════════════════════════════════════════════════════════════════
// PluginContext tests
// ══════════════════════════════════════════════════════════════════════════

describe('PluginContext contract', () => {
  function createMockContext(pluginId: string, env: Record<string, string> = {}): PluginContext {
    const configMap = new Map(Object.entries(env))
    return {
      pluginId,
      logger: {
        info: jest.fn() as any,
        warn: jest.fn() as any,
        error: jest.fn() as any,
        debug: jest.fn() as any,
      },
      getConfig: (key: string) => configMap.get(key),
      getRequiredConfig: (key: string) => {
        const val = configMap.get(key)
        if (val === undefined) throw new Error(`Required config '${key}' is not set`)
        return val
      },
      dataDir: `/data/plugins/${pluginId}`,
    }
  }

  test('getConfig returns value for known key', () => {
    const ctx = createMockContext('ghidra', { GHIDRA_INSTALL_DIR: '/opt/ghidra' })
    expect(ctx.getConfig('GHIDRA_INSTALL_DIR')).toBe('/opt/ghidra')
  })

  test('getConfig returns undefined for unknown key', () => {
    const ctx = createMockContext('ghidra')
    expect(ctx.getConfig('MISSING')).toBeUndefined()
  })

  test('getRequiredConfig throws for missing key', () => {
    const ctx = createMockContext('ghidra')
    expect(() => ctx.getRequiredConfig('GHIDRA_INSTALL_DIR')).toThrow("Required config 'GHIDRA_INSTALL_DIR' is not set")
  })

  test('getRequiredConfig returns value for present key', () => {
    const ctx = createMockContext('frida', { FRIDA_SERVER: '/path' })
    expect(ctx.getRequiredConfig('FRIDA_SERVER')).toBe('/path')
  })

  test('logger has all methods', () => {
    const ctx = createMockContext('test')
    expect(typeof ctx.logger.info).toBe('function')
    expect(typeof ctx.logger.warn).toBe('function')
    expect(typeof ctx.logger.error).toBe('function')
    expect(typeof ctx.logger.debug).toBe('function')
  })

  test('dataDir is scoped to plugin', () => {
    const ctx = createMockContext('malware')
    expect(ctx.dataDir).toContain('malware')
  })

  test('register receives context as third argument', () => {
    const server = createMockServer()
    const deps = createMockDeps()
    const ctx = createMockContext('test-plugin')
    const registerFn = jest.fn((_s: any, _d: any, _c?: PluginContext) => ['test.tool']) as any
    const p = makePlugin({ register: registerFn })

    p.register(server as any, deps, ctx)

    expect(registerFn).toHaveBeenCalledWith(server, deps, ctx)
  })
})

// ══════════════════════════════════════════════════════════════════════════
// Hot-reload lifecycle tests
// ══════════════════════════════════════════════════════════════════════════

describe('Plugin hot-reload lifecycle', () => {
  test('hotLoad → unload → re-hotLoad full cycle', async () => {
    const server = createMockServer()
    const deps = createMockDeps()
    let activateCount = 0
    let deactivateCount = 0

    const p = makePlugin({
      id: 'hot-test',
      name: 'Hot Test Plugin',
      hooks: {
        onActivate: async () => { activateCount++ },
        onDeactivate: async () => { deactivateCount++ },
      },
      register(srv: any) {
        srv.registerTool(
          { name: 'hot-test.ping', description: 'Ping', inputSchema: {} },
          async () => ({ content: [{ type: 'text', text: 'pong' }] }),
        )
        return ['hot-test.ping']
      },
      teardown: jest.fn() as any,
    })

    // Simulate hotLoad: register + activate
    const result = p.register(server as any, deps)
    expect(result).toEqual(['hot-test.ping'])
    expect(server.tools.has('hot-test.ping')).toBe(true)
    await p.hooks!.onActivate!()
    expect(activateCount).toBe(1)

    // Simulate unload: deactivate + unregister + teardown
    await p.hooks!.onDeactivate!()
    expect(deactivateCount).toBe(1)
    const tools = result as string[]
    for (const tool of tools) server.unregisterTool(tool)
    expect(server.tools.has('hot-test.ping')).toBe(false)
    await p.teardown!()
    expect(p.teardown).toHaveBeenCalledTimes(1)

    // Simulate re-hotLoad
    p.register(server as any, deps)
    expect(server.tools.has('hot-test.ping')).toBe(true)
    await p.hooks!.onActivate!()
    expect(activateCount).toBe(2)
  })

  test('teardown cleans up resources', async () => {
    let cleaned = false
    const p = makePlugin({
      teardown: async () => { cleaned = true },
    })

    await p.teardown!()
    expect(cleaned).toBe(true)
  })
})

// ══════════════════════════════════════════════════════════════════════════
// Global hooks (observability pattern)
// ══════════════════════════════════════════════════════════════════════════

describe('Global hooks (globalHooks: true)', () => {
  test('globalHooks flag is accepted on Plugin interface', () => {
    const p = makePlugin({
      globalHooks: true,
      hooks: { onBeforeToolCall: jest.fn() as any },
    })
    expect(p.globalHooks).toBe(true)
  })

  test('observer plugin fires hooks for all tools', async () => {
    const onBefore = jest.fn() as any
    const onAfter = jest.fn() as any
    const onError = jest.fn() as any
    const observer = makePlugin({
      id: 'observer',
      globalHooks: true,
      hooks: { onBeforeToolCall: onBefore, onAfterToolCall: onAfter, onToolError: onError },
    })

    // Simulate hook calls
    await observer.hooks!.onBeforeToolCall!('other-plugin.tool', { key: 'val' })
    await observer.hooks!.onAfterToolCall!('other-plugin.tool', {}, 150)
    await observer.hooks!.onToolError!('other-plugin.tool', new Error('fail'))

    expect(onBefore).toHaveBeenCalledWith('other-plugin.tool', { key: 'val' })
    expect(onAfter).toHaveBeenCalledWith('other-plugin.tool', {}, 150)
    expect(onError).toHaveBeenCalledWith('other-plugin.tool', expect.any(Error))
  })
})
