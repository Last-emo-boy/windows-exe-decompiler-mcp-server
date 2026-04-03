/**
 * Unit tests for interactive debug session
 */

import { GdbMiClient, type MiResponse } from '../../src/debug/gdb-mi-client.js'
import { DebugSessionManager } from '../../src/debug/debug-session-state.js'

describe('GdbMiClient', () => {
  it('can be instantiated', () => {
    const client = new GdbMiClient()
    expect(client).toBeInstanceOf(GdbMiClient)
    expect(client.exited).toBe(false)
  })

  it('is an EventEmitter', () => {
    const client = new GdbMiClient()
    expect(typeof client.on).toBe('function')
    expect(typeof client.emit).toBe('function')
  })
})

describe('DebugSessionManager', () => {
  let manager: DebugSessionManager

  beforeEach(() => {
    manager = new DebugSessionManager()
  })

  afterEach(() => {
    manager.dispose()
  })

  it('starts with zero active sessions', () => {
    expect(manager.activeCount).toBe(0)
  })

  it('getSession returns undefined for unknown ID', () => {
    expect(manager.getSession('nonexistent')).toBeUndefined()
  })

  it('has dispose method', () => {
    expect(typeof manager.dispose).toBe('function')
  })

  it('has createSession method', () => {
    expect(typeof manager.createSession).toBe('function')
  })

  it('has endSession method', () => {
    expect(typeof manager.endSession).toBe('function')
  })
})

describe('debug tool definitions', () => {
  it('debug.session.start exports correctly', async () => {
    const mod = await import('../../src/plugins/debug-session/tools/debug-session-start.js')
    expect(mod.debugSessionStartToolDefinition).toBeDefined()
    expect(mod.debugSessionStartToolDefinition.name).toBe('debug.session.start')
    expect(typeof mod.createDebugSessionStartHandler).toBe('function')
  })

  it('debug.session.breakpoint exports correctly', async () => {
    const mod = await import('../../src/plugins/debug-session/tools/debug-session-breakpoint.js')
    expect(mod.debugSessionBreakpointToolDefinition).toBeDefined()
    expect(mod.debugSessionBreakpointToolDefinition.name).toBe('debug.session.breakpoint')
    expect(typeof mod.createDebugSessionBreakpointHandler).toBe('function')
  })

  it('debug.session.continue exports correctly', async () => {
    const mod = await import('../../src/plugins/debug-session/tools/debug-session-continue.js')
    expect(mod.debugSessionContinueToolDefinition).toBeDefined()
    expect(mod.debugSessionContinueToolDefinition.name).toBe('debug.session.continue')
    expect(typeof mod.createDebugSessionContinueHandler).toBe('function')
  })

  it('debug.session.step exports correctly', async () => {
    const mod = await import('../../src/plugins/debug-session/tools/debug-session-step.js')
    expect(mod.debugSessionStepToolDefinition).toBeDefined()
    expect(mod.debugSessionStepToolDefinition.name).toBe('debug.session.step')
    expect(typeof mod.createDebugSessionStepHandler).toBe('function')
  })

  it('debug.session.inspect exports correctly', async () => {
    const mod = await import('../../src/plugins/debug-session/tools/debug-session-inspect.js')
    expect(mod.debugSessionInspectToolDefinition).toBeDefined()
    expect(mod.debugSessionInspectToolDefinition.name).toBe('debug.session.inspect')
    expect(typeof mod.createDebugSessionInspectHandler).toBe('function')
  })

  it('debug.session.end exports correctly', async () => {
    const mod = await import('../../src/plugins/debug-session/tools/debug-session-end.js')
    expect(mod.debugSessionEndToolDefinition).toBeDefined()
    expect(mod.debugSessionEndToolDefinition.name).toBe('debug.session.end')
    expect(typeof mod.createDebugSessionEndHandler).toBe('function')
  })
})
