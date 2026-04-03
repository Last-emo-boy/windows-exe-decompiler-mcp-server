/**
 * Debug Session Plugin
 *
 * GDB/LLDB-backed interactive debugging: start, breakpoint, step,
 * continue, inspect (registers/memory/stack/disasm), and end sessions.
 */

import type { Plugin } from '../sdk.js'
import {
  debugSessionStartToolDefinition, createDebugSessionStartHandler,
} from './tools/debug-session-start.js'
import {
  debugSessionBreakpointToolDefinition, createDebugSessionBreakpointHandler,
} from './tools/debug-session-breakpoint.js'
import {
  debugSessionContinueToolDefinition, createDebugSessionContinueHandler,
} from './tools/debug-session-continue.js'
import {
  debugSessionStepToolDefinition, createDebugSessionStepHandler,
} from './tools/debug-session-step.js'
import {
  debugSessionInspectToolDefinition, createDebugSessionInspectHandler,
} from './tools/debug-session-inspect.js'
import {
  debugSessionEndToolDefinition, createDebugSessionEndHandler,
} from './tools/debug-session-end.js'

const debugSessionPlugin: Plugin = {
  id: 'debug-session',
  name: 'Debug Session',
  description: 'Interactive debugging via GDB/LLDB — breakpoints, stepping, memory inspection',
  version: '1.0.0',
  check() {
    try {
      const { execSync } = require('child_process')
      execSync('gdb --version', { stdio: 'ignore' })
      return true
    } catch {
      return false
    }
  },
  register(server, deps) {
    server.registerTool(debugSessionStartToolDefinition, createDebugSessionStartHandler(deps))
    server.registerTool(debugSessionBreakpointToolDefinition, createDebugSessionBreakpointHandler(deps))
    server.registerTool(debugSessionContinueToolDefinition, createDebugSessionContinueHandler(deps))
    server.registerTool(debugSessionStepToolDefinition, createDebugSessionStepHandler(deps))
    server.registerTool(debugSessionInspectToolDefinition, createDebugSessionInspectHandler(deps))
    server.registerTool(debugSessionEndToolDefinition, createDebugSessionEndHandler(deps))
    return [
      'debug.session.start', 'debug.session.breakpoint', 'debug.session.continue',
      'debug.session.step', 'debug.session.inspect', 'debug.session.end',
    ]
  },
}

export default debugSessionPlugin
