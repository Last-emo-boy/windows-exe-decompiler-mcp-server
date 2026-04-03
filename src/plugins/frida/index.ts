/**
 * Frida Instrumentation Plugin
 *
 * Runtime instrumentation, script injection, and trace capture via Frida.
 */

import { execFileSync } from 'child_process'
import type { Plugin } from '../sdk.js'
import {
  fridaRuntimeInstrumentToolDefinition, createFridaRuntimeInstrumentHandler,
} from './tools/frida-runtime-instrument.js'
import {
  fridaScriptInjectToolDefinition, createFridaScriptInjectHandler,
} from './tools/frida-script-inject.js'
import {
  fridaTraceCaptureToolDefinition, createFridaTraceCaptureHandler,
} from './tools/frida-trace-capture.js'

const fridaPlugin: Plugin = {
  id: 'frida',
  name: 'Frida Instrumentation',
  description: 'Runtime instrumentation, script injection, and trace capture via Frida',
  version: '1.0.0',
  configSchema: [
    { envVar: 'FRIDA_PATH', description: 'Path to frida CLI binary', required: false },
  ],
  check() {
    try {
      execFileSync('frida', ['--version'], { stdio: 'ignore', timeout: 3000 })
      return true
    } catch { return false }
  },
  register(server, deps) {
    server.registerTool(fridaRuntimeInstrumentToolDefinition, createFridaRuntimeInstrumentHandler(deps))
    server.registerTool(fridaScriptInjectToolDefinition, createFridaScriptInjectHandler(deps))
    server.registerTool(fridaTraceCaptureToolDefinition, createFridaTraceCaptureHandler(deps))
    return ['frida.runtime.instrument', 'frida.script.inject', 'frida.trace.capture']
  },
}

export default fridaPlugin
