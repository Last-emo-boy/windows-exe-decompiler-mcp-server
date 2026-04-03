/**
 * Dynamic Analysis Automation Plugin
 *
 * Automated Frida hooking, trace attribution, and memory dumping.
 */

import type { Plugin } from '../sdk.js'
import {
  dynamicAutoHookToolDefinition, createDynamicAutoHookHandler,
} from './tools/dynamic-auto-hook.js'
import {
  dynamicTraceAttributeToolDefinition, createDynamicTraceAttributeHandler,
} from './tools/dynamic-trace-attribute.js'
import {
  dynamicMemoryDumpToolDefinition, createDynamicMemoryDumpHandler,
} from './tools/dynamic-memory-dump.js'

const dynamicPlugin: Plugin = {
  id: 'dynamic',
  name: 'Dynamic Analysis Automation',
  description: 'Automated Frida hooking, trace attribution, and memory dumping',
  version: '1.0.0',
  configSchema: [
    { envVar: 'FRIDA_PATH', description: 'Path to frida CLI', required: false },
  ],
  register(server, deps) {
    server.registerTool(dynamicAutoHookToolDefinition, createDynamicAutoHookHandler(deps))
    server.registerTool(dynamicTraceAttributeToolDefinition, createDynamicTraceAttributeHandler(deps))
    server.registerTool(dynamicMemoryDumpToolDefinition, createDynamicMemoryDumpHandler(deps))
    return ['dynamic.auto_hook', 'dynamic.trace_attribute', 'dynamic.memory_dump']
  },
}

export default dynamicPlugin
