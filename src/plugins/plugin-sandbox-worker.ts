/**
 * Plugin Sandbox Worker — runs untrusted plugins in an isolated worker_thread.
 *
 * This script is loaded by plugin-sandbox.ts as a Worker.
 * It receives messages from the main thread to:
 *   1. Initialize (load) a plugin module
 *   2. Execute tool handlers
 *   3. Teardown
 *
 * Tool registrations are sent BACK to the main thread via postMessage.
 */

import { parentPort, workerData } from 'worker_threads'
import { pathToFileURL } from 'url'

if (!parentPort) {
  throw new Error('plugin-sandbox-worker must be run as a worker_thread')
}

// ── Internal state ────────────────────────────────────────────────────────

const toolHandlers = new Map<string, (args: unknown) => Promise<any>>()

// ── Sandboxed server interface ────────────────────────────────────────────

/** A minimal server proxy that sends tool definitions back to the main thread. */
const sandboxServer = {
  registerTool(definition: any, handler: (args: any) => Promise<any>) {
    toolHandlers.set(definition.name, handler)
    // Notify main thread of this tool registration
    parentPort!.postMessage({
      id: 'auto',
      type: 'register-tool',
      toolDefinition: {
        name: definition.name,
        description: definition.description,
        inputSchema: definition.inputSchema,
      },
    })
  },
  unregisterTool(name: string) {
    toolHandlers.delete(name)
  },
}

// ── Message handler ───────────────────────────────────────────────────────

parentPort.on('message', async (msg: any) => {
  const { id, type, pluginPath, toolName, args } = msg

  if (type === 'init') {
    try {
      const mod = await import(pathToFileURL(pluginPath).href)
      const plugin = mod.default ?? mod.plugin
      if (!plugin || typeof plugin.register !== 'function') {
        parentPort!.postMessage({ id, type: 'init-error', error: 'Module does not export a valid Plugin' })
        return
      }
      // Run register with sandboxed server and minimal deps
      plugin.register(sandboxServer, {
        workspaceManager: null,
        database: null,
      })
      parentPort!.postMessage({ id, type: 'init-ok' })
    } catch (err: any) {
      parentPort!.postMessage({ id, type: 'init-error', error: err.message || String(err) })
    }
  } else if (type === 'call') {
    const handler = toolHandlers.get(toolName)
    if (!handler) {
      parentPort!.postMessage({ id, type: 'call-error', error: `Tool '${toolName}' not registered in sandbox` })
      return
    }
    try {
      const result = await handler(args)
      parentPort!.postMessage({ id, type: 'call-result', data: result })
    } catch (err: any) {
      parentPort!.postMessage({ id, type: 'call-error', error: err.message || String(err) })
    }
  } else if (type === 'teardown') {
    toolHandlers.clear()
    parentPort!.postMessage({ id, type: 'teardown-ok' })
  }
})
