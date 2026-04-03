/**
 * Plugin Sandbox — worker_threads isolation for untrusted plugins.
 *
 * Trusted (built-in) plugins run in the main process as before.
 * Untrusted (external) plugins can be loaded in a sandboxed Worker thread
 * with restricted access. Communication happens via structured message passing.
 *
 * Architecture:
 *   Main thread                    Worker thread
 *   ──────────                     ─────────────
 *   SandboxedPlugin ←→ postMessage ←→ plugin-sandbox-worker.ts
 *     register()       JSON msgs       loads plugin module
 *     tool calls       req/res         calls handler in isolation
 *
 * Security boundaries:
 *   - Worker has no access to main-thread singletons (DB, WorkspaceManager)
 *   - Tool calls are proxied: main thread serializes args → worker runs handler → main gets result
 *   - Worker cannot call arbitrary imports; only receives serializable deps subset
 */

import { Worker } from 'worker_threads'
import path from 'path'
import { fileURLToPath } from 'url'
import type { Plugin, PluginServerInterface, PluginToolDeps, ToolDefinition, PluginContext } from './sdk.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

// ═══════════════════════════════════════════════════════════════════════════
// Message protocol between main thread and sandbox worker
// ═══════════════════════════════════════════════════════════════════════════

interface SandboxRequest {
  id: string
  type: 'init' | 'call' | 'teardown'
  pluginPath?: string
  toolName?: string
  args?: unknown
}

interface SandboxResponse {
  id: string
  type: 'init-ok' | 'init-error' | 'call-result' | 'call-error' | 'register-tool' | 'teardown-ok'
  data?: unknown
  error?: string
  toolDefinition?: ToolDefinition
}

// ═══════════════════════════════════════════════════════════════════════════
// SandboxedPlugin — wraps an untrusted plugin in a Worker thread
// ═══════════════════════════════════════════════════════════════════════════

export class SandboxedPlugin implements Plugin {
  id: string
  name: string
  description?: string
  version?: string
  dependencies?: string[]
  globalHooks = false

  private worker: Worker | null = null
  private pluginPath: string
  private pendingCalls = new Map<string, { resolve: (v: any) => void; reject: (e: Error) => void }>()
  private registeredTools: ToolDefinition[] = []
  private toolHandlers = new Map<string, (args: unknown) => Promise<any>>()
  private nextId = 0

  constructor(pluginPath: string, meta: { id: string; name: string; description?: string; version?: string; dependencies?: string[] }) {
    this.pluginPath = pluginPath
    this.id = meta.id
    this.name = meta.name
    this.description = meta.description
    this.version = meta.version
    this.dependencies = meta.dependencies
  }

  private genId(): string {
    return `sb-${this.id}-${this.nextId++}`
  }

  /**
   * Register the plugin by launching a Worker, sending init, and collecting tool definitions.
   */
  register(server: PluginServerInterface, _deps: PluginToolDeps, _ctx?: PluginContext): string[] {
    const workerScript = path.join(__dirname, 'plugin-sandbox-worker.js')
    this.worker = new Worker(workerScript, {
      workerData: { pluginPath: this.pluginPath },
    })

    this.worker.on('message', (msg: SandboxResponse) => this.handleMessage(msg, server))
    this.worker.on('error', (err: Error) => {
      // Reject all pending calls
      for (const [, p] of this.pendingCalls) p.reject(err)
      this.pendingCalls.clear()
    })

    // Send init message (synchronous in terms of worker startup, but tool registration is async via messages)
    const initId = this.genId()
    this.worker.postMessage({ id: initId, type: 'init', pluginPath: this.pluginPath } satisfies SandboxRequest)

    return [] // Tools are registered asynchronously via register-tool messages
  }

  private handleMessage(msg: SandboxResponse, server: PluginServerInterface): void {
    if (msg.type === 'register-tool' && msg.toolDefinition) {
      // Worker wants to register a tool — proxy it
      const def = msg.toolDefinition
      this.registeredTools.push(def)
      const handler = async (args: unknown) => this.callTool(def.name, args)
      this.toolHandlers.set(def.name, handler)
      server.registerTool(def, handler)
    } else if (msg.type === 'call-result' || msg.type === 'call-error') {
      const pending = this.pendingCalls.get(msg.id)
      if (pending) {
        this.pendingCalls.delete(msg.id)
        if (msg.type === 'call-result') pending.resolve(msg.data)
        else pending.reject(new Error(msg.error || 'Sandboxed tool call failed'))
      }
    } else if (msg.type === 'init-error') {
      // Plugin failed to load in worker
      const pending = this.pendingCalls.get(msg.id)
      if (pending) {
        this.pendingCalls.delete(msg.id)
        pending.reject(new Error(msg.error || 'Plugin init failed in sandbox'))
      }
    }
  }

  /**
   * Call a tool in the sandboxed worker.
   */
  private callTool(toolName: string, args: unknown): Promise<any> {
    if (!this.worker) return Promise.reject(new Error('Sandbox worker not running'))
    return new Promise((resolve, reject) => {
      const id = this.genId()
      this.pendingCalls.set(id, { resolve, reject })
      this.worker!.postMessage({ id, type: 'call', toolName, args } satisfies SandboxRequest)
    })
  }

  /**
   * Teardown — terminate the Worker.
   */
  async teardown(): Promise<void> {
    if (this.worker) {
      const id = this.genId()
      this.worker.postMessage({ id, type: 'teardown' } satisfies SandboxRequest)
      await this.worker.terminate()
      this.worker = null
    }
    this.pendingCalls.clear()
    this.toolHandlers.clear()
    this.registeredTools = []
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Utility: check if a plugin should be sandboxed
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Determine if a plugin should run in a sandbox.
 * Built-in plugins (from src/plugins/) are trusted.
 * External plugins (from plugins/ at project root) are sandboxed.
 */
export function shouldSandbox(pluginPath: string): boolean {
  // If PLUGIN_SANDBOX=0, disable sandboxing globally
  if (process.env.PLUGIN_SANDBOX === '0') return false
  // Built-in plugins are trusted
  const normalized = pluginPath.replace(/\\/g, '/')
  return !normalized.includes('/src/plugins/') && !normalized.includes('/dist/plugins/')
}
