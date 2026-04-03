/**
 * Plugin SDK — Public types and utilities for third-party plugin authors.
 *
 * This package re-exports the core interfaces that plugin authors need
 * without depending on the full MCP server codebase.
 *
 * Plugins are self-contained modules that:
 *  - Live in their own directory under `src/plugins/<id>/`
 *  - Export a default `Plugin` object from `index.ts`
 *  - Are auto-discovered at server startup (no manual registration needed)
 *  - Have full lifecycle management (check → register → hooks → teardown)
 */

// ═══════════════════════════════════════════════════════════════════════════
// Core Types
// ═══════════════════════════════════════════════════════════════════════════

/** Declarative description of one config field a plugin needs. */
export interface PluginConfigField {
  /** Environment variable name, e.g. `'JADX_PATH'`. */
  envVar: string
  /** Human-readable description shown in setup guides. */
  description: string
  /** Whether the field is required for the plugin to load. */
  required: boolean
  /** Default value when the env var is unset. */
  defaultValue?: string
}

/** Lifecycle hooks a plugin can implement. All are optional. */
export interface PluginHooks {
  /** Called just before a tool belonging to this plugin executes. */
  onBeforeToolCall?: (toolName: string, args: Record<string, unknown>) => void | Promise<void>
  /** Called just after a tool belonging to this plugin returns. */
  onAfterToolCall?: (toolName: string, args: Record<string, unknown>, elapsedMs: number) => void | Promise<void>
  /** Called when a tool belonging to this plugin throws. */
  onToolError?: (toolName: string, error: unknown) => void | Promise<void>
  /** Called once after the plugin is fully loaded and tools are registered. */
  onActivate?: () => void | Promise<void>
  /** Called just before the plugin is unloaded (before teardown). */
  onDeactivate?: () => void | Promise<void>
}

/** JSON Schema type used by tool definitions. */
export type JSONSchema = Record<string, unknown>

/** Minimal tool definition structure used by registerTool. */
export interface ToolDefinition {
  name: string
  description: string
  inputSchema: JSONSchema
  outputSchema?: JSONSchema
}

/** Tool result content block. */
export interface TextContent {
  type: 'text'
  text: string
}

/** Result returned from a tool handler. */
export interface ToolResult {
  content: TextContent[]
  isError?: boolean
  structuredContent?: unknown
}

/**
 * Minimal interface for the MCP server that plugins interact with.
 * Plugins receive this in their `register()` function.
 */
export interface PluginServerInterface {
  registerTool(definition: ToolDefinition, handler: (...args: any[]) => Promise<ToolResult | unknown>): void
  unregisterTool(canonicalName: string): boolean
}

/**
 * Structured logging interface exposed to plugins via PluginContext.
 */
export interface PluginLogger {
  info(msg: string, data?: Record<string, unknown>): void
  warn(msg: string, data?: Record<string, unknown>): void
  error(msg: string, data?: Record<string, unknown>): void
  debug(msg: string, data?: Record<string, unknown>): void
}

/**
 * Minimal interface for the standard tool dependencies.
 * Plugins receive this in their `register()` function.
 */
export interface PluginToolDeps {
  workspaceManager: unknown
  database: unknown
  config: unknown
  policyGuard?: unknown
  cacheManager?: unknown
  jobQueue?: unknown
  [key: string]: unknown
}

/**
 * Context object passed to plugins during lifecycle.
 * Provides logging, config access, and plugin metadata.
 */
export interface PluginContext {
  /** Scoped logger prefixed with the plugin ID. */
  logger: PluginLogger
  /** Read an environment variable (respects plugin configSchema defaults). */
  getConfig(envVar: string): string | undefined
  /** Read a required config value — throws if missing. */
  getRequiredConfig(envVar: string): string
  /** The absolute path to the plugin's own directory. */
  pluginDir: string
  /** The plugin's unique ID. */
  pluginId: string
  /** Data directory path for this plugin (for persistent state). */
  dataDir: string
}

/**
 * Optional manifest file (`plugin-manifest.json`) placed in the plugin directory.
 * When present, provides richer metadata for registry and documentation.
 */
export interface PluginManifest {
  id: string
  name: string
  version: string
  description: string
  author?: string
  license?: string
  homepage?: string
  repository?: string
  keywords?: string[]
  configFields?: PluginConfigField[]
  dependencies?: string[]
  minServerVersion?: string
  entryPoint?: string
}

/** The contract every plugin must implement. */
export interface Plugin {
  /** Unique kebab-case identifier, e.g. `'android'`, `'ghidra'`. */
  id: string
  /** Human-readable display name. */
  name: string
  /** Short description of the plugin's capabilities. */
  description?: string
  /** Semantic version string, e.g. `'1.0.0'`. */
  version?: string
  /** IDs of plugins that must load before this one. */
  dependencies?: string[]
  /** Declarative config fields the plugin expects. */
  configSchema?: PluginConfigField[]
  /** Optional lifecycle hooks. */
  hooks?: PluginHooks
  /** If true, hooks fire for ALL tool invocations, not just this plugin's tools. */
  globalHooks?: boolean
  /** Optional prerequisite check; return false to skip loading. */
  check?: () => boolean | Promise<boolean>
  /** Register all tools belonging to this plugin. Return tool names registered. */
  register: (server: PluginServerInterface, deps: PluginToolDeps, ctx?: PluginContext) => string[] | void
  /** Optional cleanup when the plugin is unloaded at runtime. */
  teardown?: () => void | Promise<void>
}

/** Runtime metadata about a loaded (or skipped) plugin. */
export interface PluginStatus {
  id: string
  name: string
  description?: string
  version?: string
  status: 'loaded' | 'skipped-disabled' | 'skipped-check' | 'skipped-deps' | 'error'
  tools: string[]
  configFields?: PluginConfigField[]
  error?: string
}

/** Runtime metadata about a loaded (or skipped) plugin. */
export interface PluginStatus {
  id: string
  name: string
  description?: string
  version?: string
  status: 'loaded' | 'skipped-disabled' | 'skipped-check' | 'skipped-deps' | 'error'
  tools: string[]
  configFields?: PluginConfigField[]
  error?: string
}

// ═══════════════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Helper to define a plugin with type inference.
 * Usage: `export default definePlugin({ id: 'my-plugin', ... })`
 */
export function definePlugin(plugin: Plugin): Plugin {
  return plugin
}

/**
 * Check whether a path exists on disk (synchronous).
 * Useful in plugin `check()` functions.
 */
export function pathExists(p: string): boolean {
  try {
    // Use dynamic import avoidance — works because this is a type-level utility
    const fs = require('fs')
    fs.accessSync(p)
    return true
  } catch {
    return false
  }
}

/**
 * Check whether an environment variable is set and non-empty.
 */
export function envIsSet(varName: string): boolean {
  const val = process.env[varName]
  return val !== undefined && val.trim().length > 0
}
