# Plugin SDK for Windows EXE Decompiler MCP Server

Type-safe SDK for building third-party plugins for `windows-exe-decompiler-mcp-server`.

## Installation

```bash
npm install @anthropic/windows-exe-decompiler-plugin-sdk
```

## Quick Start

```typescript
import { definePlugin } from '@anthropic/windows-exe-decompiler-plugin-sdk'

export default definePlugin({
  id: 'my-custom-tool',
  name: 'My Custom Analysis Tool',
  version: '1.0.0',
  description: 'Custom binary analysis plugin',

  configSchema: [
    { envVar: 'MY_TOOL_PATH', description: 'Path to custom tool binary', required: true },
  ],

  check() {
    return Boolean(process.env.MY_TOOL_PATH)
  },

  register(server, deps, ctx) {
    // Use ctx.logger for scoped logging
    ctx?.logger.info('Registering my-tool.analyze')
    // Use ctx.getConfig() for type-safe config
    const toolPath = ctx?.getConfig('MY_TOOL_PATH')

    server.registerTool(
      {
        name: 'my-tool.analyze',
        description: 'Run custom analysis',
        inputSchema: { type: 'object', properties: { sample_id: { type: 'string' } }, required: ['sample_id'] }
      },
      async (args: { sample_id: string }) => ({
        content: [{ type: 'text' as const, text: `Analyzed ${args.sample_id} with ${toolPath}` }]
      })
    )
    return ['my-tool.analyze']
  },
})
```

## API

### `definePlugin(plugin: Plugin): Plugin`
Type-safe helper to define a plugin with full inference.

### `pathExists(path: string): boolean`
Synchronous path existence check — useful in `check()` functions.

### `envIsSet(varName: string): boolean`
Check whether an environment variable is set and non-empty.

## Plugin Lifecycle

1. **Discovery** — plugins are loaded from the `plugins/` directory
2. **check()** — optional prerequisite validation
3. **configSchema** — required fields are validated (warnings logged for missing)
4. **register(server, deps, ctx)** — register MCP tools; receives a `PluginContext` with scoped logger and config
5. **hooks** — optional before/after/error callbacks (set `globalHooks: true` to observe ALL tool calls)
6. **teardown()** — cleanup on unload

## PluginContext

The third argument to `register()` provides:

```typescript
interface PluginContext {
  pluginId: string                                // Plugin's unique ID
  logger: PluginLogger                           // Scoped logger (prefixed with plugin ID)
  getConfig(envVar: string): string | undefined  // Read config from configSchema
  getRequiredConfig(envVar: string): string       // Read required config (throws if missing)
  dataDir: string                                 // Persistent data directory for this plugin
}
```

## Global Hooks

Set `globalHooks: true` on your plugin to receive hook callbacks for ALL tool invocations,
not just your own tools. Useful for observability, logging, and monitoring plugins.

```typescript
export default definePlugin({
  id: 'my-observer',
  globalHooks: true,
  hooks: {
    onBeforeToolCall(toolName, args) { console.log(`Calling ${toolName}`) },
    onAfterToolCall(toolName, args, elapsedMs) { console.log(`${toolName} took ${elapsedMs}ms`) },
  },
  register() { return [] },
})
```

## Types

- `Plugin` — the core plugin contract
- `PluginContext` — scoped runtime context
- `PluginLogger` — structured logging interface
- `PluginConfigField` — config field descriptor
- `PluginHooks` — lifecycle hook interfaces
- `ToolDefinition` — MCP tool registration shape
- `ToolResult` — standard tool return type
