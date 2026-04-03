# Plugin SDK

The MCP server uses a plugin architecture for optional tool modules that can be
enabled, disabled, discovered, hot-loaded/unloaded, and extended — without
modifying core code. Third-party developers can drop `.js`/`.mjs` files into a
`plugins/` directory and have them auto-discovered at startup.

## Overview

Each plugin:

- Has a unique `id` (kebab-case) and human-readable `name`
- Implements a `register(server, deps)` function that registers its MCP tools and returns their names
- Can optionally declare a `check()` prerequisite that must pass before loading
- Can declare `configSchema` fields for environment-based configuration
- Can declare `dependencies` on other plugins (topologically sorted)
- Can implement `hooks` for lifecycle interception (before/after/error)
- Can implement `teardown()` for cleanup on unload

Plugins are loaded during server bootstrap via `loadPlugins()`, which is called
from the centralised tool registry.

## Built-in plugins

| Plugin ID | Name | Tools | Prerequisites |
|-----------|------|-------|---------------|
| `android` | Android / APK Analysis | `apk.structure.analyze`, `dex.decompile`, `dex.classes.list`, `apk.packer.detect` | jadx binary accessible |
| `malware` | Malware Analysis | `c2.extract`, `malware.config.extract`, `malware.classify`, `sandbox.report` | None |
| `crackme` | CrackMe Automation | `crackme.locate_validation`, `symbolic.explore`, `patch.generate`, `keygen.verify` | None (angr optional) |
| `dynamic` | Dynamic Analysis Automation | `dynamic.auto_hook`, `dynamic.trace_attribute`, `dynamic.memory_dump` | None |
| `frida` | Frida Instrumentation | `frida.runtime.instrument`, `frida.script.inject`, `frida.trace.capture` | `frida --version` succeeds |
| `ghidra` | Ghidra Integration | `ghidra.analyze`, `ghidra.health` | `GHIDRA_INSTALL_DIR` set and accessible |
| `cross-module` | Cross-Module Analysis | `cross_binary.compare`, `call_graph.cross_module`, `dll.dependency_tree` | None |
| `visualization` | Visualization & Reporting | `report.html.generate`, `behavior.timeline`, `data_flow.map` | None |
| `kb-collaboration` | Knowledge Base & Collaboration | `kb.function_match`, `analysis.template` | None |

## Plugin introspection tools

Three MCP tools let LLM clients discover and manage plugins at runtime:

| Tool | Description |
|------|-------------|
| `plugin.list` | List all plugins, their status, tools, and optional config schema |
| `plugin.enable` | Hot-load a known but currently-unloaded plugin |
| `plugin.disable` | Unload a loaded plugin (tools become unavailable) |

## Configuration

### `PLUGINS` environment variable

Controls which plugins are loaded at startup.

| Value | Meaning |
|-------|---------|
| `*` (default) | Load all built-in plugins |
| _(empty)_ | Load all built-in plugins |
| `android,malware` | Load only the listed plugins |
| `-dynamic` | Load all except the listed plugins (prefix with `-`) |

### Plugin config schema

Each plugin can declare `configSchema` — an array of `PluginConfigField` values:

```typescript
interface PluginConfigField {
  envVar: string       // e.g. 'GHIDRA_INSTALL_DIR'
  description: string  // shown in plugin.list output
  required: boolean
  defaultValue?: string
}
```

Use `plugin.list` with `include_config: true` to discover required environment
variables and their current set/unset status.

### Examples

```bash
# Load all plugins (default)
PLUGINS=* node dist/index.js

# Only Android and malware tools
PLUGINS=android,malware node dist/index.js

# Everything except dynamic analysis
PLUGINS=-dynamic node dist/index.js

# Set Ghidra dir to enable ghidra plugin
GHIDRA_INSTALL_DIR=/opt/ghidra node dist/index.js
```

### Docker

In `docker-compose.yml`:

```yaml
services:
  mcp-server:
    environment:
      PLUGINS: "android,malware"
      GHIDRA_INSTALL_DIR: "/opt/ghidra"
```

## Plugin lifecycle

1. `registerAllTools()` calls `loadPlugins(server, deps)`
2. `discoverExternalPlugins()` scans `plugins/` directory for `.js`/`.mjs` files
3. `PluginManager.loadAll()` resolves enabled plugins via `PLUGINS` env var
4. Plugins are topologically sorted by `dependencies`
5. For each enabled plugin in dependency order:
   - Dependency check: all declared dependencies must be loaded
   - If `check()` is defined, it is called. If it returns `false`, the plugin is skipped.
   - `register(server, deps)` is called, tool names are recorded.
   - Plugin status is recorded as `loaded`, `skipped-check`, `skipped-deps`, or `error`
6. `server.setPluginManager(mgr)` wires in lifecycle hooks for `callTool()`
7. Plugin introspection tools (`plugin.list`, `.enable`, `.disable`) are registered

### Lifecycle hooks

When a tool belonging to a plugin is called, the server fires:

- `onBeforeToolCall(toolName, args)` — before execution
- `onAfterToolCall(toolName, args, elapsedMs)` — after successful return
- `onToolError(toolName, error)` — when an error is thrown

Hook errors are caught and logged but never propagate to the client.

### Hot-load / unload

- `plugin.enable` → `PluginManager.hotLoad(plugin)` — registers tools at runtime
- `plugin.disable` → `PluginManager.unload(id)` — calls `teardown()`, unregisters tools
- No server restart required

## Writing a plugin

### Option A: External plugin (auto-discovered)

Create a `.js` or `.mjs` file in the `plugins/` directory at project root:

```javascript
// plugins/my-feature.mjs
export default {
  id: 'my-feature',
  name: 'My Feature',
  version: '1.0.0',
  description: 'Does something cool',

  configSchema: [
    { envVar: 'MY_TOOL_PATH', description: 'Path to my-tool binary', required: true },
  ],

  check() {
    return !!process.env.MY_TOOL_PATH
  },

  register(server, deps) {
    // Import your tool definition and handler factory, then register
    // server.registerTool(myToolDefinition, myHandler)
    return ['my.tool.name']  // return registered tool names
  },

  teardown() {
    // cleanup if needed
  },
}
```

External plugins are discovered automatically at startup — no code changes needed.

### Option B: Built-in plugin

1. Define the plugin in `src/plugins.ts` alongside existing plugins
2. Add it to the `BUILT_IN_PLUGINS` array
3. Rebuild: `npm run build`

### Option C: Runtime extra plugin

```typescript
import { loadPlugins } from './plugins.js'
await loadPlugins(server, deps, [myPlugin])
```

## Plugin interface (full SDK)

```typescript
interface Plugin {
  id: string                        // unique kebab-case identifier
  name: string                      // human-readable display name
  description?: string              // short capability description
  version?: string                  // semver string
  dependencies?: string[]           // IDs of plugins that must load first
  configSchema?: PluginConfigField[] // declarative config fields
  hooks?: PluginHooks               // lifecycle hooks
  check?: () => boolean | Promise<boolean>  // prerequisite gate
  register: (server: MCPServer, deps: ToolDeps) => string[] | void  // register tools
  teardown?: () => void | Promise<void>     // cleanup on unload
}

interface PluginHooks {
  onBeforeToolCall?: (toolName: string, args: Record<string, unknown>) => void | Promise<void>
  onAfterToolCall?: (toolName: string, args: Record<string, unknown>, elapsedMs: number) => void | Promise<void>
  onToolError?: (toolName: string, error: unknown) => void | Promise<void>
}

interface PluginConfigField {
  envVar: string
  description: string
  required: boolean
  defaultValue?: string
}
```

## Troubleshooting

### Plugin not loading

1. Check `PLUGINS` env var — ensure the plugin ID is included (or not excluded).
2. If the plugin defines `check()`, verify its prerequisites (e.g. external tool paths, env vars).
3. Check server logs for `Plugin skipped (prerequisites not met)` or `skipped-deps` messages.
4. Use `plugin.list` to see all plugin statuses and error messages.

### Tool not appearing after adding a plugin

1. Ensure the tool file exports both the definition and handler factory.
2. Ensure `register()` calls `server.registerTool(definition, handler)` and returns tool names.
3. For external plugins, ensure the file is in `plugins/` and default-exports a `Plugin` object.
4. Rebuild: `npm run build`

### Hot-load not working

1. `plugin.enable` only works for plugins known to the system (built-in or previously discovered).
2. If prerequisites fail, `hotLoad()` returns a `skipped-check` status.
3. Check that `setPluginManager()` was called during bootstrap.
