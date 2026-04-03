# Architecture

This document describes the internal architecture of the MCP server, covering
the tool registry, plugin system, command safety layer, concurrency model,
streaming support, and MCP resource exposure.

## High-level component diagram

```
┌─────────────────────────────────────────────────────┐
│  MCP Client (Claude / Copilot / Codex / …)          │
└─────────────┬───────────────────────────────────────┘
              │ JSON-RPC over stdio
┌─────────────▼───────────────────────────────────────┐
│  MCPServer  (src/server.ts)                         │
│  ┌────────────┐  ┌────────────┐  ┌───────────────┐ │
│  │ Tools      │  │ Prompts    │  │ Resources     │ │
│  └─────┬──────┘  └─────┬──────┘  └──────┬────────┘ │
│        └───────────┬────┘               │           │
│              ┌─────▼─────────────────────▼────┐     │
│              │  Tool Registry                 │     │
│              │  (src/tool-registry.ts)        │     │
│              └─────┬──────────────────────────┘     │
│                    │                                │
│        ┌───────────┼────────────────┐               │
│        ▼           ▼                ▼               │
│  148 Tool      3 Prompt      16 Resource            │
│  Handlers      Handlers      Handlers               │
│        │           │                │               │
│  ┌─────▼───┐ ┌─────▼───┐   ┌──────▼──────┐        │
│  │ Plugins │ │ LLM     │   │ Frida/Ghidra│        │
│  │ android │ │ Prompts │   │ Script Files│        │
│  │ malware │ └─────────┘   └─────────────┘        │
│  │ crackme │                                       │
│  │ dynamic │                                       │
│  └─────────┘                                       │
└─────────────────────────────────────────────────────┘
         │              │               │
    ┌────▼────┐   ┌─────▼─────┐   ┌────▼────────────┐
    │ Python  │   │ Workspace │   │ Database        │
    │ Process │   │ Manager   │   │ (SQLite)        │
    │ Pool    │   └───────────┘   └─────────────────┘
    └─────────┘
```

## Entry point

[src/index.ts](../src/index.ts) is kept minimal (~90 lines). It:

1. Loads configuration via `loadConfig()`
2. Instantiates core components (WorkspaceManager, DatabaseManager, PolicyGuard,
   CacheManager, StorageManager, JobQueue, AnalysisTaskRunner)
3. Creates the `MCPServer` instance
4. Calls `await registerAllTools(server, deps)` — the single point of tool/prompt/resource registration
5. Starts the server and wires graceful shutdown handlers

## Tool Registry

**File:** `src/tool-registry.ts`

The tool registry is the centralised place where every MCP tool, prompt, and
resource is imported and wired to its handler factory. This replaces the earlier
pattern of registering tools inline in `index.ts`.

### `ToolDeps` interface

Every handler factory receives a subset of these dependencies:

```typescript
interface ToolDeps {
  workspaceManager: WorkspaceManager
  database: DatabaseManager
  policyGuard: PolicyGuard
  cacheManager: CacheManager
  jobQueue: JobQueue
  storageManager: StorageManager
  config: Config
  server: MCPServer
}
```

### `registerAllTools(server, deps)`

An `async` function that:

1. Registers 148 MCP tools, grouped by category:
   - Core (ingest, profile, triage)
   - LLM-assisted review (naming, explanation, reconstruction)
   - PE analysis (structure, headers, sections, exports)
   - Strings and static analysis
   - Workflows (analyze, summarize, reconstruct)
   - Reports and exports
   - Ghidra integration
   - Dynamic analysis (Frida, trace, memory)
   - Docker backend tools
   - Threat intelligence
   - Code analysis (CFG, decompile, diff)
   - Unpacking and packer detection
   - Vulnerability analysis
   - Knowledge base
   - ELF/Mach-O, Debug, VM detection
   - **Plugin-managed categories** (Android, CrackMe, Dynamic automation, Malware)
2. Registers 3 MCP prompts (semantic name review, function explanation, module reconstruction)
3. Registers 16 MCP resources via `registerScriptResources()` (8 Frida + 8 Ghidra scripts)
4. Calls `loadPlugins(server, deps)` for plugin-managed tool categories

### Adding a new tool

1. Create `src/tools/my-new-tool.ts` exporting `myNewToolDefinition` (schema) and `createMyNewToolHandler(deps…)` (factory)
2. Import both in `src/tool-registry.ts`
3. Add `server.registerTool(myNewToolDefinition, createMyNewToolHandler(…))` in the appropriate category section
4. Add a test file at `tests/unit/my-new-tool.test.ts`

## Plugin Architecture

**File:** `src/plugins.ts` — Full guide: [PLUGINS.md](./PLUGINS.md)

Four tool categories are managed as plugins that can be enabled/disabled via the
`PLUGINS` environment variable:

| Plugin ID  | Tools Registered |
|------------|------------------|
| `android`  | `apk.structure.analyze`, `dex.decompile`, `dex.classes.list`, `apk.packer.detect` |
| `malware`  | `c2.extract`, `malware.config.extract`, `malware.classify`, `sandbox.report` |
| `crackme`  | `crackme.locate_validation`, `symbolic.explore`, `patch.generate`, `keygen.verify` |
| `dynamic`  | `dynamic.auto_hook`, `dynamic.trace_attribute`, `dynamic.memory_dump` |

By default all plugins are enabled (`PLUGINS=*`). See [PLUGINS.md](./PLUGINS.md)
for selection syntax and custom plugin development.

## MCP Resources

The server exposes analysis helper scripts as MCP resources. Clients can
discover them via `resources/list` and read their content via `resources/read`.

### Registered resources

**Frida scripts** (8):

| URI | Description |
|-----|-------------|
| `script://frida/api_trace.js` | Windows API tracing with argument logging |
| `script://frida/string_decoder.js` | Runtime string decryption |
| `script://frida/anti_debug_bypass.js` | Anti-debug bypass |
| `script://frida/crypto_finder.js` | Cryptographic API detection |
| `script://frida/file_registry_monitor.js` | File/registry monitoring |

**Ghidra scripts** (8):

| URI | Description |
|-----|-------------|
| `script://ghidra/ExtractFunctions.java` | Function extraction |
| `script://ghidra/DecompileFunction.java` | Function decompilation |
| `script://ghidra/ExtractCFG.java` | Control flow graph extraction |
| `script://ghidra/AnalyzeCrossReferences.java` | Cross-reference analysis |
| `script://ghidra/SearchFunctionReferences.java` | Function reference search |

The resource handler reads script files from disk on demand and returns their
content as `text/javascript` or `text/x-java-source`.

## Safe Command Execution

**File:** `src/safe-command.ts`

All external command invocations go through a command safety layer that prevents
injection attacks:

- **Whitelist regex validation**: Command names are validated against
  `SAFE_COMMAND_NAME_RE = /^[a-zA-Z0-9._/:\\-]+$/` before execution.
- **Array-based arguments**: Uses `execFileSync` / `spawnSync` with argument
  arrays instead of string interpolation — eliminating shell injection vectors.
- **`safeCommandExists(cmd)`**: Checks whether a command is available on PATH
  without shell evaluation.
- **`safeGetCommandVersion(cmd, args)`**: Safely retrieves version output from
  external tools.
- **`validateGraphvizFormat(fmt)`**: Whitelist-based validation for Graphviz
  output format parameters.

All callers in `env-validator.ts`, `cfg-visual-exports.ts`, and tool handlers
use these safe wrappers.

## Python Process Pool

**File:** `src/python-process-pool.ts`

Python workers (static analysis, APK parsing, symbolic execution, etc.) are
executed through a concurrency-limited process pool:

- **Queue-based**: Incoming requests are queued FIFO when the pool is at capacity.
- **Configurable**: `MAX_PYTHON_WORKERS` env var (default: `min(cpu_count, 8)`).
- **Lifecycle**: Workers are tracked from spawn to completion; on timeout,
  `SIGTERM` is sent with a fallback to `SIGKILL`.
- **Observable**: `pythonProcessPool.getStats()` returns `{ active, queued, max, total_completed }`,
  surfaced through `system.health`.

## Streaming / Progress Notifications

**File:** `src/streaming-progress.ts`

Long-running tools can report progress to clients via the MCP `notifications/progress`
mechanism:

```typescript
interface ProgressReporter {
  report(progress: number, message?: string): void
}
```

- When a client sends `_meta.progressToken` with a tool call, the server
  creates a real `ProgressReporter` that emits `notifications/progress`
  notifications.
- Without a token, a no-op reporter is returned — zero overhead.
- The `MCPServer.getProgressReporter(token?)` public method is available to any
  tool handler.

### Example usage in a handler

```typescript
const reporter = server.getProgressReporter(progressToken)
reporter.report(0, 'Starting analysis…')
// … do work …
reporter.report(50, 'Halfway done')
// … finish …
reporter.report(100, 'Complete')
```

## Structured Logging

**File:** `src/logger.ts`

All server components use [Pino](https://github.com/pinojs/pino) structured
JSON logging:

- Child loggers per component: `logger.child({ component: 'ghidra' })`
- `logOperationStart / logOperationComplete / logOperationError` helpers
- Audit events via `AuditEvent` type for security-relevant operations
- No `console.log` / `console.error` in production code paths

## CI/CD Security Scanning

**File:** `.github/workflows/ci.yml`

The CI pipeline includes a dedicated `security` job:

1. **npm audit** — Checks for known vulnerabilities in Node.js dependencies
2. **pip-audit** — Checks Python dependencies for CVEs
3. **CodeQL SAST** — Static application security testing via GitHub's CodeQL engine

This runs on every push and pull request alongside the existing build and test jobs.
