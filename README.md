# Rikune

Chinese version: [`README_zh.md`](./README_zh.md)

An MCP server for Windows reverse engineering. It exposes PE triage, Ghidra-backed inspection, DLL/COM profiling, runtime evidence ingestion, Rust/.NET recovery, source-like reconstruction, and LLM-assisted review as reusable MCP tools for any tool-calling LLM.

## Feature highlights

- Universal Windows PE coverage: EXE, DLL, COM-oriented libraries, Rust-native samples, and .NET assemblies all have dedicated profiling or recovery paths.
- Recover-first design: when Ghidra function extraction is empty or degraded, the server can continue with `.pdata` parsing, boundary recovery, symbol recovery, and imported function definitions.
- Observable Ghidra runs: command logs, runtime logs, staged progress, project/log roots, and parsed Java exception summaries are surfaced through high-level outputs.
- Runtime-aware reconstruction: static evidence, trace imports, memory snapshots, and semantic review artifacts can all be correlated back into reconstruct and report workflows.
- LLM-assisted review layers: function naming, function explanation, and module reconstruction review are exposed as structured MCP flows instead of ad hoc prompts.
- Queue-friendly orchestration: persisted staged runs are the primary workflow model, while low-level queued jobs remain available for raw execution inspection.
- Full Linux analysis image: the Docker distribution now bundles Graphviz, Rizin, YARA-X, UPX, Wine/winedbg, Frida CLI, Qiling, angr, PANDA bindings, and RetDec in addition to the baseline Ghidra/capa/DIE/FLOSS stack.
- **Staged nonblocking pipeline**: analysis is organized into explicit stages (`fast_profile`, `enrich_static`, `function_map`, `reconstruct`, `dynamic_plan`, `dynamic_execute`, `summarize`), with preview-first tool contracts and persisted run state for reuse.
- **HTTP File Server**: Embedded HTTP API on port 18080 for direct sample uploads, artifact downloads, and upload session management with API key authentication.
- **Web Dashboard**: Dark-themed real-time monitoring dashboard at `http://localhost:18080/dashboard` — shows all tools, plugins, samples, config diagnostics, system resources, and SSE event stream.
- **Server-Sent Events (SSE)**: Real-time event streaming at `/api/v1/events` for analysis progress, sample ingestion, and server state changes.

## New in the staged analysis pipeline

This iteration introduces a unified nonblocking analysis pattern to prevent MCP
request timeouts on large or expensive samples:

- `workflow.analyze.start` initiates or reuses a persisted staged analysis run. Only the `fast_profile` stage executes inline; heavier stages are queued by default.
- `workflow.analyze.status` queries aggregate run status, including deferred jobs, completed stages, and reusable artifact refs.
- `workflow.analyze.promote` promotes an existing run to deeper stages without rerunning completed work.
- Heavy tools (`strings.extract`, `binary.role.profile`, `analysis.context.link`, `crypto.identify`) now provide explicit bounded preview modes before deeper queued execution.
- `workflow.summarize` consumes persisted run state and stage artifacts instead of rerunning hidden heavy analysis.
- Coverage envelope fields (`coverage_level`, `completion_state`, `coverage_gaps`, `upgrade_paths`) provide machine-readable analysis boundaries and next-step guidance.
- Run/report surfaces now expose `recovery_state`, `recoverable_stages`, `evidence_state`, `provenance_visibility`, and `persisted_state_visibility` so clients can tell what was reused, deferred, or interrupted.
- Scheduler-aware status now exposes `execution_bucket`, `cost_class`, `worker_family`, `budget_deferral_reason`, `warm_reuse`, and `cold_start`, so clients can tell why work was admitted, deferred, or reused.
- Memory-aware status also exposes `expected_rss_mb`, `current_rss_mb`, `peak_rss_mb`, `memory_limit_mb`, and `control_plane_headroom_mb` when heavy work is admitted, deferred, or interrupted.
- Large-sample full evidence may now be returned as a bounded inline digest plus `chunk_manifest` and persisted chunk artifacts instead of one monolithic payload.
- Preview helpers now prefer pooled warm execution for static Python helpers and `Rizin` preview inspection, while `Ghidra` remains on isolated deep-attribution lanes.

Primary runtime docs:

- [Analysis Runtime](./docs/ANALYSIS-RUNTIME.md)
- [Async Job Pattern](./docs/ASYNC-JOB-PATTERN.md)
- [Migration To The Staged Runtime](./docs/MIGRATION-ASYNC.md)

### Explanation-first graph surfaces

Graph-capable tools are now meant to help AI agents and analysts explain why a
finding exists, not to decorate reports.

- `workflow.summarize` and `report.summarize` surface bounded explanation graph artifacts instead of relying on large inline graph payloads.
- `code.function.cfg` is the primary local navigation graph surface; Mermaid and DOT are serializer choices over the same bounded graph semantics.
- `graphviz.render` is a renderer/export helper for existing graph artifacts, not a primary analysis workflow.
- Explanation graph outputs now distinguish `observed`, `correlated`, and `inferred` content and carry provenance plus omission markers.

### Primary vs compatibility surfaces

Treat tool surfaces as role-scoped:

- Primary orchestration: `workflow.analyze.start`, `workflow.analyze.status`, `workflow.analyze.promote`, `workflow.summarize`
- Compatibility facades: `workflow.triage`, `task.status`, `report.summarize`
- Export-only surfaces: `report.generate`
- Renderer/export helpers: `graphviz.render`

When both a primary and compatibility surface exist, prefer the primary staged-runtime path.

### Recommended calling patterns

**For quick triage:**
```
workflow.analyze.start(sample_id, goal='triage')
→ Returns fast_profile stage result inline
→ Check coverage_gaps and upgrade_paths for next steps
```

**For deep analysis:**
```
workflow.analyze.start(sample_id, goal='reverse')
→ Returns queued status with job_id
→ Poll workflow.analyze.status(run_id) until completed
→ Promote to deeper stages as needed
```

**For large or oversized samples:**
```
workflow.analyze.start(sample_id, goal='triage')
→ workflow.analyze.status(run_id)
→ workflow.analyze.promote(run_id, through_stage='enrich_static')
→ workflow.analyze.status(run_id)
→ workflow.analyze.promote(run_id, through_stage='function_map')
→ workflow.summarize(sample_id, through_stage='final')
```

Keep `report.summarize(detail_level='compact')` for large samples. The runtime now downshifts `detail_level='full'` back to compact when the sample tier is too large for safe inline reporting.

**For summary:**
```
workflow.summarize(sample_id, through_stage='final')
→ Automatically consumes any existing analysis run state
→ Returns compact analyst-facing summary
```

## New in the static triage foundation

This iteration adds a stronger first-pass static analysis layer before deep
reverse engineering:

- `static.capability.triage` uses `capa`-style behavior classification to
  answer what a sample appears capable of, not just what strings or imports it
  contains.
- `pe.structure.analyze` merges `pefile` and `LIEF` style structural parsing
  into one canonical PE summary with backend-specific detail blocks.
- `compiler.packer.detect` adds compiler, protector, and packer attribution
  with setup-aware degradation when Detect It Easy is unavailable.
- `workflow.triage`, `report.summarize`, and `report.generate` now consume
  these results directly, including artifact provenance, static scope selection,
  and compare/baseline support.

## Typical analysis flows

### Quick triage

1. `sample.ingest`
2. `static.capability.triage`
3. `pe.structure.analyze`
4. `compiler.packer.detect`
5. `workflow.triage`
6. `report.summarize`

### Hard native recovery

1. `ghidra.analyze`
2. `workflow.function_index_recover`
3. `workflow.reconstruct`

### LLM-assisted refinement

1. `workflow.reconstruct`
2. `workflow.semantic_name_review`
3. `workflow.function_explanation_review`
4. `workflow.module_reconstruction_review`

## What this server is for

This project is meant to be a reusable reverse-engineering tool surface, not a pile of one-off local scripts.

It is designed to help MCP clients:

- triage Windows PE samples quickly
- inspect imports, exports, strings, packers, runtime hints, and binary role
- use Ghidra when available for decompile, CFG, search, and reconstruction
- recover usable function indexes when Ghidra function extraction fails
- surface actionable setup guidance when Java, Python extras, or Ghidra are missing
- expose richer Ghidra diagnostics, command logs, and stage/progress metadata when analysis fails
- correlate static evidence, runtime traces, memory snapshots, and semantic review artifacts
- export source-like reconstruction output with optional build and harness validation

## Core capability areas

### Sample and static analysis

- `sample.ingest`
- `sample.profile.get`
- `static.capability.triage`
- `pe.structure.analyze`
- `compiler.packer.detect`
- `pe.fingerprint`
- `pe.imports.extract`
- `pe.exports.extract`
- `pe.pdata.extract`
- `dll.export.profile`
- `com.role.profile`
- `strings.extract`
- `strings.floss.decode`
- `yara.scan`
- `runtime.detect`
- `packer.detect`
- `binary.role.profile`
- `system.setup.guide`

### Ghidra and function analysis

- `ghidra.health`
- `ghidra.analyze`
- `code.functions.list`
- `code.functions.rank`
- `code.functions.search`
- `code.function.decompile`
- `code.function.disassemble`
- `code.function.cfg`
- `code.functions.reconstruct`

### Recovery for Rust and hard native samples

- `code.functions.smart_recover`
- `pe.symbols.recover`
- `code.functions.define`
- `rust_binary.analyze`
- `workflow.function_index_recover`

### .NET and managed inspection

- `dotnet.metadata.extract`
- `dotnet.types.list`
- `dotnet.reconstruct.export`

### Runtime evidence and reporting

- `dynamic.dependencies`
- `sandbox.execute`
- `dynamic.trace.import`
- `dynamic.memory.import`
- `dynamic.auto_hook` - Automated Frida hook generation from static evidence
- `dynamic.memory_dump` - Runtime memory dump with pattern scanning
- `attack.map`
- `ioc.export`
- `report.summarize`
- `report.generate`
- `artifacts.list`
- `artifact.read`
- `artifacts.diff`
- `tool.help`

### Android / APK analysis

- `apk.structure.analyze` - APK manifest, permissions, component extraction
- `apk.packer.detect` - APK packer/obfuscator detection
- `dex.decompile` - DEX-to-Java decompilation via jadx
- `dex.classes.list` - DEX class/method enumeration

### Symbolic execution & CrackMe

- `symbolic.explore` - angr-backed symbolic execution
- `keygen.verify` - Keygen/license verification (Qiling/angr)
- `constraint.solve` - Z3/angr constraint solver

### Malware analysis

- `malware.config.extract` - Malware configuration extraction
- `malware.classify` - Family classification (YARA + capa + behavioral)
- `c2.extract` - C2 infrastructure extraction

### Cross-platform & visualization

- `elf.macho.parse` - ELF/Mach-O header/section parsing via Rizin
- `rizin.diff` - Binary diffing (function/basic-block level)
- `cfg.visualize` - Control flow graph visualization (DOT/SVG/JSON)
- `timeline.correlate` - Multi-source event timeline correlation
- `cross_module.xref` - Cross-module cross-reference analysis
- `kb.search` - Knowledge base semantic search

### Semantic review and reconstruction

- `code.function.rename.prepare` (deprecated, use `llm.analyze`)
- `code.function.rename.review` (deprecated, use `llm.analyze`)
- `code.function.rename.apply` (deprecated, use `llm.analyze`)
- `code.function.explain.prepare` (deprecated, use `llm.analyze`)
- `code.function.explain.review` (deprecated, use `llm.analyze`)
- `code.function.explain.apply` (deprecated, use `llm.analyze`)
- `code.module.review.prepare` (deprecated, use `llm.analyze`)
- `code.module.review` (deprecated, use `llm.analyze`)
- `code.module.review.apply` (deprecated, use `llm.analyze`)
- `code.reconstruct.plan`
- `code.reconstruct.export`

### LLM-assisted analysis (NEW)

- `llm.analyze` - Unified LLM analysis interface (replaces deprecated 3-step tools)
  - `task: 'summarize'` - Concise summaries
  - `task: 'explain'` - Clear explanations
  - `task: 'recommend'` - Actionable recommendations
  - `task: 'review'` - Critical review

## High-level workflows

These are the main orchestration entrypoints for MCP clients.

### `workflow.triage`

Fast first-pass triage facade for PE samples. Use this when you want a bounded `fast_profile` view backed by the staged run model.

**Important**: Treat this as a compatibility view, not as proof that deeper static analysis already completed. Use `workflow.analyze.promote` or `workflow.analyze.status` for deeper work.

### `workflow.deep_static`

Long-running static pipeline for deeper analysis and ranking. Supports async job mode.

**Note**: Prefer `workflow.analyze.start` plus `workflow.analyze.promote` for the primary nonblocking client flow. Use `task.status` only when you need raw job details.

### `workflow.reconstruct`

The main high-level reconstruction workflow.

**Note**: Prefer the staged run model for orchestration and reuse. `workflow.reconstruct` remains a deep workflow surface, but `workflow.analyze.status` should be your first progress lookup.

## Run And Job Model

The server now has two distinct layers:

- **Run layer**: `workflow.analyze.start/status/promote`
- **Job layer**: `task.status/task.cancel/task.sweep`

Preferred client flow:

**Example:**
```typescript
const start = await workflow.analyze.start({ sample_id: '...', goal: 'reverse' })
const runId = start.data.run_id

await workflow.analyze.promote({ run_id: runId, through_stage: 'function_map' })
const status = await workflow.analyze.status({ run_id: runId })
```

**Documentation:**
- [Analysis Runtime](docs/ANALYSIS-RUNTIME.md)
- [Async Job Pattern Guide](docs/ASYNC-JOB-PATTERN.md)
- [Migration Guide](docs/MIGRATION-ASYNC.md)
- tune export strategy based on role-aware preflight for native Rust, DLL, and COM-oriented samples
- return structured setup guidance when Java, Ghidra, or optional dependencies are not ready
- expose stage-oriented progress metadata for queued and foreground runs
- carry runtime and semantic provenance through the result

### `workflow.function_index_recover`

High-level recovery chain for hard native binaries:

- `code.functions.smart_recover`
- `pe.symbols.recover`
- `code.functions.define`

Use this when Ghidra analysis exists but function extraction is empty or degraded.

### `workflow.semantic_name_review`

High-level semantic naming review workflow for external LLM clients. It can prepare evidence, request model review through MCP sampling when available, apply accepted names, and optionally refresh reconstruct/export output. When export refresh runs, the workflow now carries the same `ghidra_execution` summary used by `workflow.reconstruct`, including project root, log root, command/runtime log paths, progress stages, and parsed Java exception context.

### `workflow.function_explanation_review`

High-level explanation workflow for external LLM clients. It can prepare evidence, request structured explanations, apply them, and optionally rerun reconstruct/export. Export refresh results also surface `ghidra_execution` so explanation-heavy review chains still expose Ghidra project/log context and progress metadata.

### `workflow.module_reconstruction_review`

High-level module review workflow for external LLM clients. It can prepare reconstructed modules for review, request structured module refinements through MCP sampling when available, apply accepted module summaries and guidance, and optionally refresh reconstruct/export output. When export refresh runs, the workflow also carries `ghidra_execution` so module-level review chains expose Ghidra project/log context and progress metadata just like reconstruct and function-level review workflows.

## Universal recovery model

This server does not assume Ghidra is always able to recover functions correctly.

For difficult native samples, especially Rust, Go, or heavily optimized binaries, the recovery path is:

1. `ghidra.analyze`
2. if Ghidra post-script extraction fails, use `pe.pdata.extract`
3. recover candidate function boundaries with `code.functions.smart_recover`
4. recover names with `pe.symbols.recover`
5. import the recovered boundaries with `code.functions.define`
6. continue with `code.functions.list`, `code.functions.rank`, `code.functions.reconstruct`, or `workflow.reconstruct`

This means `function_index` readiness is tracked separately from `decompile` and `cfg` readiness.

## Evidence scope, semantic scope, and replayability

Most high-level tools support explicit scope control so clients can choose between all history and the current session.

Runtime evidence selection:

- `evidence_scope=all`
- `evidence_scope=latest`
- `evidence_scope=session` with `evidence_session_tag`

Semantic naming / explanation / module-review selection:

- `semantic_scope=all`
- `semantic_scope=latest`
- `semantic_scope=session` with `semantic_session_tag`

Comparison-aware outputs are also supported through:

- `compare_evidence_scope`
- `compare_evidence_session_tag`
- `compare_semantic_scope`
- `compare_semantic_session_tag`

This allows MCP clients to ask not only "what is the current result?" but also "what changed compared with the previous evidence or semantic review session?"

Static-analysis artifact selection:

- `static_scope=all`
- `static_scope=latest`
- `static_scope=session` with `static_session_tag`

Static baseline comparison:

- `compare_static_scope`
- `compare_static_session_tag`

## LLM review layers

This server supports multiple structured review layers for MCP clients with tool calling and optional sampling:

- function naming review
- function explanation review
- module reconstruction review

Each layer follows the same pattern:

1. prepare a structured evidence bundle
2. optionally ask the connected MCP client to perform a constrained review through sampling
3. apply accepted results as stable semantic artifacts
4. rerun reconstruct/export/report workflows against explicit semantic scope

## Async job model

Long-running workflows support queued execution and background completion:

- `workflow.deep_static`
- `workflow.reconstruct`
- `workflow.semantic_name_review`
- `workflow.function_explanation_review`
- `workflow.module_reconstruction_review`

Use these with:

- `task.status`
- `task.cancel`
- `task.sweep`

Queued workflow responses and `task.status` include `polling_guidance`, but the primary staged orchestration surface is still `workflow.analyze.status`.
When a long-running stage is queued/running, MCP clients should prefer run-level status first and only fall back to `task.status` for raw queue details.

## Environment bootstrap and setup guidance

If a client starts using the server before Python, dynamic-analysis extras, or Ghidra are configured, use:

- `system.health`
- `dynamic.dependencies`
- `ghidra.health`
- `system.setup.guide`

These return structured setup actions and required user inputs so an MCP client can explicitly ask for:

- `python -m pip install ...`
- `JAVA_HOME`
- `GHIDRA_PATH` / `GHIDRA_INSTALL_DIR`
- `GHIDRA_PROJECT_ROOT` / `GHIDRA_LOG_ROOT`
- `CAPA_RULES_PATH`
- `DIE_PATH`
- optional dynamic-analysis extras such as Speakeasy/Frida dependencies
- Docker full-stack extras such as Graphviz/Rizin/YARA-X/UPX/Wine/Qiling/angr/PANDA/RetDec

### Frida Dynamic Instrumentation (Optional)

For runtime API tracing and behavioral analysis, install Frida:

```bash
pip install frida frida-tools
```

**Environment Variables** (optional - auto-detected when `frida` is in PATH):

- `FRIDA_SERVER_PATH` - Path to Frida server binary for USB/remote device analysis
- `FRIDA_DEVICE` - Device ID or "usb" for USB device selection (default: local spawn)

**Pre-built Scripts** are included in `frida_scripts/`:
- `api_trace.js` - Windows API tracing with argument logging
- `string_decoder.js` - Runtime string decryption
- `anti_debug_bypass.js` - Anti-debug detection neutralization
- `crypto_finder.js` - Cryptographic API detection
- `file_registry_monitor.js` - File/registry operation tracking

See [`docs/EXAMPLES.md`](./docs/EXAMPLES.md#场景 -9-frida-运行时 instrumentation) for usage examples.

## Current Development Status

### Latest Release: v1.0.0-beta.2

**Stable Features** (Production Ready):
- PE triage and static analysis (`static.capability.triage`, `pe.structure.analyze`, `compiler.packer.detect`)
- Ghidra-backed inspection with full execution visibility
- DLL/COM profiling (`dll.export.profile`, `com.role.profile`)
- Rust and .NET recovery paths
- Source-like reconstruction with LLM-assisted review layers
- Runtime evidence ingestion and correlation
- Android/APK analysis (`apk.structure.analyze`, `dex.decompile`, `dex.classes.list`, `apk.packer.detect`)
- Symbolic execution and CrackMe tools (`symbolic.explore`, `keygen.verify`, `constraint.solve`)
- Malware analysis (`malware.config.extract`, `malware.classify`, `c2.extract`)
- Cross-platform binary parsing (`elf.macho.parse`, `rizin.diff`)
- Visualization and correlation (`cfg.visualize`, `timeline.correlate`, `cross_module.xref`, `kb.search`)
- Frida dynamic instrumentation (`frida.runtime.instrument`, `frida.script.inject`, `frida.trace.capture`)
- HTTP File Server with REST API (port 18080) — sample upload, artifact CRUD, SSE events
- **Web Dashboard** at `http://localhost:18080/dashboard` — real-time monitoring of tools, plugins, samples, config, system
- **Plugin SDK** with 15 built-in plugins, hot-load/unload, third-party auto-discovery
- **Production infrastructure**: Rate limiting, config validation, pagination, retry, batch analysis, SBOM generation
- **SSE real-time events**: Server-Sent Events for live analysis progress streaming

### Full Service Inventory (Docker)

When running in Docker (`docker-compose up -d`), the container exposes:

| Service | Access | Description |
|---------|--------|-------------|
| MCP Server | stdio (`docker exec -i`) | 160 tools, 3 prompts, 16 resources for LLM clients |
| HTTP API | `http://localhost:18080/api/v1/*` | REST API for samples, artifacts, uploads, health, SSE |
| Web Dashboard | `http://localhost:18080/dashboard` | Real-time monitoring SPA (8 tabs, dark theme) |
| SSE Events | `http://localhost:18080/api/v1/events` | Real-time event stream for analysis events |
| Dashboard API | `http://localhost:18080/api/v1/dashboard/*` | 12 JSON endpoints powering the dashboard |

### Built-in Plugins (15)

| Plugin | ID | Tools | Description |
|--------|----|-------|-------------|
| Android / APK | `android` | 4 | APK manifest, DEX decompilation, packer detection |
| Malware Analysis | `malware` | 4 | C2 extraction, config parsing, family classification, sandbox reports |
| CrackMe Automation | `crackme` | 4 | Validation location, symbolic execution, patching, keygen |
| Dynamic Analysis | `dynamic` | 3 | Auto Frida hooks, trace attribution, memory dumps |
| Frida Instrumentation | `frida` | 3 | Runtime instrumentation, script injection, trace capture |
| Ghidra Integration | `ghidra` | 2 | Headless Ghidra analysis and health checks |
| Cross-Module Analysis | `cross-module` | 3 | Cross-binary comparison, call graphs, DLL dependency trees |
| Visualization | `visualization` | 3 | HTML reports, behavior timelines, data-flow maps |
| Knowledge Base | `kb-collaboration` | 2 | Function signature matching, analysis templates |
| PE Analysis | `pe-analysis` | 6 | PE structure, imports, exports, fingerprint, pdata, symbol recovery |
| Vulnerability Scanner | `vuln-scanner` | 2 | Vulnerability pattern scanning and summary |
| Threat Intelligence | `threat-intel` | 2 | ATT&CK mapping and IOC export |
| Debug Session | `debug-session` | 6 | GDB/LLDB debug session management |
| Memory Forensics | `memory-forensics` | 6 | Memory dump analysis, volatility integration |
| Observability | `observability` | 1 | Tool call hook tracing and metrics |

Plugins are controlled via the `PLUGINS` environment variable (`*` = all, `android,malware` = specific, `-dynamic` = exclude). See [`docs/PLUGINS.md`](./docs/PLUGINS.md).

### In Development (Post-beta roadmap)

For the new static triage foundation, the most common optional requirements are:

- `flare-capa`
- `pefile`
- `lief`
- a downloaded capa rules bundle referenced by `CAPA_RULES_PATH`
- Detect It Easy CLI referenced by `DIE_PATH`

The Docker image now bundles the static-analysis stack by default:

- `flare-capa`
- a container-local `capa` CLI wrapper at `/usr/local/bin/capa`
- bundled `capa-rules` at `/opt/capa-rules`
- bundled `capa` signatures at `/opt/capa-sigs`
- bundled Detect It Easy CLI at `/usr/bin/diec` using the stable `3.10 Debian 12` package

For Ghidra 12.0.4, the server expects Java 21+ and will report explicit Java compatibility hints through:

- `ghidra.health`
- `system.health`
- `system.setup.guide`

For Docker deployments, that means a Java 21+ JDK, not only a JRE. The containerized runtime should expose both `java` and `javac`.

When Ghidra commands fail, the server now persists command logs and, when available, Ghidra runtime logs. Normalized diagnostics include Java exception summaries and remediation hints instead of only returning `exit code 1`.

The bundled `ghidra_scripts/` directory is resolved from the installed package
or repository root, not from the current working directory. This prevents
`ExtractFunctions.py` / `ExtractFunctions.java` lookup failures when the server
is launched from a different folder.

## Ghidra execution visibility

High-level outputs now expose a structured `ghidra_execution` block instead of hiding Ghidra details behind generic success/failure states.

You can now see:

- which analysis record was selected
- whether the result came from the best ready analysis or only the latest attempt
- project path, project root, and log root
- persisted command logs and runtime logs
- function extraction status and script name
- staged progress metadata
- parsed Java exception summaries when Ghidra fails

This summary is surfaced through:

- `workflow.reconstruct`
- `workflow.semantic_name_review` when export refresh runs
- `workflow.function_explanation_review` when export refresh runs
- `workflow.module_reconstruction_review` when export refresh runs
- `report.summarize`
- `report.generate`

## Architecture

The server uses a **centralised tool registry** (`src/tool-registry.ts`) that
imports and wires 109 core MCP tools, 3 prompts, and 16 resources in one place.
An additional 51 tools are registered by the 15 built-in plugins, bringing the
total to 160 MCP tools.
The entry point (`src/index.ts`) is kept under 90 lines.

All 15 tool categories — from PE analysis and vulnerability scanning to Android,
Malware, Frida, Ghidra, and debug sessions — are managed as **plugins** that
can be toggled via the `PLUGINS` environment variable (default: all enabled).
See [docs/PLUGINS.md](./docs/PLUGINS.md).

Other infrastructure:

| Component | File | Purpose |
|-----------|------|---------|
| Safe command execution | `src/safe-command.ts` | Whitelist-validated, array-based command invocation — prevents shell injection |
| Python process pool | `src/python-process-pool.ts` | Concurrency-limited worker pool (`MAX_PYTHON_WORKERS` env var) |
| Streaming progress | `src/streaming-progress.ts` | MCP `notifications/progress` for long-running tools |
| MCP resources | `src/tool-registry.ts` | 8 Frida + 8 Ghidra scripts discoverable via `resources/list` |
| HTTP File Server | `src/api/file-server.ts` | REST API (port 18080) for sample upload, artifact CRUD, SSE events, and dashboard |
| Web Dashboard | `src/api/dashboard/index.html` | Dark-themed SPA at `/dashboard` — tools, plugins, samples, config, system info |
| Dashboard API | `src/api/routes/dashboard-api.ts` | 12 JSON endpoints (`/api/v1/dashboard/*`) powering the web dashboard |
| SSE Events | `src/api/sse-events.ts` | Server-Sent Events for real-time analysis progress and server state |
| Rate Limiter | `src/api/rate-limiter.ts` | Request rate limiting for the HTTP API |
| Config Validator | `src/config-validator.ts` | Validates runtime config and surfaces diagnostics via dashboard |
| CI security scanning | `.github/workflows/ci.yml` | npm audit + pip-audit + CodeQL SAST |
| Structured logging | `src/logger.ts` | Pino JSON logging, child loggers, audit events |

Full details: [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)

## Project layout

```text
bin/                         npm CLI entrypoint
dist/                        compiled TypeScript output
ghidra_scripts/              Ghidra helper scripts used by the server
frida_scripts/               Frida instrumentation scripts (also MCP resources)
helpers/DotNetMetadataProbe/ .NET metadata helper project
src/                         TypeScript MCP server source
  index.ts                   Entry point (~90 lines)
  server.ts                  MCPServer class (tools, prompts, resources)
  tool-registry.ts           Centralised tool/prompt/resource registration
  plugins.ts                 Plugin framework (15 built-in + auto-discovery)
  safe-command.ts            Command injection prevention
  python-process-pool.ts     Concurrency-limited Python worker pool
  streaming-progress.ts      MCP progress notification support
  config-validator.ts        Runtime config validation with diagnostics
  logger.ts                  Pino structured logging
  tools/                     Individual tool definitions and handlers (~90 files)
  plugins/
    sdk.ts                   Plugin contract and shared types
    android/                 Android/APK analysis plugin
    crackme/                 CrackMe automation plugin
    cross-module/            Cross-binary analysis plugin
    debug-session/           GDB/LLDB debug session plugin
    dynamic/                 Dynamic analysis plugin
    frida/                   Frida instrumentation plugin
    ghidra/                  Ghidra integration plugin
    kb-collaboration/        Knowledge base plugin
    malware/                 Malware analysis plugin
    memory-forensics/        Memory forensics plugin
    observability/           Tool call tracing plugin
    pe-analysis/             PE binary analysis plugin
    threat-intel/            Threat intelligence plugin
    visualization/           Reporting and visualization plugin
    vuln-scanner/            Vulnerability pattern detection plugin
  api/
    file-server.ts           HTTP API server (port 18080)
    rate-limiter.ts          Request rate limiting
    auth-middleware.ts       API key authentication
    sse-events.ts            Server-Sent Events for real-time streaming
    dashboard/index.html     Web dashboard SPA (dark theme, 8 tabs)
    routes/
      health.ts              Health check endpoint
      dashboard-api.ts       Dashboard JSON API (12 endpoints)
tests/                       unit and integration tests (207 test files)
workers/                     Python workers, YARA rules, dynamic helpers
packages/plugin-sdk/         Standalone Plugin SDK npm package
docs/                        Documentation
  ARCHITECTURE.md            Internal architecture guide
  PLUGINS.md                 Plugin system guide
  DOCKER.md                  Docker deployment guide (with service inventory)
  API-FILE-SERVER.md         HTTP API usage guide
  API-REFERENCE.md           Complete API reference
  QUALITY_EVALUATION.md      Evaluation checklist for release readiness
```

## Prerequisites

### Option 1: Docker (Recommended - Zero Configuration)

The easiest way to run the MCP server with all dependencies pre-installed:

```bash
# Build the Docker image (10-15 minutes, ~2.5GB)
docker build -t rikune:latest .

# Or pull from registry (when published)
# docker pull ghcr.io/last-emo-boy/rikune:latest

# Run with Docker Compose
docker-compose up -d mcp-server

# Or run directly
docker run --rm -i \
  --network=none \
  -v ./samples:/samples:ro \
  -v ~/.rikune/workspaces:/app/workspaces \
  rikune:latest
```

See [`docs/DOCKER.md`](./docs/DOCKER.md) for complete Docker documentation.

The default Docker image is now a full Linux-side analysis stack. In addition to
the baseline `Ghidra`, `capa`, `Detect It Easy`, `FLOSS`, `legacy YARA`, and
`Speakeasy` components, it also bundles:

- `Graphviz`, `Rizin`, `YARA-X`, `UPX`, `RetDec`
- `frida-tools`, `Wine`, `winedbg`, `Qiling`（隔离解释器）, `angr`, `pandare`

Important caveats:

- `Qiling` still needs an externally mounted Windows rootfs via `QILING_ROOTFS`.
- `Wine` and `winedbg` are useful Linux-hosted user-mode helpers, not full Windows desktop debugging replacements.
- `RetDec` is a heavy backend and should be consumed artifact-first instead of returning oversized inline payloads.

### Option 2: Local Installation

Required:

- Node.js 18+
- npm 9+
- Python 3.9+

Optional but strongly recommended:

- Ghidra for native decompile and CFG features
- .NET SDK for `dotnet.metadata.extract`
- Clang for reconstruct export validation
- Python packages from [`requirements.txt`](./requirements.txt)
- Python worker packages from [`workers/requirements.txt`](./workers/requirements.txt)

## Local development

### Option 1: Docker Development (Recommended)

```bash
# Build image
npm run docker:build

# Test toolchain
npm run docker:test

# Enter container for debugging
npm run docker:run

# Clean up Docker resources
npm run docker:clean
```

### Option 2: Native Development

Install JavaScript dependencies:

```bash
npm install
```

Install Python worker dependencies:

```bash
python -m pip install -r requirements.txt
python -m pip install -r workers/requirements.txt
python -m pip install -r workers/requirements-dynamic.txt
```

Build:

```bash
npm run build
```

Run tests:

```bash
npm test
```

Start locally:

```bash
npm start
```

## MCP client configuration

### Generic stdio config

```json
{
  "mcpServers": {
    "rikune": {
      "command": "node",
      "args": ["/absolute/path/to/repo/dist/index.js"],
      "cwd": "/absolute/path/to/repo",
      "env": {
        "GHIDRA_PATH": "C:/path/to/ghidra",
        "GHIDRA_INSTALL_DIR": "C:/path/to/ghidra"
      }
    }
  }
}
```

### Docker Compose plus `docker exec`

For the single-container deployment model, start the daemon once with `docker compose up -d mcp-server` and point the MCP client at the running container:

```json
{
  "mcpServers": {
    "rikune": {
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "rikune",
        "node",
        "dist/index.js"
      ],
      "env": {
        "NODE_ENV": "production",
        "PYTHONUNBUFFERED": "1",
        "WORKSPACE_ROOT": "/app/workspaces",
        "DB_PATH": "/app/data/database.db",
        "CACHE_ROOT": "/app/cache",
        "GHIDRA_PROJECT_ROOT": "/ghidra-projects",
        "GHIDRA_LOG_ROOT": "/ghidra-logs"
      },
      "timeout": 300000
    }
  }
}
```

In this deployment, host-side file uploads should use `sample.request_upload` and the returned `http://localhost:18080/api/v1/uploads/<token>` URL instead of trying to pass a host filesystem path into the containerized worker.

### Local install helpers

- Codex: [`install-to-codex.ps1`](./install-to-codex.ps1)
- Claude Code: [`install-to-claude.ps1`](./install-to-claude.ps1)
- GitHub Copilot: [`install-to-copilot.ps1`](./install-to-copilot.ps1)

Related docs:

- [`CODEX_INSTALLATION.md`](./CODEX_INSTALLATION.md)
- [`COPILOT_INSTALLATION.md`](./COPILOT_INSTALLATION.md)
- [`CLAUDE_INSTALLATION.md`](./CLAUDE_INSTALLATION.md)
- [`docs/ANALYSIS-COVERAGE.md`](./docs/ANALYSIS-COVERAGE.md)

## Persistent storage

By default, runtime state is stored under the user profile instead of the current working directory:

- Windows workspace root: `%USERPROFILE%/.rikune/workspaces`
- SQLite database: `%USERPROFILE%/.rikune/data/database.db`
- File cache: `%USERPROFILE%/.rikune/cache`
- Audit log: `%USERPROFILE%/.rikune/audit.log`
- Ghidra project root: `%ProgramData%/.rikune/ghidra-projects`
- Ghidra log root: `%ProgramData%/.rikune/ghidra-logs`
- Bundled Ghidra scripts: resolved from the installed package root

You can override these with environment variables or the user config file:

- `%USERPROFILE%/.rikune/config.json`
- `WORKSPACE_ROOT`
- `DB_PATH`
- `CACHE_ROOT`
- `AUDIT_LOG_PATH`
- `GHIDRA_PROJECT_ROOT`
- `GHIDRA_LOG_ROOT`

## Sample ingest note

For local IDE clients such as VS Code or Copilot, prefer local file paths:

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "E:/absolute/path/to/sample.exe"
  }
}
```

Use `bytes_b64` only when the client cannot access the same filesystem as the server.

## Packed samples and debug-aware analysis

For suspected or confirmed packed binaries, prefer the staged unpack/debug path over immediate deep reconstruction:

```text
workflow.analyze.start
-> workflow.analyze.status
-> workflow.analyze.promote(dynamic_plan)
-> workflow.analyze.status
-> workflow.analyze.promote(dynamic_execute)
-> workflow.summarize
```

Important runtime fields:

- `packed_state`
- `unpack_state`
- `unpack_confidence`
- `unpack_plan`
- `debug_state`
- `debug_session`
- `diff_digests` / `unpack_debug_diffs`

Practical guidance:

- `upx.inspect(test|list)` is a safe unpack probe
- `upx.inspect(decompress)` is the bounded transform path for UPX-style samples
- `breakpoint.smart` and `trace.condition` are planning-only and help build a persisted debug session
- `frida.trace.capture` and `wine.run` remain manual or approval-gated execution surfaces
- `workflow.summarize` and `report.summarize(detail_level='compact')` should prefer unpack/debug diff digests over raw dump or trace trees

## Publishing to npm

The published package includes:

- compiled `dist/`
- the CLI entrypoint in `bin/`
- Python workers and YARA rules
- Ghidra helper scripts
- the .NET metadata helper source
- MCP client install scripts

It excludes:

- tests
- local workspaces
- caches
- generated reports
- scratch documents and internal progress notes

Pre-publish checklist:

1. Update the version in [`package.json`](./package.json).
2. Run `npm run release:check`.
3. Inspect `npm run pack:dry-run`.
4. Log in with `npm login`.
5. Publish with `npm publish --access public`.

GitHub automation included in this repository:

- [`ci.yml`](./.github/workflows/ci.yml)
- [`publish-npm.yml`](./.github/workflows/publish-npm.yml)
- [`dependabot.yml`](./.github/dependabot.yml)

For GitHub Actions publishing, configure the `NPM_TOKEN` repository secret.

## Security boundaries

This project is for analysis workflows, not live malware operations.

Current strengths:

- PE triage and classification support
- reverse-engineering evidence extraction
- IOC and ATT&CK export
- runtime evidence import and correlation
- source-like reconstruction and review

Current non-goals:

- original source recovery for complex native binaries
- guaranteed malware family attribution from static evidence alone
- fully automatic unpacking for every packer
- high-confidence semantic recovery of every function in heavily optimized code

## Contributing and release process

- Contributor guide: [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- Architecture overview: [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md)
- Plugin development: [`docs/PLUGINS.md`](./docs/PLUGINS.md)
- Quality evaluation notes: [`docs/QUALITY_EVALUATION.md`](./docs/QUALITY_EVALUATION.md)
- Example benchmark corpus: [`examples/benchmark-corpus.example.json`](./examples/benchmark-corpus.example.json)
- Security policy: [`SECURITY.md`](./SECURITY.md)

## Using the published package

The published npm package is now best treated as a thin MCP launcher, while Docker carries the heavy reverse-engineering runtime. That keeps npm and Docker separate, but intentionally strong-bound:

- `npm` / `npx` provides the client-facing executable and versioned launcher
- `docker compose up -d mcp-server` provides the persistent runtime, storage, upload API, and toolchain

This does **not** remove the existing source checkout or direct Docker client paths. If you are running from a cloned repo, `node dist/index.js` and direct `docker exec ... node dist/index.js` still work.

Recommended published-package flow:

1. Start the daemon runtime once:

```bash
docker compose up -d mcp-server
```

2. Point the MCP client at the npm launcher:

```json
{
  "mcpServers": {
    "rikune": {
      "command": "npx",
      "args": ["-y", "rikune", "docker-stdio"]
    }
  }
}
```

Optional overrides for the launcher:

- `RIKUNE_DOCKER_CONTAINER`
- `RIKUNE_DOCKER_IMAGE`

For local clone/native mode instead, keep using the earlier examples in this README that call `node /absolute/path/to/dist/index.js` directly.

## License

Released under the MIT license. See [`LICENSE`](./LICENSE).
