# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning where practical.

## [Unreleased]

### Security Hardening (P0)

- **Security headers**: All responses now include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and a strict `Content-Security-Policy`.
- **CORS lockdown**: Changed `Access-Control-Allow-Origin` from wildcard `*` to localhost-only origin reflection (127.0.0.1 / localhost).
- **Dashboard authentication**: Dashboard HTML and API routes now require API key when `API_KEY` is set. Supports `X-API-Key` header or `?key=` query parameter for browser access.
- **Docker health check**: Replaced fake `console.log('healthy')` with real HTTP GET to `/api/v1/health`.

### Dashboard UX (P2)

- **Toast notifications**: Error, warning, info, and success toasts with auto-dismiss. API errors now show visual feedback.
- **Global search (Ctrl+K)**: Modal search across tools, samples, and artifacts. Debounced input with result categories and click-to-navigate.
- **Export CSV/JSON**: Samples, Analyses, and Artifacts tabs now have export buttons to download data as CSV or JSON files.
- **Plugin detail drawer**: Click any plugin row to open a detail panel showing config schema, tool list, error details, and status.
- **Auto-refresh toggle**: Header toggle to auto-refresh the active tab every 10 seconds.
- **Page jump & per-page**: All paginated tabs now support direct page jump input and configurable rows per page (30/50/100).

### CI/CD (P3)

- **Lint step**: Added `npm run lint` to CI pipeline (continue-on-error).
- **Coverage reporting**: Added coverage generation step with artifact upload.
- **Fixed CI flags**: Replaced deprecated `--testPathPattern` with `--testPathPatterns`.

### API Performance (P4)

- **Response caching**: Dashboard API endpoints for tools, plugins, config, and system now include `Cache-Control`, `ETag` headers. Supports `If-None-Match` → 304 Not Modified.
- **Dashboard API documentation**: Added complete Dashboard API section to `docs/API-REFERENCE.md` documenting all 13 endpoints with parameters and response examples.

### Developer Experience (P5)

- **Dashboard hot-reload**: New `npm run dev:dashboard` script watches `src/api/dashboard/` and copies changes to dist on save.
- **Docker dev compose**: New `docker-compose.dev.yml` overlay mounts source code for live editing with dashboard hot-reload.

### Dashboard Iteration

- **Samples display fix**: Fixed `handleSamples` SQL query that selected non-existent columns (`original_name`, `file_size`), causing samples table to show blank rows. Now queries actual schema columns (`sha256`, `size`, `file_type`, `source`).
- **Sample detail drawer**: Clickable sample rows open a slide-in detail panel showing metadata grid, related analyses (with status badges and duration), artifacts (with inline view buttons), and top 20 functions ranked by score.
- **Analyses tab**: New dashboard tab with paginated analysis history table. Supports status filter dropdown (All / Done / Running / Queued / Failed) and clickable sample links.
- **Reports tab**: New dashboard tab for browsing and viewing artifacts inline.
  - Artifact list with type filter (auto-populated from backend) and path search.
  - **Markdown renderer**: Zero-dependency renderer supporting headers, bold/italic, code blocks, fenced code, tables, lists, blockquotes, links, horizontal rules.
  - **JSON syntax highlighter**: Recursive renderer with color-coded keys, strings, numbers, booleans, null.
  - **HTML viewer**: Sandboxed iframe rendering.
  - **SVG viewer**: DOMParser-based sanitized rendering.
  - **Code / text viewer**: Pre-formatted monospace display.
- **Dashboard API expansion**: 4 new endpoints — sample detail (`/samples/:id`), analyses listing, artifacts listing with type aggregation, artifact content reader with format detection.
- **Dashboard tab count**: 6 → 8 tabs (Overview, Tools, Plugins, Samples, Analyses, Reports, Config, System).

### Bug Fixes & Quality

- **Async error handling**: Fixed fire-and-forget `void handleArtifactContent(...)` in dashboard API — unhandled promise rejections now caught and logged with 500 response.
- **npm packaging**: Added `dist/**/*.html` and `data/*.json` to package.json `files` array — dashboard HTML and vuln-patterns data were missing from published npm package.
- **Structured logging**: Replaced `console.error` in `src/workflows/triage.ts` with project logger.
- **Code hygiene**: Moved `error-handler.example.ts` from `src/` to `examples/` to avoid shipping example code in production build.
- **npm scripts**: Added `test:coverage` (Jest with --coverage) and `validate` (build + lint + test).

### Plugin System Deep Refactoring

- **Plugin directory convention**: All plugin tool handlers migrated from flat `src/tools/` into `src/plugins/<id>/tools/` directories. Each plugin is now fully self-contained.
- **6 new plugins**: Expanded from 9 → 15 built-in plugins:
  - `vuln-scanner` — Vulnerability pattern scanning and summary (2 tools)
  - `pe-analysis` — PE structure, imports, exports, fingerprint, pdata, symbol recovery (6 tools)
  - `threat-intel` — ATT&CK mapping and IOC export (2 tools)
  - `debug-session` — GDB/LLDB debug session management (6 tools)
  - `memory-forensics` — Memory dump analysis, volatility integration (6 tools)
  - `observability` — Tool call hook tracing (1 tool)
- **Plugin SDK**: Added `ToolArgs` type to `src/plugins/sdk.ts`; unified handler signature to `(deps: PluginToolDeps)` pattern across all plugins.
- **Tool count**: 160 MCP tools total (109 registry + 51 plugin-managed).
- **Test coverage**: 207 test files (194 unit + 13 integration).

### Web Dashboard

- **Web Dashboard** (`src/api/dashboard/index.html`): Dark-themed single-page monitoring dashboard served at `http://localhost:18080/dashboard`. 6 tabs: Overview, Tools, Plugins, Samples, Config, System.
- **Dashboard API** (`src/api/routes/dashboard-api.ts`): 7 JSON REST endpoints (`/api/v1/dashboard/*`) — overview, tools (categorized), plugins, samples (paginated), workers, config validation, system info.
- **Real-time SSE integration**: Dashboard subscribes to `/api/v1/events` for live analysis event streaming.
- **Auto-refresh**: Overview tab auto-polls every 15 seconds; tool search and sample pagination are fully client-side.
- **Docker integration**: Dashboard HTML is copied to dist during build; Dockerfile includes static asset copy; `docker-compose.yml` port comment updated.

### Production Hardening (P0-P3)

- **CI test coverage** (P0): `.github/workflows/ci.yml` runs full test suite.
- **TODO stub completion** (P0): Implemented `keygen-synthesizer`, `worker-pool`, `context-manager`, `decompiler-worker`, `DatabaseManager.getDb()`, `WorkerPool.registerHandler()`.
- **Config validation** (P0): `src/config-validator.ts` with `validateConfig()` returning `ValidationReport`; `config.validate` MCP tool.
- **Rate limiting** (P1): `src/api/rate-limiter.ts` integrated into HTTP File Server.
- **Pagination** (P1): `src/pagination.ts` cursor-based pagination utility.
- **Retry** (P1): `src/retry.ts` exponential backoff helper for transient failures.
- **Plugin SDK package** (P2): `packages/plugin-sdk/` standalone npm package for third-party plugin authors.
- **Plugin scaffolding** (P2): `scripts/create-plugin.js` interactive plugin generator.
- **Plugin tests** (P2): `tests/unit/plugins.test.ts` — 17 tests covering lifecycle, hooks, hot-load, and dependency resolution.
- **Plugin registry** (P2): `src/plugin-registry.ts` centralized plugin discovery and management.
- **LLM multi-model routing** (P3): `src/llm/model-router.ts` supports routing to multiple LLM backends.
- **Memory forensics** (P3): `src/plugins/memory-forensics.ts` plugin for memory analysis.
- **SBOM generation** (P3): `src/tools/sbom-generate.ts` Software Bill of Materials export.
- **Batch analysis** (P3): `src/tools/batch-analysis.ts` multi-sample batch analysis orchestration.
- **SSE events** (P3): `src/api/sse-events.ts` Server-Sent Events infrastructure for real-time streaming.

### Plugin SDK (Open Extensibility)

- **Plugin SDK** (`src/plugins.ts`): Complete rewrite — enhanced `Plugin` interface with `description`, `version`, `dependencies`, `configSchema`, `hooks`, and `teardown` fields. Third-party plugin authors implement this interface for full extensibility.
- **PluginManager**: Singleton class managing plugin lifecycle — `loadAll()`, `loadOne()`, `hotLoad()`, `unload()`, `fireHook()`, topological dependency sorting, `resolveEnabledPlugins()`.
- **9 built-in plugins**: Expanded from 4 → 9 plugins. Added `frida` (runtime instrumentation), `ghidra` (headless analysis), `cross-module` (cross-binary comparison), `visualization` (HTML reports, timelines, data-flow maps), `kb-collaboration` (function matching, analysis templates).
- **Prerequisite checks**: `android` checks jadx binary access, `frida` checks `frida --version`, `ghidra` checks `GHIDRA_INSTALL_DIR` env var. Plugins that fail checks are gracefully skipped.
- **Plugin auto-discovery**: `plugins/` directory at project root is scanned for `.js`/`.mjs` files that default-export a `Plugin` object — loaded automatically alongside built-ins.
- **Declarative config schema**: Each plugin declares `configSchema: PluginConfigField[]` (envVar, description, required, defaultValue). Surfaced via `plugin.list` tool.
- **Dependency resolution**: Plugins declare `dependencies: string[]`. `PluginManager.topoSort()` loads them in correct order; missing deps → `skipped-deps` status.
- **Lifecycle hooks**: `PluginHooks` interface (`onBeforeToolCall`, `onAfterToolCall`, `onToolError`). Hooks are fired by `MCPServer.callTool()` for tools belonging to hook-equipped plugins.
- **Hot-load / unload**: `plugin.enable` hot-loads a plugin at runtime, `plugin.disable` calls `teardown()` and unregisters all plugin tools — no server restart required.
- **Plugin introspection tools**: `plugin.list` (read-only status/config), `plugin.enable`, `plugin.disable` — LLM clients can discover and manage plugins via MCP.
- **`MCPServer.unregisterTool()`**: New method to remove tools at runtime, enabling plugin unload.
- **`MCPServer.setPluginManager()`**: Wires PluginManager into server for lifecycle hook dispatch.
- **Docs**: Comprehensive `docs/PLUGINS.md` rewrite covering SDK types, hook system, auto-discovery, external plugin authoring, and troubleshooting.

### Architecture & Infrastructure

- **Tool Registry** (`src/tool-registry.ts`): Centralised registration of all 148 tools, 3 prompts, and 16 resources. `src/index.ts` reduced from ~1,450 lines to ~90 lines.
- **Plugin Architecture** (`src/plugins.ts`): Four built-in plugins (android, malware, crackme, dynamic) controlled via `PLUGINS` env var. Supports prerequisite checks and custom plugin extensions. Docs: `docs/PLUGINS.md`.
- **MCP Resources**: 16 helper scripts (8 Frida + 8 Ghidra) exposed as MCP resources discoverable via `resources/list` and readable via `resources/read`.
- **Streaming Progress** (`src/streaming-progress.ts`): `ProgressReporter` interface for long-running tools. Emits `notifications/progress` MCP notifications when client sends `_meta.progressToken`.
- **Architecture docs** (`docs/ARCHITECTURE.md`): Comprehensive guide covering tool registry, plugin system, resources, streaming, safe commands, process pool, structured logging, and CI/CD security.

### Security Hardening

- **Command injection prevention** (`src/safe-command.ts`): Whitelist regex validation (`SAFE_COMMAND_NAME_RE`), `execFileSync`/`spawnSync` with argument arrays, `safeCommandExists()`, `safeGetCommandVersion()`, `validateGraphvizFormat()`.
- **env-validator.ts**: Replaced `execSync` shell calls with safe wrappers.
- **cfg-visual-exports.ts**: Added `validateGraphvizFormat()` whitelist validation.
- **CI/CD security scanning**: Added `security` job to `.github/workflows/ci.yml` — npm audit, pip-audit, CodeQL SAST.

### Observability

- **Structured logging**: Migrated 7 files from `console.log`/`console.error` to Pino structured JSON logging (`policy-guard.ts`, `llm-analyze.ts`, `auto-trigger.ts`, `triage.ts`, `cache-manager.ts`).
- **Python Process Pool** (`src/python-process-pool.ts`): Queue-based concurrency limiter with `MAX_PYTHON_WORKERS` env var. Stats surfaced through `system.health` tool.

### Testing

- **68 new test files** generated for previously untested tools (193 total unit tests, up from 125).
- **Integration tests**: `tests/integration/full-pipeline.test.ts` (E2E ingest→triage), `tests/integration/beta2-tools.test.ts` (beta.2 tool coverage).

### Documentation

- **API docs generation**: `scripts/generate-api-docs.js` + `npm run docs:api` script.
- New: `docs/ARCHITECTURE.md`, `docs/PLUGINS.md`.
- Updated: `README.md` (architecture section, project layout), `CONTRIBUTING.md` (tool registration guide, plugin development), `SECURITY.md` (command injection prevention, CI/CD scanning), `docs/API-REFERENCE.md` (MCP resources), `CHANGELOG.md`.

## [1.0.0-beta.2] - 2026-03-30

### Android / APK Analysis

- Added `apk.structure.analyze` — APK manifest, permissions, and component extraction via Python worker
- Added `apk.packer.detect` — APK packer/obfuscator detection (DexGuard, iJiami, Bangcle, etc.)
- Added `dex.decompile` — DEX-to-Java decompilation via jadx
- Added `dex.classes.list` — DEX class/method enumeration
- Added `workers/apk_dex_worker.py` — Unified Python worker for APK/DEX operations
- Docker: Added jadx v1.5.1 installation (`/opt/jadx/bin/jadx`)

### Symbolic Execution & CrackMe

- Added `symbolic.explore` — angr-backed symbolic execution for path exploration and constraint solving
- Added `keygen.verify` — Keygen/license verification via Qiling or angr backends
- Added `constraint.solve` — Z3/angr constraint solver for serial/key generation
- Added `workers/symbolic_explorer_worker.py`, `workers/keygen_verify_worker.py`, `workers/constraint_solver_worker.py`

### Dynamic Analysis

- Added `dynamic.auto_hook` — Automated Frida hook generation from static analysis evidence
- Added `dynamic.memory_dump` — Frida-based runtime memory dump with pattern scanning

### Malware Analysis

- Added `malware.config.extract` — Malware configuration extraction (C2, encryption keys, mutexes)
- Added `malware.classify` — Malware family classification using YARA + capa + behavioral indicators
- Added `c2.extract` — C2 infrastructure extraction and indicator enrichment
- Added `workers/malware_config_worker.py`

### Cross-Platform & Visualization

- Added `elf.macho.parse` — ELF/Mach-O header and section parsing via Rizin
- Added `rizin.diff` — Binary diffing via Rizin (function-level and basic-block-level)
- Added `cfg.visualize` — Control flow graph visualization (DOT/SVG/JSON)
- Added `timeline.correlate` — Multi-source event timeline correlation
- Added `cross_module.xref` — Cross-module cross-reference analysis
- Added `kb.search` — Knowledge base semantic search
- Added `workers/elf_macho_worker.py`, `workers/rizin_diff_worker.py`

### Quality & Infrastructure

- **Config**: Unified Python path resolution via `config.workers.static.pythonPath` across all new tools; added `JADX_PATH` env var support
- **PolicyGuard**: Applied to 5 high-risk dynamic/symbolic tools (`symbolic.explore`, `keygen.verify`, `patch.generate`, `dynamic.auto_hook`, `dynamic.memory_dump`)
- **CacheManager**: Applied to 3 malware analysis tools (`malware.config.extract`, `c2.extract`, `malware.classify`)
- **Worker validation**: Added `os.path.isfile()` input checks to 4 Python workers
- **Workflow integration**: `workflow.triage` now routes APK/DEX samples to APK-specific analysis tools
- **Type safety**: Replaced `any` type annotations with proper union types in malware-classify
- **npm packaging**: Added 7 missing worker files to `package.json` `files` array
- **Unit tests**: Added test suites for malware-config-extract, apk-structure-analyze, symbolic-explore, and patch-generate

## [1.0.0-beta.1] - 2026-03-29

### Frida Dynamic Instrumentation

- Added Frida runtime instrumentation with `frida.runtime.instrument` supporting spawn and attach modes
- Added Frida script injection via `frida.script.inject` with pre-built script library:
  - `api_trace.js` - Windows API tracing with argument logging
  - `string_decoder.js` - Runtime string decryption
  - `anti_debug_bypass.js` - Anti-debug detection neutralization
  - `crypto_finder.js` - Cryptographic API detection
  - `file_registry_monitor.js` - File/registry operation tracking
- Added Frida trace capture via `frida.trace.capture` with canonical MCP trace schema
- Implemented trace filtering, aggregation, artifact persistence, and provenance tracking
- Integrated Frida traces into `dynamic.trace.import`, `report.generate`, and `report.summarize`
- Added async job support for long-running Frida traces via `task.status` / `task.cancel`
- Added evidence scope selection (`all`/`latest`/`session`) and compare/baseline support for Frida traces
- Added comprehensive Frida documentation: installation guides, workflow examples, troubleshooting guidance
- Added `frida_scripts/` library with README documentation
- Added comprehensive unit tests for Frida tools:
  - `tests/unit/frida-runtime-instrument.test.ts` - Runtime instrumentation tests (11 tests)
  - `tests/unit/frida-script-inject.test.ts` - Script injection tests (13 tests)
  - `tests/unit/frida-trace-capture.test.ts` - Trace capture/normalization tests (19 tests)
  - `tests/unit/setup-guidance.test.ts` - Setup guidance behavior tests (24 tests)
- Added integration tests for Frida workflows:
  - `tests/integration/frida-workflow.test.ts` - End-to-end spawn/attach/capture workflow tests
  - Tests graceful degradation when Frida unavailable with structured setup guidance
  - Tests concurrent operations and artifact persistence

### Static Analysis Foundation

- Added a static triage foundation for the upcoming `0.2.0` line: `static.capability.triage`, `pe.structure.analyze`, and `compiler.packer.detect`
- Added worker/config/setup support for `flare-capa`, `pefile`, `lief`, `CAPA_RULES_PATH`, and `DIE_PATH`
- Integrated static capability, PE structure, and compiler/packer attribution into `workflow.triage`, `report.summarize`, and `report.generate`
- Added static artifact persistence, provenance, scope selection, and compare/baseline support for the new analysis families
- Updated MCP docs, install guides, and release notes to cover early-stage static triage chaining and optional dependency bootstrap

### HTTP File Server

- Added embedded HTTP file server on port 18080 for direct sample uploads and artifact downloads
- Implemented REST API endpoints:
  - `POST /api/v1/samples` - Direct sample upload with multipart/form-data support
  - `GET /api/v1/samples/:id` - Sample metadata retrieval and optional file download
  - `GET /api/v1/artifacts` - List artifacts with optional sample filtering
  - `GET/DELETE /api/v1/artifacts/:id` - Artifact metadata, download, and deletion
  - `GET /api/v1/health` - Health check endpoint
  - `POST/GET /api/v1/uploads/:token` - Upload session management
- Added API key authentication via `X-API-Key` header (optional, configurable via `API_KEY`)
- Added MCP tools for file access:
  - `sample.download` - Download sample by ID with metadata
  - `artifact.download` - Download artifact by ID with optional content parsing
- Added PowerShell CLI tools:
  - `scripts/upload-api.ps1` - Sample upload with progress display and error handling
  - `scripts/download-artifact.ps1` - Artifact download with metadata support
- Implemented storage management:
  - `StorageManager` - Unified storage operations with date partitioning
  - `cleanup-job.ts` - Automatic retention-based cleanup (configurable via `API_RETENTION_DAYS`)
  - `metadata-logger.ts` - Audit logging for upload tracking
- Added comprehensive documentation:
  - `docs/API-FILE-SERVER.md` - API usage guide with examples
  - `docs/API-REFERENCE.md` - Complete API reference with error codes
  - Updated `README.md` and `INSTALL.md` with API configuration
- Added Docker configuration:
  - Exposed port 18080 in Dockerfile
  - Added storage volume mounting in docker-compose.yml
  - Added API environment variables in .env.example
- Added unit tests:
  - `tests/unit/api/auth-middleware.test.ts` - Authentication tests
  - `tests/unit/api/sample-upload.test.ts` - Upload workflow tests
  - `tests/unit/api/storage-manager.test.ts` - Storage operation tests
  - `tests/unit/api/api-endpoints.test.ts` - Endpoint contract tests
  - `tests/unit/api/upload-workflow.test.ts` - E2E workflow tests

### MCP Server Optimization (Phase 1-8)

- **Cache Layer Optimization** (Phase 1):
  - Implemented smart cache key generation filtering 18 unstable parameters
  - Added parameter normalization for deterministic key generation
  - Implemented cache hit rate statistics and monitoring
  - Expected improvement: +30-50% cache hit rate
  - New modules: `src/smart-cache.ts`, `src/cache-manager.ts` extensions

- **Tiered Response System** (Phase 2):
  - Implemented L1/L2/L3 response tiering to reduce token consumption
  - Created `TieredResponse` interface and `BaseTool` abstract class
  - L1 Summary (100-500 tokens), L2 Structured data, L3 Artifact references
  - Expected improvement: -80-90% token consumption
  - New module: `src/tiered-response.ts`

- **JobQueue Enhancement** (Phase 3):
  - Added progress tracking API (`updateProgress`)
  - Added cancellation check API (`isCancelled`)
  - Improved workflow observability
  - Modified: `src/job-queue.ts`

- **Artifact Lifecycle Management** (Phase 4):
  - Implemented artifact age calculation and retention bucket classification
  - Added gzip compression for artifacts older than 7 days
  - Implemented automatic cleanup with configurable retention policy
  - Added dry-run mode for preview
  - Expected improvement: -50-70% disk usage
  - New module: `src/artifact-lifecycle.ts`

- **Error Recovery Enhancement** (Phase 5):
  - Implemented intelligent error classification (9 categories)
  - Added auto-recovery actions (5 types: install, retry, downgrade, etc.)
  - Implemented exponential backoff retry logic
  - Added lite mode fallback for resource exhaustion
  - New module: `src/error-handler-enhanced.ts`

- **MCP Resources Protocol** (Phase 6):
  - Implemented `resources/list` and `resources/read` endpoints
  - Added `artifact://` and `sample://` URI schemes
  - Added resource change notifications
  - New module: `src/mcp-resources.ts`

- **Token Budget Tracking** (Phase 7):
  - Implemented SQLite `token_usage` table for persistence
  - Added simple usage recording and querying
  - Provides tool-based statistics and recent usage history
  - Lightweight implementation focused on core recording needs
  - New module: `src/token-budget.ts`

- **Performance Benchmarking** (Phase 8):
  - Created benchmark suite for cache, response, and disk optimization
  - Implemented token reduction measurement
  - Added optimization report generation
  - Added tuning recommendations
  - New module: `src/performance-benchmark.ts`

## [0.1.4] - 2026-03-14

- Added safer Ghidra defaults for `GHIDRA_PROJECT_ROOT` / `GHIDRA_LOG_ROOT`, automatic project-parent creation, and safer Windows defaults that avoid unstable per-repo relative paths
- Fixed bundled `ghidra_scripts` resolution so helper scripts are loaded from the installed package or repository root instead of the current working directory
- Added richer Ghidra diagnostics: persisted command/runtime logs, parsed Java exception summaries, normalized remediation hints, and stage progress callbacks for queued analysis
- Surfaced structured `ghidra_execution` summaries through `workflow.reconstruct`, `workflow.semantic_name_review`, `workflow.function_explanation_review`, `workflow.module_reconstruction_review`, `report.summarize`, and `report.generate`
- Added Java runtime detection and Java 21+ setup guidance across `ghidra.health`, `system.health`, `system.setup.guide`, and high-level workflows
- Extended module reconstruction review refresh so all three high-level semantic review workflows now expose the same Ghidra project/log/progress context after export refresh
- Stabilized unit coverage for Ghidra analysis failure handling, timeout reporting, Java fallback extraction, and degraded function-index recovery

## [0.1.3] - 2026-03-14

- Added DLL- and COM-oriented profiling with `dll.export.profile` and `com.role.profile`
- Added module-level LLM review primitives: `code.module.review.prepare`, `code.module.review`, `code.module.review.apply`, prompt `reverse.module_reconstruction_review`, and `workflow.module_reconstruction_review`
- Extended `workflow.reconstruct` with role-aware export strategy so DLL/COM/Rust preflight can influence module grouping and reconstruction priority
- Improved runtime memory ingestion with segment/module hints, region ownership, and richer runtime provenance
- Added structured setup guidance with `system.setup.guide` and surfaced install/input requirements from health checks and high-level workflows
- Refined README, installation docs, and release packaging for the `0.1.3` npm/GitHub release

## [0.1.2] - 2026-03-12

- Upgraded `workflow.reconstruct` with universal preflight orchestration, including binary role profiling, Rust-specific profiling, and optional automatic function-index recovery before export
- Aligned `workflow.semantic_name_review` and `workflow.function_explanation_review` with reconstruct refresh preflight, provenance, and selection diff semantics
- Added `.pdata`-driven PE recovery tooling: `pe.pdata.extract`, `code.functions.smart_recover`, `pe.symbols.recover`, and `code.functions.define`
- Added `workflow.function_index_recover` and `rust_binary.analyze` to make Rust and hard-to-index native samples recoverable even when Ghidra function extraction fails
- Hardened sample/original and Ghidra project fallback handling so analysis can continue when older workspaces are incomplete
- Stabilized runtime state defaults by moving workspace, database, cache, and audit paths to persistent user-level configuration roots

## [0.1.1] - 2026-03-11

- Added `binary.role.profile` for universal EXE/DLL/.NET/driver role profiling, export surface triage, and COM/service/plugin indicators
- Added quality scaffolding with benchmark corpus example and evaluation guidance for future regression baselines
- Added async job mode for `workflow.reconstruct`, `workflow.semantic_name_review`, and `workflow.function_explanation_review`
- Wired queued workflow execution into the background analysis task runner
- Integrated binary role profile output into `report.summarize` and `report.generate`
- Added report coverage for runtime/semantic provenance plus binary role context in generated markdown and JSON output
- Continued repository and packaging cleanup for public GitHub/npm release

## [0.1.0] - 2026-03-11

- Initial public packaging baseline
- MCP server with static PE analysis, Ghidra integration hooks, runtime evidence tools, and reconstruction workflows
