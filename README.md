# Windows EXE Decompiler MCP Server

Chinese version: [`README_zh.md`](./README_zh.md)

An MCP server for Windows reverse engineering. It exposes PE triage, Ghidra-backed inspection, DLL/COM profiling, runtime evidence ingestion, Rust/.NET recovery, source-like reconstruction, and LLM-assisted review as reusable MCP tools for any tool-calling LLM.

## What this server is for

This project is meant to be a reusable reverse-engineering tool surface, not a pile of one-off local scripts.

It is designed to help MCP clients:

- triage Windows PE samples quickly
- inspect imports, exports, strings, packers, runtime hints, and binary role
- use Ghidra when available for decompile, CFG, search, and reconstruction
- recover usable function indexes when Ghidra function extraction fails
- correlate static evidence, runtime traces, memory snapshots, and semantic review artifacts
- export source-like reconstruction output with optional build and harness validation

## Core capability areas

### Sample and static analysis

- `sample.ingest`
- `sample.profile.get`
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
- `attack.map`
- `ioc.export`
- `report.summarize`
- `report.generate`
- `artifacts.list`
- `artifact.read`
- `artifacts.diff`
- `tool.help`

### Semantic review and reconstruction

- `code.function.rename.prepare`
- `code.function.rename.review`
- `code.function.rename.apply`
- `code.function.explain.prepare`
- `code.function.explain.review`
- `code.function.explain.apply`
- `code.module.review.prepare`
- `code.module.review`
- `code.module.review.apply`
- `code.reconstruct.plan`
- `code.reconstruct.export`

## High-level workflows

These are the main orchestration entrypoints for MCP clients.

### `workflow.triage`

Fast first-pass triage for PE samples. Use this when you want a quick answer before deeper recovery.

### `workflow.deep_static`

Long-running static pipeline for deeper analysis and ranking. Supports async job mode.

### `workflow.reconstruct`

The main high-level reconstruction workflow.

It can:

- run binary preflight
- detect Rust-oriented samples
- profile DLL lifecycle, export dispatch, callback surface, and COM activation hints
- auto-recover a function index when Ghidra function extraction is missing or degraded
- export native or .NET reconstruction output
- optionally validate build and run the generated harness
- tune export strategy based on role-aware preflight for native Rust, DLL, and COM-oriented samples
- carry runtime and semantic provenance through the result

### `workflow.function_index_recover`

High-level recovery chain for hard native binaries:

- `code.functions.smart_recover`
- `pe.symbols.recover`
- `code.functions.define`

Use this when Ghidra analysis exists but function extraction is empty or degraded.

### `workflow.semantic_name_review`

High-level semantic naming review workflow for external LLM clients. It can prepare evidence, request model review through MCP sampling when available, apply accepted names, and optionally refresh reconstruct/export output.

### `workflow.function_explanation_review`

High-level explanation workflow for external LLM clients. It can prepare evidence, request structured explanations, apply them, and optionally rerun reconstruct/export.

### `workflow.module_reconstruction_review`

High-level module review workflow for external LLM clients. It can prepare reconstructed modules for review, request structured module refinements through MCP sampling when available, apply accepted module summaries and guidance, and optionally refresh reconstruct/export output.

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

## Environment bootstrap and setup guidance

If a client starts using the server before Python, dynamic-analysis extras, or Ghidra are configured, use:

- `system.health`
- `dynamic.dependencies`
- `ghidra.health`
- `system.setup.guide`

These return structured setup actions and required user inputs so an MCP client can explicitly ask for:

- `python -m pip install ...`
- `GHIDRA_PATH` / `GHIDRA_INSTALL_DIR`
- optional dynamic-analysis extras such as Speakeasy/Frida dependencies

## Project layout

```text
bin/                         npm CLI entrypoint
dist/                        compiled TypeScript output
ghidra_scripts/              Ghidra helper scripts used by the server
helpers/DotNetMetadataProbe/ .NET metadata helper project
src/                         TypeScript MCP server source
tests/                       unit and integration tests
workers/                     Python worker, YARA rules, dynamic helpers
install-to-codex.ps1         local Codex MCP install helper
install-to-copilot.ps1       local GitHub Copilot MCP install helper
install-to-claude.ps1        local Claude Code MCP install helper
docs/QUALITY_EVALUATION.md   evaluation checklist for regression and release readiness
```

## Prerequisites

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
    "windows-exe-decompiler": {
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

### Local install helpers

- Codex: [`install-to-codex.ps1`](./install-to-codex.ps1)
- Claude Code: [`install-to-claude.ps1`](./install-to-claude.ps1)
- GitHub Copilot: [`install-to-copilot.ps1`](./install-to-copilot.ps1)

Related docs:

- [`CODEX_INSTALLATION.md`](./CODEX_INSTALLATION.md)
- [`COPILOT_INSTALLATION.md`](./COPILOT_INSTALLATION.md)
- [`CLAUDE_INSTALLATION.md`](./CLAUDE_INSTALLATION.md)

## Persistent storage

By default, runtime state is stored under the user profile instead of the current working directory:

- Windows workspace root: `%USERPROFILE%/.windows-exe-decompiler-mcp-server/workspaces`
- SQLite database: `%USERPROFILE%/.windows-exe-decompiler-mcp-server/data/database.db`
- File cache: `%USERPROFILE%/.windows-exe-decompiler-mcp-server/cache`
- Audit log: `%USERPROFILE%/.windows-exe-decompiler-mcp-server/audit.log`

You can override these with environment variables or the user config file:

- `%USERPROFILE%/.windows-exe-decompiler-mcp-server/config.json`

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
- Quality evaluation notes: [`docs/QUALITY_EVALUATION.md`](./docs/QUALITY_EVALUATION.md)
- Example benchmark corpus: [`examples/benchmark-corpus.example.json`](./examples/benchmark-corpus.example.json)
- Security policy: [`SECURITY.md`](./SECURITY.md)

## Using the published package

```json
{
  "mcpServers": {
    "windows-exe-decompiler": {
      "command": "npx",
      "args": ["-y", "windows-exe-decompiler-mcp-server"],
      "env": {
        "GHIDRA_PATH": "C:/path/to/ghidra",
        "GHIDRA_INSTALL_DIR": "C:/path/to/ghidra"
      }
    }
  }
}
```

## License

Released under the MIT license. See [`LICENSE`](./LICENSE).
