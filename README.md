# Windows EXE Decompiler MCP Server

中文说明见 [`README_zh.md`](./README_zh.md).

An MCP server for Windows binary reverse engineering.

It exposes PE triage, native and .NET analysis, Ghidra-backed function
inspection, runtime evidence import, reconstruction workflows, and report
generation as MCP tools that any tool-calling LLM can consume.

## What this project is for

This server is designed to provide a reusable reverse-engineering tool surface
over MCP instead of one-off local scripts.

Primary use cases:

- Windows PE triage
- import / export / string / YARA analysis
- Ghidra-assisted decompile, CFG, and function search
- .NET metadata inspection
- runtime trace and memory snapshot import
- function naming and explanation review workflows
- source-like reconstruction export with validation harnesses

## Current capability areas

### Static analysis

- `sample.ingest`
- `sample.profile.get`
- `pe.fingerprint`
- `pe.imports.extract`
- `pe.exports.extract`
- `strings.extract`
- `strings.floss.decode`
- `yara.scan`
- `runtime.detect`
- `packer.detect`
- `binary.role.profile`

### Ghidra and code analysis

- `ghidra.health`
- `ghidra.analyze`
- `code.functions.list`
- `code.functions.rank`
- `code.functions.search`
- `code.function.decompile`
- `code.function.disassemble`
- `code.function.cfg`
- `code.functions.reconstruct`

### Reconstruction and review workflows

- `code.reconstruct.plan`
- `code.reconstruct.export`
- `dotnet.metadata.extract`
- `dotnet.types.list`
- `dotnet.reconstruct.export`
- `workflow.triage`
- `workflow.deep_static`
- `workflow.reconstruct`
- `workflow.semantic_name_review`
- `workflow.function_explanation_review`

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

## Local development setup

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

Build the server:

```bash
npm run build
```

Run tests:

```bash
npm test
```

Start the server locally:

```bash
npm start
```

## MCP client configuration

### Generic stdio config

Most MCP clients can start this server with:

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

This repository already includes local install scripts:

- Codex: [`install-to-codex.ps1`](./install-to-codex.ps1)
- Claude Code: [`install-to-claude.ps1`](./install-to-claude.ps1)
- GitHub Copilot: [`install-to-copilot.ps1`](./install-to-copilot.ps1)

Related docs:

- [`CODEX_INSTALLATION.md`](./CODEX_INSTALLATION.md)
- [`COPILOT_INSTALLATION.md`](./COPILOT_INSTALLATION.md)
- [`CLAUDE_INSTALLATION.md`](./CLAUDE_INSTALLATION.md)

By default, the server now stores persistent sample workspaces under the user
profile instead of `./workspaces`:

- Windows: `%USERPROFILE%/.windows-exe-decompiler-mcp-server/workspaces`

The same user-level app root is also used for:

- SQLite database: `%USERPROFILE%/.windows-exe-decompiler-mcp-server/data/database.db`
- File cache: `%USERPROFILE%/.windows-exe-decompiler-mcp-server/cache`
- Audit log: `%USERPROFILE%/.windows-exe-decompiler-mcp-server/audit.log`

You can still override these with environment variables or a user config file at:

- `%USERPROFILE%/.windows-exe-decompiler-mcp-server/config.json`

## Sample ingest note

For local IDE clients such as VS Code or Copilot, prefer:

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "E:/absolute/path/to/sample.exe"
  }
}
```

Use `bytes_b64` only when the MCP client cannot access the same filesystem as
the MCP server.

## Publishing to npm

### What is included in the npm package

The published package includes:

- compiled `dist/`
- a CLI entrypoint in `bin/`
- Python workers and YARA rules
- Ghidra helper scripts
- the .NET metadata helper source
- MCP client install scripts

It intentionally excludes:

- tests
- local workspaces
- caches
- generated reports
- scratch documents and internal progress notes

### Pre-publish checklist

1. Pick a package name that is available on npm.
2. Update the version in [`package.json`](./package.json).
3. Run:

```bash
npm run release:check
```

4. Inspect the dry-run pack list:

```bash
npm run pack:dry-run
```

5. Log in to npm:

```bash
npm login
```

6. Publish:

```bash
npm publish
```

### GitHub Actions

This repository now includes:

- [`ci.yml`](./.github/workflows/ci.yml): build, Python syntax check, key unit tests, and `npm pack --dry-run`
- [`publish-npm.yml`](./.github/workflows/publish-npm.yml): publish on `v*` tags or manual dispatch, then create a GitHub Release with the npm tarball attached
- [`dependabot.yml`](./.github/dependabot.yml): weekly npm and GitHub Actions dependency updates

Before npm publishing from GitHub Actions, add this repository secret:

- `NPM_TOKEN`

Recommended release flow:

```bash
npm version patch
git push origin main --follow-tags
```

That tag push will trigger the publish workflow.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for local
setup, validation, and release steps.

For release-quality regression planning, see [`docs/QUALITY_EVALUATION.md`](./docs/QUALITY_EVALUATION.md)
and [`examples/benchmark-corpus.example.json`](./examples/benchmark-corpus.example.json).

## Security

See [`SECURITY.md`](./SECURITY.md) for disclosure guidance
and operational boundaries.

### Using the published package

Once published, an MCP client can use `npx`:

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

## Security boundaries

This project is designed for analysis workflows, not for live malware
operations. Current practical strengths are:

- triage and classification support
- reverse-engineering evidence extraction
- IOC and ATT&CK export
- runtime evidence import and correlation
- source-like reconstruction and review

Current non-goals:

- original source recovery for complex native binaries
- guaranteed malware family attribution from static evidence alone
- full automatic unpacking for all packers
- high-confidence semantic recovery of every function in heavily optimized code

## License

This project is released under the MIT license. See [`LICENSE`](./LICENSE).
