# Install in Codex

## Quick start

Build the project first:

```powershell
npm run build
```

Then run the helper script from the repository root:

```powershell
.\install-to-codex.ps1
```

By default, the script writes a stable `WORKSPACE_ROOT` under your user profile:

- `%USERPROFILE%/.rikune/workspaces`

It also pins:

- `DB_PATH`
- `CACHE_ROOT`
- `AUDIT_LOG_PATH`
- `GHIDRA_PROJECT_ROOT`
- `GHIDRA_LOG_ROOT`

Optional static-analysis inputs can also be provided through:

- `CAPA_RULES_PATH`
- `DIE_PATH`

The server's bundled `ghidra_scripts/` directory is resolved from the installed
package or repository root, not from the shell's current working directory. You
do not need to manually configure a script path for `ExtractFunctions.py`.

For Ghidra 12.0.4, keep Java 21+ available. If Java is installed in a custom
location, set `JAVA_HOME` before starting Codex.

If Ghidra is not already configured through `GHIDRA_PATH` or
`GHIDRA_INSTALL_DIR`, pass it explicitly:

```powershell
.\install-to-codex.ps1 -GhidraPath "C:\tools\ghidra"
```

If you want a different persistent workspace root:

```powershell
.\install-to-codex.ps1 -WorkspaceRoot "D:\reverse-data\workspaces"
```

## What the script does

- validates that `dist/index.js` exists
- registers the MCP server with Codex
- updates `~/.codex/config.toml`
- writes `WORKSPACE_ROOT` so workspaces do not depend on the current repo path
- writes `GHIDRA_PATH` and `GHIDRA_INSTALL_DIR` when a Ghidra path is provided
- honors `GHIDRA_PROJECT_ROOT` and `GHIDRA_LOG_ROOT` when you want Ghidra
  projects and runtime logs under a fixed location

## Manual configuration example

If you prefer to edit the config by hand, add a block like this to
`C:\Users\<you>\.codex\config.toml`:

```toml
[mcp_servers.rikune]
command = "node"
args = ["E:/path/to/repo/dist/index.js"]
cwd = "E:/path/to/repo"
startup_timeout_sec = 30
tool_timeout_sec = 300
enabled = true
env = { WORKSPACE_ROOT = "C:/Users/<you>/.rikune/workspaces", GHIDRA_PATH = "C:/tools/ghidra", GHIDRA_INSTALL_DIR = "C:/tools/ghidra" }
```

## Verify

Run:

```powershell
codex mcp list
```

Then ask Codex to call one of these tools:

- `tool.help`
- `sample.ingest`
- `workflow.triage`

If Codex reports missing Python packages, dynamic-analysis extras, or Ghidra
configuration, ask it to call:

- `system.setup.guide`
- `system.health`
- `ghidra.health`

For the static capability / PE structure / compiler attribution layer, the most
common optional requirements are:

- `python -m pip install flare-capa pefile lief`
- a capa rules bundle referenced by `CAPA_RULES_PATH`
- Detect It Easy CLI referenced by `DIE_PATH`

## Troubleshooting

- `dist/index.js was not found`
  Run `npm run build` first.
- `node` was not found
  Install Node.js or pass `-NodePath`.
- native analysis is unavailable
  Set `GHIDRA_PATH` or `GHIDRA_INSTALL_DIR`, or rerun the script with
  `-GhidraPath`.
