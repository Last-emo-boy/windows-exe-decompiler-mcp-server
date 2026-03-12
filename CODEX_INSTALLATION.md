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

- `%USERPROFILE%/.windows-exe-decompiler-mcp-server/workspaces`

It also pins:

- `DB_PATH`
- `CACHE_ROOT`
- `AUDIT_LOG_PATH`

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

## Manual configuration example

If you prefer to edit the config by hand, add a block like this to
`C:\Users\<you>\.codex\config.toml`:

```toml
[mcp_servers.windows-exe-decompiler]
command = "node"
args = ["E:/path/to/repo/dist/index.js"]
cwd = "E:/path/to/repo"
startup_timeout_sec = 30
tool_timeout_sec = 300
enabled = true
env = { WORKSPACE_ROOT = "C:/Users/<you>/.windows-exe-decompiler-mcp-server/workspaces", GHIDRA_PATH = "C:/tools/ghidra", GHIDRA_INSTALL_DIR = "C:/tools/ghidra" }
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

## Troubleshooting

- `dist/index.js was not found`
  Run `npm run build` first.
- `node` was not found
  Install Node.js or pass `-NodePath`.
- native analysis is unavailable
  Set `GHIDRA_PATH` or `GHIDRA_INSTALL_DIR`, or rerun the script with
  `-GhidraPath`.
