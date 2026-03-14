# Claude Installation

This repository can be installed into Claude Code as an MCP server in three
scopes:

- `local`: machine-local config for the current project, stored in
  `~/.claude.json`
- `user`: machine-wide config for your user, stored in `~/.claude.json`
- `project`: project-scoped config written to `.mcp.json` in the repo root

On this Windows setup, writing the config file directly is more reliable than
shelling out to `claude mcp add`, so the install script uses the config-file
path directly and then verifies the result with `claude mcp get`.

## Prerequisites

- Claude Code CLI installed and available as `claude`
- Node.js available as `node`
- Project already built with `npm run build`

## Recommended Install

From the repository root:

```powershell
.\install-to-claude.ps1
```

The default scope is `user`, so this installs the server once for your account
and makes it available in all Claude Code projects on this machine.

The script also writes a stable `WORKSPACE_ROOT` by default:

- `%USERPROFILE%/.windows-exe-decompiler-mcp-server/workspaces`

It also pins:

- `DB_PATH`
- `CACHE_ROOT`
- `AUDIT_LOG_PATH`
- `GHIDRA_PROJECT_ROOT`
- `GHIDRA_LOG_ROOT`

The server's bundled `ghidra_scripts/` directory is resolved from the installed
package or repository root, not from the shell's current working directory. You
do not need to manually point Claude at `ExtractFunctions.py`.

For Ghidra 12.0.4, keep Java 21+ available. If Java is installed outside the
system default location, also set `JAVA_HOME`.

## Pass Ghidra Explicitly

```powershell
.\install-to-claude.ps1 -GhidraPath "C:\path\to\ghidra"
```

The script writes both `GHIDRA_PATH` and `GHIDRA_INSTALL_DIR`.

If you want to pin Ghidra project/log roots explicitly, set:

- `GHIDRA_PROJECT_ROOT`
- `GHIDRA_LOG_ROOT`

If you want a different persistent workspace root:

```powershell
.\install-to-claude.ps1 -WorkspaceRoot "D:\reverse-data\workspaces"
```

## Change Scope

Examples:

```powershell
.\install-to-claude.ps1 -Scope local
.\install-to-claude.ps1 -Scope user
.\install-to-claude.ps1 -Scope project
```

If you choose `project`, the script writes `.mcp.json` into the repository
root. If you choose `local` or `user`, the script updates `~/.claude.json`.
Use `local` only when you want this repo to override the global `user`
registration.

If both `user` and `local` registrations exist, Claude will show the `local`
scope while you are inside that repository, and the `user` scope everywhere
else.

## Manual Config Format

Claude Code recognizes the standard MCP config shape:

```json
{
  "mcpServers": {
    "windows-exe-decompiler": {
      "command": "node",
      "args": ["E:/Playground/Reverse/dist/index.js"],
      "cwd": "E:/Playground/Reverse",
      "env": {
        "WORKSPACE_ROOT": "C:/Users/<you>/.windows-exe-decompiler-mcp-server/workspaces",
        "GHIDRA_PATH": "C:/path/to/ghidra",
        "GHIDRA_INSTALL_DIR": "C:/path/to/ghidra"
      }
    }
  }
}
```

That same server object works in:

- repo-local `.mcp.json` for `project` scope
- top-level `mcpServers` in `~/.claude.json` for `user` scope
- `projects["E:/path/to/repo"].mcpServers` in `~/.claude.json` for `local`
  scope

## Verify

```powershell
claude mcp list
claude mcp get windows-exe-decompiler
```

If you used `project` scope, `claude mcp get` should report `Scope: Project
config (shared via .mcp.json)`. If you used `local` or `user`, it should report
the corresponding Claude config scope from `~/.claude.json`.

## First-run setup guidance

If Claude can connect to the MCP server but reports missing Python packages,
dynamic-analysis extras, or Ghidra configuration, ask it to call:

- `system.setup.guide`
- `system.health`
- `ghidra.health`

These tools return structured `setup_actions` and `required_user_inputs`
instead of only failing with a generic error.

## References

- Claude Code MCP overview: https://docs.anthropic.com/en/docs/claude-code/mcp
- Claude Code MCP management and CLI behavior: https://docs.anthropic.com/en/docs/claude-code/mcp#manage-mcp-servers
