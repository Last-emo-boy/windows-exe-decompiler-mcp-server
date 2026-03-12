# Install in GitHub Copilot

This repository includes a helper script for local GitHub Copilot clients:

```powershell
.\install-to-copilot.ps1
```

By default, the script writes a stable `WORKSPACE_ROOT` under your user profile:

- `%USERPROFILE%/.windows-exe-decompiler-mcp-server/workspaces`

It also pins:

- `DB_PATH`
- `CACHE_ROOT`
- `AUDIT_LOG_PATH`

Build the project first:

```powershell
npm run build
```

If Ghidra is not already configured in the environment, pass it explicitly:

```powershell
.\install-to-copilot.ps1 -GhidraPath "C:\tools\ghidra"
```

If you want a different persistent workspace root:

```powershell
.\install-to-copilot.ps1 -WorkspaceRoot "D:\reverse-data\workspaces"
```

## What the script updates

- workspace config: `.vscode/mcp.json`
- Copilot CLI config: `~/.copilot/mcp-config.json`

You can target only one config:

```powershell
.\install-to-copilot.ps1 -SkipCopilotCliConfig
.\install-to-copilot.ps1 -SkipWorkspaceConfig
```

If the `code` command is available and you also want to try the VS Code
user-level profile route:

```powershell
.\install-to-copilot.ps1 -InstallVsCodeUserProfile
```

## Verify

### VS Code / GitHub Copilot

1. Open the repository in VS Code.
2. Confirm that `.vscode/mcp.json` contains `windows-exe-decompiler`.
3. Trust the MCP server when VS Code prompts you.
4. Ask Copilot to call `tool.help` or `workflow.triage`.

### Copilot CLI

Run:

```text
/mcp list
```

or:

```text
/mcp show windows-exe-decompiler
```

## References

- https://code.visualstudio.com/docs/copilot/customization/mcp-servers
- https://code.visualstudio.com/docs/copilot/reference/mcp-configuration
- https://docs.github.com/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers
- https://docs.github.com/en/enterprise-cloud@latest/copilot/reference/cli-command-reference

## Scope

These instructions are for local Copilot clients such as:

- VS Code with GitHub Copilot
- GitHub Copilot CLI

They do not configure GitHub.com hosted coding agents.
