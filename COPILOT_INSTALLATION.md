# Install in GitHub Copilot

This repository includes a helper script for local GitHub Copilot clients:

```powershell
.\install-to-copilot.ps1
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
do not need to separately point Copilot at `ExtractFunctions.py`.

For Ghidra 12.0.4, keep Java 21+ available. If Java is installed outside the
default system location, set `JAVA_HOME` before launching Copilot clients.

Build the project first:

```powershell
npm run build
```

If Ghidra is not already configured in the environment, pass it explicitly:

```powershell
.\install-to-copilot.ps1 -GhidraPath "C:\tools\ghidra"
```

If you want to pin Ghidra projects and logs under a fixed location, set:

- `GHIDRA_PROJECT_ROOT`
- `GHIDRA_LOG_ROOT`

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
2. Confirm that `.vscode/mcp.json` contains `rikune`.
3. Trust the MCP server when VS Code prompts you.
4. Ask Copilot to call `tool.help` or `workflow.triage`.

### Copilot CLI

Run:

```text
/mcp list
```

or:

```text
/mcp show rikune
```

## First-run setup guidance

If Copilot can reach the MCP server but the server reports missing Python
packages, dynamic-analysis extras, or Ghidra configuration, ask Copilot to call:

- `system.setup.guide`
- `system.health`
- `ghidra.health`

These tools return structured setup actions and missing user inputs.

For the static capability / PE structure / compiler attribution layer, the most
common optional requirements are:

- `python -m pip install flare-capa pefile lief`
- a capa rules bundle referenced by `CAPA_RULES_PATH`
- Detect It Easy CLI referenced by `DIE_PATH`

## References

- https://code.visualstudio.com/docs/copilot/customization/mcp-servers
- https://code.visualstudio.com/docs/copilot/reference/mcp-configuration
- https://docs.github.com/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers
- https://docs.github.com/en/enterprise-cloud@latest/copilot/reference/cli-command-reference
- https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/extend-coding-agent-with-mcp

## Scope

These instructions are for local Copilot clients such as:

- VS Code with GitHub Copilot
- GitHub Copilot CLI

They do not configure GitHub.com hosted coding agents. For hosted coding-agent MCP setup, use the GitHub MCP coding-agent documentation linked above.
