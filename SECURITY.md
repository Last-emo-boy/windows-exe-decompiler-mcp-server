# Security Policy

## Scope

This repository provides an MCP server for reverse-engineering and malware
analysis workflows. It is intended for controlled analysis environments.

## Reporting a vulnerability

Do not open a public GitHub issue for a security-sensitive report.

Instead, report:

- the affected version or commit
- the impacted MCP tool or workflow
- reproduction steps
- whether the issue can expose local files, execute unintended commands, or
  corrupt analysis results

If you plan to publish the repository, add your preferred private disclosure
channel before accepting public contributions.

## What is considered security-sensitive here

- unintended command execution
- path traversal or arbitrary file overwrite
- unsafe sample handling outside the intended analysis boundary
- privilege boundary bypass in packaging, install scripts, or worker launchers
- exposure of secrets through logs, reports, or generated artifacts

## Command injection prevention

All external command invocations use `src/safe-command.ts`:

- **Whitelist validation**: Command names are checked against
  `SAFE_COMMAND_NAME_RE = /^[a-zA-Z0-9._/:\-]+$/` before execution.
- **Array arguments**: `execFileSync` and `spawnSync` are called with argument
  arrays — never with shell string interpolation.
- **Safe helpers**: `safeCommandExists()`, `safeGetCommandVersion()`, and
  `validateGraphvizFormat()` replace the previous `execSync` invocations.

When adding new external command calls, always use these wrappers rather than
calling `execSync` or `child_process.exec` directly.

## CI/CD security scanning

The CI pipeline (`.github/workflows/ci.yml`) runs a dedicated `security` job:

1. **npm audit** — known vulnerabilities in Node.js dependencies
2. **pip-audit** — CVE checks for Python dependencies
3. **CodeQL SAST** — static application security testing

## Operational guidance

- Run the server in a dedicated analysis environment.
- Do not analyze untrusted samples on a production workstation.
- Review install scripts before using them in shared environments.
- Keep Ghidra, Python packages, and Node dependencies current.
- Set `PLUGINS` to limit loaded tool categories in restricted environments.
- Set `MAX_PYTHON_WORKERS` to limit concurrent Python processes.
