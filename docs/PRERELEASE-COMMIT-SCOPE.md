# Prerelease Commit Scope

This document defines the recommended commit buckets for the `v1.0.0-beta.1`
release line. The goal is to separate shipping surfaces from unfinished or
future-facing work without dropping the already completed runtime changes.

## What Belongs In Beta.1

The beta should include the current staged runtime and packaging story:

1. Core analysis runtime convergence
2. Nonblocking and memory-aware large-sample behavior
3. Docker runtime plus npm launcher packaging
4. Explanation-first graph and summary surfaces
5. Packed-sample unpack/debug runtime
6. Release docs, version bump, and publish prep

## What Should Not Block Beta.1

These areas should stay out of the beta commit scope unless they are already
required by the shipping runtime:

- unfinished collaborative knowledge-base work
- unfinished generic async-job cleanup that is superseded by
  `workflow.analyze.start/status/promote`
- unfinished visualization polish that does not affect explanation artifacts
- experimental or benchmark-only code paths that are not part of the supported
  release workflow

## Recommended Commit Buckets

### 1. Runtime Core

Use for the staged orchestration and evidence model:

- `src/index.ts`
- `src/server.ts`
- `src/database.ts`
- `src/config.ts`
- `src/job-queue.ts`
- `src/analysis-*.ts`
- `src/nonblocking-analysis.ts`
- `src/intent-routing.ts`
- `src/tool-surface-guidance.ts`
- `src/workflows/analyze-*.ts`
- `src/workflows/triage.ts`
- `src/workflows/summarize.ts`
- `src/workflows/deep-static.ts`
- `src/workflows/reconstruct.ts`

Suggested commit message:

```text
feat(runtime): ship staged nonblocking analysis runtime
```

### 2. Static / Reverse / Reporting Surfaces

Use for the main tools that now sit on top of the staged runtime:

- `src/tools/analysis-context-link.ts`
- `src/tools/binary-role-profile.ts`
- `src/tools/code-*.ts`
- `src/tools/compiler-packer-detect.ts`
- `src/tools/crypto-identify.ts`
- `src/tools/ghidra-analyze.ts`
- `src/tools/packer-detect.ts`
- `src/tools/pe-*.ts`
- `src/tools/report-*.ts`
- `src/tools/runtime-detect.ts`
- `src/tools/sample-*.ts`
- `src/tools/static-capability-triage.ts`
- `src/tools/static-worker-client.ts`
- `src/tools/strings-*.ts`
- `src/tools/system-*.ts`
- `src/tools/task-status.ts`
- `src/tools/tool-help.ts`
- `src/tools/yara-scan.ts`

Suggested commit message:

```text
feat(tools): align analysis tools with staged runtime and bounded outputs
```

### 3. Dynamic / Unpack / Debug

Use for Frida, packed-sample handling, and debug-session artifacts:

- `src/unpack-debug-runtime.ts`
- `src/crypto-breakpoint-analysis.ts`
- `src/crypto-planning-artifacts.ts`
- `src/tools/breakpoint-smart.ts`
- `src/tools/dynamic-dependencies.ts`
- `src/tools/frida-*.ts`
- `src/tools/trace-condition.ts`
- `src/frida/`
- `workers/frida_worker.py`
- `workers/requirements-dynamic.txt`

Suggested commit message:

```text
feat(dynamic): add packed-sample unpack and debug-session runtime
```

### 4. Visualization / Explanation

Use for explanation graphs and render serializers:

- `src/explanation-graphs.ts`
- `src/cfg-visual-exports.ts`
- `src/visualization/`
- `src/tools/code-function-cfg.ts`
- `src/tools/docker-backend-tools.ts`

Suggested commit message:

```text
feat(explanations): add explanation-first graph artifacts
```

### 5. Docker + npm Packaging

Use for the published-package launcher model and Docker runtime:

- `Dockerfile`
- `docker-compose.yml`
- `docker-entrypoint.sh`
- `.dockerignore`
- `.env.example`
- `install-docker.ps1`
- `start-docker.ps1`
- `settings.json`
- `bin/rikune.js`
- `bin/rikune-docker.js`
- `src/npm-docker-launcher.ts`
- `src/api/`
- `src/storage/`
- `src/runtime-worker-pool.ts`
- `workers/rizin_preview_worker.py`
- `workers/requirements-qiling.txt`

Suggested commit message:

```text
feat(packaging): separate npm launcher from docker runtime
```

### 6. Docs / Release / Cleanup

Use for prerelease-facing documentation and versioning:

- `README.md`
- `README_zh.md`
- `INSTALL.md`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `docs/ANALYSIS-*.md`
- `docs/API-*.md`
- `docs/ASYNC-JOB-PATTERN.md`
- `docs/DOCKER*.md`
- `docs/MCP-CLIENT-DOCKER-CONFIG.md`
- `docs/MIGRATION-*.md`
- `docs/UPLOAD-*.md`
- `docs/PRERELEASE-COMMIT-SCOPE.md`
- `.gitignore`
- `package.json`
- `package-lock.json`
- `requirements.txt`
- deleted temp artifacts:
  - `test-data-sample-ingest/test.db-journal`
  - `test-frida-runtime.db-journal`
  - `tmp-ghidra-cmd-wqLDZV/.../echo-args.cmd`

Suggested commit message:

```text
chore(release): prepare v1.0.0-beta.1 packaging and docs
```

## Paths To Leave Out For Now

These paths exist in the tree but should be reviewed separately before being
treated as prerelease blockers:

- `src/kb/`
- `docs/KNOWLEDGE-BASE.md`
- `tests/integration/kb-integration.test.ts`
- `.github/prompts/`
- `.github/skills/`
- `src/performance-benchmark.ts`
- any unfinished OpenSpec change under `openspec/changes/` that is not already
  reflected in the runtime above

## Non-interactive Staging Examples

Use non-interactive staging so each bucket stays reviewable:

```powershell
git add src/index.ts src/server.ts src/database.ts src/config.ts src/job-queue.ts src/analysis-*.ts src/nonblocking-analysis.ts src/intent-routing.ts src/tool-surface-guidance.ts src/workflows/analyze-*.ts src/workflows/triage.ts src/workflows/summarize.ts src/workflows/deep-static.ts src/workflows/reconstruct.ts
```

```powershell
git add Dockerfile docker-compose.yml docker-entrypoint.sh .dockerignore .env.example install-docker.ps1 start-docker.ps1 settings.json bin/rikune.js bin/rikune-docker.js src/npm-docker-launcher.ts src/api src/storage src/runtime-worker-pool.ts workers/rizin_preview_worker.py workers/requirements-qiling.txt
```

```powershell
git add README.md README_zh.md INSTALL.md CHANGELOG.md CONTRIBUTING.md docs/ANALYSIS-*.md docs/API-*.md docs/ASYNC-JOB-PATTERN.md docs/DOCKER*.md docs/MCP-CLIENT-DOCKER-CONFIG.md docs/MIGRATION-*.md docs/UPLOAD-*.md docs/PRERELEASE-COMMIT-SCOPE.md .gitignore package.json package-lock.json requirements.txt
git add -u test-data-sample-ingest/test.db-journal test-frida-runtime.db-journal tmp-ghidra-cmd-wqLDZV
```

## Release Principle

Do not try to make the worktree clean by hiding real features. For this beta,
the job is to separate:

- what already forms the supported runtime
- what is documentation and packaging for that runtime
- what is still exploratory or incomplete

If a path is already required by the staged runtime, keep it in beta. If it is
unfinished and not on the critical path, defer it rather than forcing it into
the prerelease commit.
