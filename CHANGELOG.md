# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning where practical.

## [Unreleased]

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
