# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning where practical.

## [Unreleased]

- Ongoing reverse-engineering coverage, MCP workflow orchestration, and packaging polish

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
