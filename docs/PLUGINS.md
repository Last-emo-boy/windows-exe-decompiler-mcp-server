# Plugin SDK And Built-In Plugins

Rikune uses plugins for most optional and specialist analysis surfaces. Core intake, workflow, artifact, task, and system tools are registered by `src/core/tool-registry.ts`; specialist tools are registered by plugins under `src/plugins/<id>/`.

The public plugin contract lives in `packages/plugin-sdk/src/index.ts`. Compatibility re-exports are available through `src/plugins/sdk.ts`.

## Plugin Responsibilities

A plugin can:

- register one or more MCP tools;
- declare static, dynamic, or both-domain execution;
- declare dependencies on other plugins;
- declare external system dependencies;
- expose configuration schema for `plugin.list`;
- provide lifecycle hooks;
- provide Docker generation metadata;
- define progressive tool surface rules;
- delegate execution to Runtime Node through a runtime contract.
- declare bounded optional backend Worker contracts for explicit worker-backed tools.

## Built-In Plugins

The repository currently contains 117 built-in plugins.

| ID | Name | Domain | Surface tier |
| --- | --- | --- | --- |
| `android` | Android / APK Analysis | static | 1 |
| `android-package` | Android Package Inventory | static | 1 |
| `android-runtime` | Android Runtime Plan | dynamic | 2 |
| `angr` | angr | static | 3 |
| `api-hash` | API Hash Resolution | static | 2 |
| `apk-smali` | APK Smali Analysis | static | 1 |
| `apple-container` | Apple Container Inventory | static | 1 |
| `apple-objc-swift` | Apple ObjC / Swift Metadata Inventory | static | 1 |
| `apple-signing` | Apple Signing Inventory | static | 1 |
| `batch` | Batch Analysis | both | 0 |
| `behavior-first` | Behavior-First Analysis | dynamic | 2 |
| `binary-diff` | Binary Diff | static | 2 |
| `binary-hardening` | Binary Hardening Inventory | static | 1 |
| `btf` | BTF Type Inventory | static | 1 |
| `bytecode` | Script Bytecode Inventory | static | 1 |
| `ebpf-bytecode` | eBPF Bytecode Inventory | static | 1 |
| `capstone` | Capstone Disassembly | static | 2 |
| `code-analysis` | Code Analysis | static | 0 |
| `compiler-codegen` | Compiler Codegen Fingerprint | static | 1 |
| `container-analysis` | Container / Archive Inventory | static | 2 |
| `cpp-abi-layout` | C++ ABI Layout Inventory | static | 1 |
| `crackme` | CrackMe Automation | static | 3 |
| `cross-module` | Cross-Module Analysis | static | 2 |
| `culifter` | CuLifter GPU Plan | static | 3 |
| `cuda-binary` | CUDA Binary Inventory | static | 2 |
| `debug-session` | Debug Session | dynamic | 3 |
| `deep-unpack` | Deep Unpack | static | 2 |
| `die` | Detect It Easy | static | 0 |
| `dotnet-decompile` | .NET Decompile | static | 2 |
| `dotnet-managed` | .NET Managed Inventory | static | 1 |
| `dotnet-reactor` | .NET Reactor Deobfuscation | static | 2 |
| `dynamic` | Dynamic Analysis Automation | dynamic | 3 |
| `elf-macho` | ELF / Mach-O | static | 1 |
| `external-re-bridge` | External RE Bridge | static | 3 |
| `firmware` | Firmware Analysis | static | 1 |
| `frida` | Frida Instrumentation | dynamic | 3 |
| `ghidra` | Ghidra Integration | static | 3 |
| `go-analysis` | Go Analysis | static | 2 |
| `graphviz` | Graphviz | static | 0 |
| `gtirb` | GTIRB IR Plan | static | 3 |
| `host-correlation` | Host Correlation | static | 2 |
| `ios-runtime` | iOS Runtime Plan | dynamic | 2 |
| `jsimplifier` | JSIMPLIFIER Pipeline Plan | static | 3 |
| `jsir-cascade` | JSIR/CASCADE Plan | static | 3 |
| `jsvmp-analysis` | JSVMP Analysis Plan | static | 2 |
| `jvm` | JVM Bytecode Inventory | static | 1 |
| `jvm-decompile` | JVM Bytecode Decompiler (CFR) | static | 2 |
| `javascript-deobfuscation` | JavaScript Deobfuscation | static | 2 |
| `kb-collaboration` | Knowledge Base & Collaboration | static | 0 |
| `kernel-driver-surface` | Kernel Driver Surface Inventory | static | 1 |
| `lib-identify` | Library Function Identification (FLIRT) | static | 2 |
| `lief` | LIEF Binary Plan | static | 3 |
| `llvm-bitcode` | LLVM Bitcode Inventory | static | 1 |
| `linux-binary` | Linux Binary Inventory | static | 1 |
| `linux-package` | Linux Package Inventory | static | 1 |
| `linux-runtime` | Linux Runtime Plan | dynamic | 2 |
| `macos-runtime` | macOS Runtime Plan | dynamic | 2 |
| `malware` | Malware Analysis | static | 0 |
| `managed-fake-c2` | Managed Fake C2 | dynamic | 2 |
| `managed-il-xrefs` | Managed IL Cross-References | static | 2 |
| `managed-sandbox` | Managed Sandbox | dynamic | 2 |
| `manifold` | Manifold Decompilation Plan | static | 3 |
| `memory-forensics` | Memory Forensics (Volatility 3) | static | 3 |
| `metadata` | File Metadata | static | 0 |
| `miasm` | Miasm IR Plan | static | 3 |
| `ml-model` | ML Model Artifact Inventory | static | 1 |
| `native-debug-types` | Native Debug Types Inventory | static | 1 |
| `native-object` | Native Object Inventory | static | 1 |
| `observability` | observability.metrics | both | 0 |
| `office-analysis` | Office Analysis | static | 1 |
| `panda` | PANDA | dynamic | 3 |
| `pcap-analysis` | PCAP Analysis | static | 1 |
| `pdf-analysis` | PDF Static Analysis | static | 2 |
| `pe-analysis` | PE Analysis | static | 0 |
| `pe-signature` | PE Authenticode Signature | static | 2 |
| `python-decompile` | Python Bytecode Decompiler | static | 2 |
| `qbdi` | QBDI Instrumentation Plan | static | 3 |
| `qiling` | Qiling | dynamic | 3 |
| `radare2` | radare2 Pipeline Plan | static | 3 |
| `remill` | Remill Lift Plan | static | 3 |
| `reporting` | Reporting | both | 0 |
| `restringer` | REstringer Plan | static | 3 |
| `retdec` | RetDec | static | 3 |
| `revng` | rev.ng Pipeline Plan | static | 3 |
| `rizin` | Rizin | static | 3 |
| `runtime-deobfuscate` | Runtime Deobfuscation | dynamic | 2 |
| `rust-binary` | Rust Binary Inventory | static | 1 |
| `sbom` | SBOM | static | 2 |
| `serialization-format` | Serialization Format Inventory | static | 1 |
| `shader-ir` | Shader IR Inventory | static | 1 |
| `similarity` | Sample Similarity | static | 2 |
| `speakeasy` | Speakeasy Emulator | dynamic | 2 |
| `static-triage` | Static Triage | static | 0 |
| `strings` | Strings Extraction | static | 0 |
| `syscall-abi-surface` | Syscall ABI Surface Inventory | static | 2 |
| `tee-enclave` | TEE Enclave Inventory | static | 1 |
| `threat-intel` | Threat Intelligence | static | 0 |
| `triton` | Triton Symbolic Plan | static | 3 |
| `uefi-smm-surface` | UEFI/SMM Surface Inventory | static | 1 |
| `unity-managed` | Unity Managed Inventory | static | 1 |
| `unpacking` | Unpacking | static | 2 |
| `upx` | UPX | static | 2 |
| `visualization` | Visualization & Reporting | static | 0 |
| `vm-analysis` | VM Analysis & Symbolic | static | 3 |
| `vuln-scanner` | Vulnerability Scanner | static | 2 |
| `wabt` | WABT Toolchain Plan | static | 3 |
| `wasm` | WebAssembly Inventory | static | 1 |
| `wasm-component` | WebAssembly Component Model Inventory | static | 1 |
| `wasm-runtime` | WASM Runtime Plan | dynamic | 2 |
| `windows-debug-symbols` | Windows Debug Symbols Inventory | static | 1 |
| `windows-interface-surface` | Windows Interface Surface Inventory | static | 2 |
| `windows-installer` | Windows Installer Inventory | static | 1 |
| `windows-runtime` | Windows Runtime Plan | dynamic | 2 |
| `wine` | Wine | dynamic | 3 |
| `yara` | YARA | static | 0 |
| `yara-x` | YARA-X | static | 2 |
| `zig-binary` | Zig Binary Inventory | static | 1 |

Surface tier meanings:

- `0`: gateway-capable tools, visible only when included in the explicit gateway surface.
- `1`: file-type activated tools.
- `2`: finding/signal activated tools.
- `3`: expert tools, usually selected by `workflow.search` and exposed only through explicit activation or readiness checks.

`pdf-analysis` exposes `pdf.analyze`, a bounded passive parser backed by a bundled Python standard-library worker. It inventories PDF objects, embedded JavaScript as text, URIs, actions, and embedded-file markers without opening the document, evaluating JavaScript, or using the network.

## Discovery Portal Contract

Rikune intentionally starts with a small MCP gateway surface: `workflow.search`, `workflow.run`,
and `artifact.read`. Hidden core tools and specialist plugin tools are still registered, but direct
calls remain blocked by `ToolExecutor` until the surface manager exposes them. Clients should route
through `workflow.search` instead of assuming the full plugin catalog is visible at startup.

The remote `rikune-agent` connector follows the same contract with stable transport names:
`workflow_search`, `workflow_run`, `artifact_read`, and the advanced `rikune_tool_call` subtool
gateway. Its `rikune_connection_refresh` command refreshes the internal upstream capability cache
only; it must not be treated as a request for MCP clients to hot-load newly discovered specialist
tools.

`workflow.search` is the AI-facing profile-search and controlled activation gateway. The lower-level
`tools.discover` handler remains registered for compatibility and internal activation plumbing. It
supports four release-guarded actions:

| Action | Purpose | Backend behavior |
| --- | --- | --- |
| `status` | Report progressive surface counts: total plugins/tools and visible plugins/tools. | Metadata only. |
| `list` | Search registered core/plugin capabilities by query, sample id, file type, category, plugin id, or tool name. | Metadata only. |
| `recommend` | Rank matching tools and plugin toolchains for a sample or goal. | Metadata only; no readiness bypass. |
| `activate` | Expose matching hidden core tools or plugin tools by tool, plugin, category, finding, or file type. | Activation only; no backend execution. |

Recommendation entries include:

- `score` and `match_reasons`: explain why a toolchain matched the query, file type, aspects, or
  workflow recipe.
- `readiness_state`: `ready`, `hidden_activation_required`, `backend_profile_required`,
  `byo_backend_required`, `sidecar_backend_required`, `license_profile_required`,
  `runtime_opt_in_required`, `backend_readiness_required`, `readiness_warning`, or `blocked`.
- `activation_plan` and `activation_command`: the exact next portal action needed before direct
  tool calls.
- `why_hidden`: the progressive-surface reason a tool is not initially callable.
- `backend_install_profile` and `backend_profile_summary`: Docker/backend install routes and
  profile gates for external binaries, BYO tools, sidecars, runtimes, GPU tooling, or license gates.
- `recommended_tools`, `available_tools`, `blocked_tools`, `missing_deps`, and `next_actions`:
  machine-readable routing hints for the next stage.

Activation responses include `activation_audit`, which records the request, activated plugins,
activated core tools, activated tool names, matched sample/file-type context, and policy facts. The
audit must preserve `readiness_not_bypassed: true` and `backend_execution_started: false`.
Discovery, help, readiness, plugin listing, catalog generation, and Docker dry-run paths must never
start Ghidra, RetDec, radare2, Rizin, IDA, Binary Ninja, emulators, debuggers, solvers, browser/JS
runtimes, GPU tooling, or user samples.

## Plugin Standard v2

Plugin Standard v2 is the non-breaking contract for built-in and external plugins. During the
migration window, missing metadata is reported as `qualityWarnings`; it does not prevent plugin
loading unless the plugin shape itself is invalid.

Required plugin-level fields:

- `id`, `name`, `description`, `version`
- `executionDomain`: `static`, `dynamic`, or `both`
- `aspects`: at least one useful routing group, usually `formats`, `platforms`, `execution`,
  `safety`, `capabilities`, or `evidence`
- `surfaceRules`: tier and category, plus `activateOn` rules for tier 1 or tier 2 plugins
- `tools` or `register()`

Required tool-level fields:

- `definition.name`, `description`, `inputSchema`, and `outputSchema`
- `aspects` when the tool has narrower scope than the plugin
- `artifacts` or `evidence` when the tool emits analysis results
- `workflowRecipes` when the tool starts, advances, or completes a workflow/correlation chain
- `runtimePolicy` and either a `runtime` contract or explicit plan-only semantics for dynamic
  and runtime-backed tools
- `workerBackend` when a tool delegates to an optional backend Worker

Quality warning severities are intentionally warning-first:

| Code | Meaning | Migration action |
| --- | --- | --- |
| `missing-output-schema` | Tool output is not machine-described | Add `outputSchema` or a shared worker-result schema |
| `missing-surface-rules` | Plugin defaults to always visible | Add tier/category and activation rules |
| `missing-aspects` | Plugin or tool cannot be routed by profile | Add aspect metadata |
| `missing-evidence` | Tool result provenance is unclear | Add artifact or evidence declarations |
| `missing-workflow-recipe` | Workflow/correlation-capable tool cannot explain follow-up flow | Add `workflowRecipes` with recipe id, inputs, outputs, next tools, and safety tags |
| `missing-runtime-policy` | Runtime behavior is not policy-described | Add `runtimePolicy` |
| `dynamic-runtime-contract-missing` | Dynamic tool has no delegation contract | Add `runtime` or make the tool clearly plan-only |
| `missing-system-deps` | Dependency readiness cannot be explained | Add `systemDeps` or a `check()` hook |
| `missing-readiness-check` | Dynamic plugin lacks readiness metadata | Add `systemDeps`, `check()`, or plan-only readiness semantics |
| `missing-tools` | Plugin has no tools or register handler | Add declarative tools or `register()` |

The canonical audit helper is `auditPluginQuality()` from `@rikune/plugin-sdk`. The core
orchestrator uses it to populate `plugin.list`, `tools.discover`, `tool.help`, and
`tool.readiness` quality metadata.

## Capability Workflows

Workflow recipes are additive metadata for cross-plugin analysis chains. They are exposed by
`plugin.list`, `tools.discover`, `tool.help`, `tool.readiness`, and `sample.profile.get`; they
must not start runtime backends or inspect samples by themselves.

Use `workflowRecipes` on each tool that acts as a workflow entry, bridge, or terminal evidence
collector. Supported fields:

- `id`: stable kebab/dot-case recipe id, such as `android.static.behavior`.
- `title` and optional `description`: short human-readable purpose.
- `startsWith`: tool names that can seed the recipe.
- `nextTools`: follow-up tools clients may choose after this tool succeeds.
- `requiredArtifacts`: artifact types or evidence bundles the tool expects.
- `producesArtifacts`: artifact types the tool emits or refines.
- `evidence`: evidence tags produced or consumed by the recipe.
- `safety`: passive and runtime-gate tags clients must preserve.
- `runtimeBackends`: backend names for plan-only or opt-in runtime handoff.

Shared artifact/evidence vocabulary for this iteration:

- `workflow_recipe`: workflow metadata envelope emitted by discovery/help/readiness surfaces.
- `finding_bundle`: grouped findings that can be routed into another plugin without parsing prose.
- `correlation_graph`: cross-tool relation graph for artifacts, processes, files, imports, IOCs, or packages.
- `provenance_graph`: source-to-derived-artifact lineage graph with tool and sample anchors.
- `runtime_plan`: plan-only runtime guidance that does not start a backend.
- `analysis_memory`: reusable analyst notes, rules, labels, or sample facts captured for future routing.
- `analysis_report`: generated report artifact consuming structured evidence.

Workflow-capable tools usually declare `execution: ["correlation"]`, `capabilities` containing
`workflow-*` or graph terms, or `evidence` containing `workflow`, `correlation-graph`, or
`provenance-graph`. When such a tool lacks `workflowRecipes`, `auditPluginQuality()` reports
`missing-workflow-recipe` with a `suggested_task_owner` identifying the relevant capability task.

### Completed Capability Workflow Recipes

The current capability iteration fixed the following workflow recipes as release-guarded metadata.
These recipes are discoverable through `plugin.list`, `tools.discover`, `tool.help`,
`tool.readiness`, and the plugin aspect matrix. Default recipe paths are passive: they do not start
runtime backends, execute samples, perform network lookups, mount images, install packages, launch
emulators, or attach debuggers.

| Recipe | Plugin | Entry tool | Primary follow-up tools | Default safety boundary |
| --- | --- | --- | --- | --- |
| `memory-forensics.offline-correlation` | `memory-forensics` | `memory-forensics.correlate` | `analysis.evidence.graph`, `report.generate` | Existing Volatility rows only; no live memory, no network. |
| `vm.symbolic.workflow` | `vm-analysis` | `vm.workflow.plan` | `constraint.extract`, `smt.solve`, `keygen.synthesize` | Planner only; no solver or emulator is started. |
| `kb.analysis-memory.reuse` | `kb-collaboration` | `kb.context.suggest` | `kb.function.match`, `rule.library`, `kb.export` | Local analysis memory only; no network. |
| `kb.function-match.reuse-handoff` | `kb-collaboration` | `kb.function.match` | `analysis.evidence.graph`, `analysis.notes`, `rule.library`, `kb.export`, `report.generate` | Deterministic local function correlation only; no sample execution, mutation, or network. |
| `windows.runtime.opt-in` | `windows-runtime` | `windows.runtime.plan` | `dynamic.runtime.status`, runtime-backed tools after approval | Plan-only, opt-in, isolated, network disabled. |
| `linux.runtime.opt-in` | `linux-runtime` | `linux.runtime.plan` | `dynamic.runtime.status`, `qiling`/debug tooling after approval | Plan-only, opt-in, isolated, network disabled. |
| `macos.runtime.opt-in` | `macos-runtime` | `macos.runtime.plan` | `dynamic.runtime.status`, LLDB/DTrace tooling after approval | Plan-only, opt-in, isolated, network disabled. |
| `ios.runtime.opt-in` | `ios-runtime` | `ios.runtime.plan` | `tool.readiness`, Frida/LLDB tooling after approval | Plan-only; no install, device attach, or simulator start. |
| `android.runtime.opt-in` | `android-runtime` | `android.runtime.plan` | `dynamic.toolkit.status`, ADB/emulator/Frida tooling after approval | Plan-only; no install, launch, device connection, or Frida attach. |
| `wasm.runtime.opt-in` | `wasm-runtime` | `wasm.runtime.plan` | `tool.readiness`, wasmtime tooling after approval | Plan-only; no module instantiation or WASI grant. |
| `supply-chain.sbom.provenance` | `sbom` | `sbom.provenance.graph` | `sbom.generate`, `vuln.pattern.summary`, `report.generate` | Local inventories only; no install, mount, execute, or network lookup. |
| `container.image-security-profile` | `container-analysis` | `container.image.security.profile` | `container.structure.analyze`, `sbom.provenance.graph`, `sbom.generate`, `analysis.evidence.graph`, `report.generate` | Passive Docker/OCI image config and layer-header profile only; no registry network, Docker daemon, image load, layer extraction, mount, package install, entrypoint, mutation, or CVE lookup. |
| `ml.model-static-inventory` | `ml-model` | `ml.model.inventory` | `artifact.read`, `metadata.extract`, `strings.extract`, `analysis.evidence.graph`, `report.generate` | Passive ML model artifact inventory for SafeTensors, GGUF/GGML, ONNX, TFLite, PyTorch/pickle checkpoints, and NumPy arrays; no deserialization, model load, inference, ML framework import, archive extraction, mutation, or network. |
| `shader.ir-static-inventory` | `shader-ir` | `shader.ir.inventory` | `artifact.read`, `metadata.extract`, `strings.extract`, `llvm.bitcode.inventory`, `culifter.gpu.plan`, `analysis.evidence.graph`, `report.generate` | Passive shader IR inventory for SPIR-V, DXIL/DXBC containers, WGSL source, and Metal library hints; no validator, compiler, disassembler, GPU driver, GPU access, shader runtime, sample execution, mutation, or network. |
| `wasm.component-static-inventory` | `wasm-component` | `wasm.component.inventory` | `wasm.structure.analyze`, `wasm.runtime.plan`, `wabt.toolchain.plan`, `analysis.evidence.graph`, `artifact.read`, `strings.extract`, `sbom.generate` | Passive WebAssembly Component Model inventory for WIT/WASI Preview 2, component imports/exports, and Canonical ABI hints; no component instantiation, wasmtime start, WASI grant, external wasm tooling, package fetch, mutation, or network. |
| `android.static.behavior-graph` | `android` | `android.behavior.graph` | `dex.classes.list`, `android.runtime.plan` | Static graph only; no APK launch, device connection, or runtime start. |
| `apple.security.runtime-profile` | `apple-signing` | `apple.security.profile` | `macho.structure.analyze`, `macos.runtime.plan`, `ios.runtime.plan` | Static profile only; no mount, install, keychain, codesign, or device action. |
| `apple.objc-swift-metadata-static-inventory` | `apple-objc-swift` | `apple.objc_swift.metadata.inspect` | `macho.structure.analyze`, `apple.signing.inspect`, `apple.security.profile`, `analysis.evidence.graph`, `artifact.read`, `strings.extract`, `report.generate`, `macos.runtime.plan`, `ios.runtime.plan` | Passive Objective-C class/protocol/selector and Swift ABI/reflection metadata inventory; no app launch, debugger attach, device connection, DMG mount, external Apple tooling, demangle process, runtime start, mutation, or network. |
| `pe.security.hardening-profile` | `pe-analysis` | `pe.security.profile` | `pe.structure.analyze`, `pe.imports.extract`, `pe.pdata.extract`, `analysis.evidence.graph`, `windows.runtime.plan` | Static PE mitigation profile only; no DLL load, loader invocation, exploit test, network, or mutation. |
| `firmware.iot.passive-workflow` | `firmware` | `firmware.workflow.plan` | `firmware.entropy`, `sbom.provenance.graph`, `qiling.inspect` | Passive workflow plan; no extraction-to-execute, mount, module load, or emulation. |
| `office.macro.static-profile` | `office-analysis` | `office.behavior.profile` | `ioc.export`, `yara.generate`, `sigma.rule.generate`, `report.generate` | Static macro profile only; no Office automation or macro execution. |
| `static-triage.capability-correlation` | `static-triage` | `static.capability.triage` | `static.config.carver`, `static.behavior.classify`, `crypto.identify`, `packer.detect`, `analysis.evidence.graph`, `malware.intel.loop` | Passive capability correlation bundle for behavior/config/crypto/packer routing; no live sample, dynamic backend, or network access. |
| `static-triage.config-evidence-correlation` | `static-triage` | `static.config.carver` | `malware.intel.loop`, `ioc.export`, `static.behavior.classify`, `dynamic.behavior.diff`, `analysis.evidence.graph`, `report.generate` | Passive config and IOC carving handoff for evidence graph/reporting; runtime validation requires explicit opt-in. |
| `static-triage.resource-payload-correlation` | `static-triage` | `static.resource.graph` | `static.config.carver`, `entropy.analyze`, `strings.extract`, `crypto.identify`, `unpack.workflow.plan`, `analysis.evidence.graph`, `report.generate` | Passive resource and embedded payload handoff for config carving, unpack planning, evidence graph, and reporting; runtime follow-up requires explicit opt-in. |
| `static-triage.compiler-packer-attribution` | `static-triage` | `compiler.packer.detect` | `packer.detect`, `entropy.analyze`, `static.resource.graph`, `unpack.workflow.plan`, `static.capability.triage`, `code.cross_decompiler.consensus`, `analysis.evidence.graph`, `report.generate` | Passive Detect It Easy-style compiler, packer, protector, and file-type attribution handoff for unpack planning, evidence graph, and reporting; runtime follow-up requires explicit opt-in. |
| `static-triage.behavior-runtime-validation` | `static-triage` | `static.behavior.classify` | `dynamic.behavior.diff`, `dynamic.deep_plan`, `breakpoint.smart`, `trace.condition`, `analysis.evidence.graph`, `report.generate` | Static behavior classifier handoff with evidence graph nodes and opt-in runtime validation gates; no live sample, backend, mutation, or network by default. |
| `static-triage.crypto-runtime-tracing` | `static-triage` | `crypto.identify` | `breakpoint.smart`, `trace.condition`, `crypto.lifecycle.graph`, `analysis.evidence.graph`, `report.generate` | Passive crypto identification handoff with evidence graph and lifecycle routing; runtime tracing requires explicit opt-in. |
| `unpacking.detect-plan-retriage` | `unpacking` | `unpack.workflow.plan` | `unpack.auto`, `runtime.deobfuscate.plan`, `static.triage`, `analysis.evidence.graph` | Passive plan with packer confidence, runtime gate matrix, re-triage handoff, and opt-in gates; no live unpacking by default. |
| `similarity.family-cluster` | `similarity` | `sample.family.cluster` | `binary.diff.summary`, `kb.context.suggest`, `report.generate` | Corpus-local clustering; no private dataset or network requirement. |
| `strings.raw-extraction-evidence` | `strings` | `strings.extract` | `analysis.context.link`, `strings.floss.decode`, `static.config.carver`, `malware.intel.loop`, `analysis.evidence.graph`, `report.generate` | Passive raw string evidence handoff for context linking, FLOSS follow-up, IOC/config carving, evidence graph, and reporting; no live sample or network access. |
| `strings.floss-decoded-evidence` | `strings` | `strings.floss.decode` | `analysis.context.link`, `static.config.carver`, `malware.intel.loop`, `analysis.evidence.graph`, `report.generate` | Passive FLOSS decoded string evidence handoff for context linking, IOC/config carving, evidence graph, and reporting; no live sample or network access. |
| `yara.rule-generation-handoff` | `yara` | `yara.generate` | `yara.scan`, `analysis.evidence.graph`, `report.generate`, `artifact.read` | Passive YARA rule generation handoff with score gates, false-positive review routing, evidence graph, and reporting; no live sample or network access. |
| `yara.family-rule-generation-handoff` | `yara` | `yara.generate.batch` | `yara.scan`, `sample.family.cluster`, `analysis.evidence.graph`, `report.generate`, `artifact.read` | Passive multi-sample YARA family rule handoff with common-feature evidence, family cluster review, corpus validation, evidence graph, and reporting; no live sample or network access. |
| `yara-x.scan-validation-handoff` | `yara-x` | `yara_x.scan` | `artifact.read`, `yara.scan`, `analysis.evidence.graph`, `report.generate` | Passive YARA-X scan validation handoff with bounded match previews, legacy YARA comparison, evidence graph, and reporting; no live sample or network access. |
| `upx.inspect-validation-handoff` | `upx` | `upx.inspect` | `artifact.read`, `unpack.workflow.plan`, `static.triage`, `analysis.evidence.graph`, `report.generate` | Passive UPX inspection and decompression handoff with packed-sample validation, decompressed artifact re-triage, evidence graph, and reporting; no live sample execution or network access. |
| `die.scan-validation-handoff` | `die` | `die.scan` | `artifact.read`, `compiler.packer.detect`, `packer.detect`, `unpack.workflow.plan`, `static.capability.triage`, `crypto.identify`, `analysis.evidence.graph`, `report.generate` | Passive Detect It Easy signature scan handoff with compiler, packer, protector, crypto, evidence graph, and reporting routes; runtime follow-up requires explicit opt-in. |
| `api-hash.resolver-recovery` | `api-hash` | `hash.resolver.plan` | `hash.identify`, `hash.resolve`, `analysis.evidence.graph`, `report.generate` | Static resolver/hash planning with evidence handoff and quality gates; runtime breakpoint or trace follow-up requires explicit opt-in. |
| `threat-intel.ioc-export-handoff` | `threat-intel` | `ioc.export` | `analysis.evidence.graph`, `malware.intel.loop`, `attack.map`, `sigma.rule.generate`, `yara.generate`, `report.generate` | Passive IOC export handoff for JSON, CSV, and STIX artifacts with quality gates, ATT&CK routing, evidence graph, detection generation, and reporting; no live sample or network access. |
| `threat-intel.sigma-rule-generation-handoff` | `threat-intel` | `sigma.rule.generate` | `analysis.evidence.graph`, `attack.map`, `ioc.export`, `yara.generate`, `report.generate`, `artifact.read` | Passive Sigma rule generation handoff with quality gates, ATT&CK/IOC/YARA feedback, evidence graph, artifact review, and reporting; no live sample, SIEM mutation, or network access. |
| `malware.intel.feedback-loop` | `malware` | `malware.intel.loop` | `ioc.export`, `attack.map`, `sigma.rule.generate`, `yara.generate`, `analysis.evidence.graph`, `report.generate` | Offline IOC provenance fusion with quality gates; no threat-intel network lookup by default. |
| `visualization.plugin-evidence-reporting` | `visualization` | `analysis.evidence.graph` | `workflow.summarize`, `report.summarize`, `report.generate`, `artifact.read` | Passive graph/report handoff over existing plugin artifacts only; no backend, sample execution, mutation, or network access. |
| `javascript.deobfuscation.jsvmp-triage` | `javascript-deobfuscation` | `javascript.obfuscation.profile` | `strings.extract`, `yara.generate`, `analysis.evidence.graph`, `report.generate` | Passive source/profile triage only; no JavaScript execution, Node/V8 start, network, or external deobfuscator invocation. |
| `jsvmp.bytecode.recovery-plan` | `jsvmp-analysis` | `jsvmp.bytecode.plan` | `strings.extract`, `yara.generate`, `analysis.evidence.graph`, `report.generate` | Plan-only bytecode/handler-map recovery; no JavaScript evaluation, interpreter-assisted normalization, Node/V8/browser start, or external backend invocation. |
| `jsimplifier.javascript.pipeline-plan` | `jsimplifier` | `jsimplifier.pipeline.plan` | `restringer.deobfuscation.plan`, `jsir.cascade.plan`, `jsvmp.bytecode.plan`, `analysis.evidence.graph` | Plan-only staged JavaScript deobfuscation; no dynamic trace, LLM call, JavaScript execution, Node/V8 start, or network. |
| `jsir.cascade.normalization-plan` | `jsir-cascade` | `jsir.cascade.plan` | `jsvmp.bytecode.plan`, `strings.extract`, `yara.generate`, `analysis.evidence.graph` | Plan-only IR normalization; no JavaScript execution, browser automation, Node/V8 start, or external deobfuscator invocation. |
| `restringer.javascript.preprocess-plan` | `restringer` | `restringer.deobfuscation.plan` | `jsir.cascade.plan`, `jsvmp.bytecode.plan`, `strings.extract`, `yara.generate` | Plan-only string-array/expression deobfuscation planning; no REstringer process, Node/V8 start, or source evaluation. |
| `reverse.cross-decompiler.consensus` | `code-analysis` | `code.cross_decompiler.consensus` | `code.functions.reconstruct`, `code.function.explain.prepare`, `code.function.cfg`, `analysis.evidence.graph`, `report.generate` | Fixture-safe consensus over existing decompiler/IR artifacts with function handoff and quality gates; no backend process, live sample, mutation, or network. |
| `revng.lift-decompile.plan` | `revng` | `revng.pipeline.plan` | `rizin.analyze`, `ghidra.analyze`, `retdec.decompile`, `analysis.evidence.graph` | Plan-only backend integration; no rev.ng process, lifting, decompile, execution, mount, or network. |
| `remill.llvm.lift-plan` | `remill` | `remill.lift.plan` | `revng.pipeline.plan`, `gtirb.ir.plan`, `ghidra.analyze`, `analysis.evidence.graph` | Plan-only LLVM lifting workflow; no Remill process, loader, emulator, solver, debugger, or network. |
| `gtirb.binary.ir-plan` | `gtirb` | `gtirb.ir.plan` | `remill.lift.plan`, `revng.pipeline.plan`, `rizin.analyze`, `analysis.evidence.graph` | Plan-only binary IR and rewrite-boundary planning; no GTIRB tooling, binary rewriting, mutation, loader, or network. |
| `triton.symbolic.recovery-plan` | `triton` | `triton.symbolic.plan` | `constraint.extract`, `smt.solve`, `vm.workflow.plan`, `analysis.evidence.graph` | Plan-only symbolic workflow; no Triton/Unicorn emulation, solver run, live execution, or network. |
| `miasm.ir.deobfuscation-plan` | `miasm` | `miasm.ir.plan` | `code.function.cfg`, `constraint.extract`, `smt.solve`, `analysis.evidence.graph` | Plan-only IR/data-flow workflow; no Python backend start, IR lifting, symbolic execution, or network. |
| `lief.binary.structure-plan` | `lief` | `lief.binary.plan` | `pe.signature.verify`, `native.object.inventory`, `sbom.provenance.graph` | Plan-only LIEF integration; no binary modification, backend parsing, signing mutation, or network. |
| `radare2.cross-backend.plan` | `radare2` | `radare2.pipeline.plan` | `rizin.analyze`, `ghidra.analyze`, `retdec.decompile`, `analysis.evidence.graph` | Plan-only compatibility backend; no radare2 process, r2pipe command execution, debugger attach, or network. |
| `qbdi.dbi.opt-in-plan` | `qbdi` | `qbdi.instrumentation.plan` | `windows.runtime.plan`, `linux.runtime.plan`, `macos.runtime.plan`, `dynamic.runtime.status` | Plan-only DBI handoff; no QBDI load, process launch, instrumentation injection, debugger attach, or live execution. |
| `manifold.superset.decompilation-plan` | `manifold` | `manifold.decompilation.plan` | `revng.pipeline.plan`, `gtirb.ir.plan`, `miasm.ir.plan`, `analysis.evidence.graph` | Plan-only superset-decompilation workflow; no decompiler, fact engine, lifter, solver, or network. |
| `culifter.gpu.lift-plan` | `culifter` | `culifter.gpu.plan` | `linux.binary.inventory`, `native.object.inventory`, `strings.extract`, `sbom.provenance.graph` | Plan-only GPU binary lifting workflow; no GPU driver, profiler, emulator, lifter, or sample execution. |
| `cuda.binary.static-inventory-handoff` | `cuda-binary` | `cuda.binary.inventory` | `culifter.gpu.plan`, `culifter.gpu.artifact.inventory`, `native.object.inventory`, `linux.binary.inventory`, `strings.extract`, `sbom.provenance.graph`, `analysis.evidence.graph` | Passive CUDA/PTX/CUBIN/fatbin inventory; no CUDA driver, GPU access, cuobjdump, nvdisasm, profiler, or sample execution. |
| `btf.type-core-inventory` | `btf` | `btf.type.inventory` | `ebpf.bytecode.inventory`, `native.object.inventory`, `linux.binary.inventory`, `analysis.evidence.graph`, `report.generate`, `linux.runtime.plan` | Passive BTF type and CO-RE relocation inventory; no `bpf()` syscall, kernel verifier, program load, libbpf, bpftool, runtime start, or network. |
| `ebpf.bytecode-static-inventory` | `ebpf-bytecode` | `ebpf.bytecode.inventory` | `native.object.inventory`, `linux.binary.inventory`, `analysis.evidence.graph`, `linux.runtime.plan` | Passive eBPF bytecode and ELF EM_BPF inventory; no `bpf()` syscall, kernel verifier run, program load, attach, map creation, runtime start, or network. |
| `binary.hardening-static-inventory` | `binary-hardening` | `binary.hardening.inventory` | `pe.security.profile`, `elf.structure.analyze`, `macho.structure.analyze`, `compiler.codegen.fingerprint`, `analysis.evidence.graph`, `report.generate`, `workflow.search` | Passive cross-platform exploit-mitigation and hardening posture inventory for ELF, PE, Mach-O, object artifacts, CET, PAC/BTI, MTE, and CHERI hints; no loaders, exploit tests, debuggers, emulators, external tools, network, mutation, or rewriting. |
| `native.debug-types-static-inventory` | `native-debug-types` | `native.debug.types.inventory` | `native.object.inventory`, `windows.debug.metadata.inspect`, `elf.structure.analyze`, `macho.structure.analyze`, `strings.extract`, `analysis.evidence.graph`, `artifact.read`, `report.generate`, `workflow.search` | Passive DWARF, split-DWARF, and CTF debug/type metadata inventory; no debugger, native load, external dumpers, symbol-server download, source fetch, mutation, or network. |
| `cpp.abi-layout-static-inventory` | `cpp-abi-layout` | `cpp.abi.layout.inventory` | `native.object.inventory`, `native.debug.types.inventory`, `windows.debug.metadata.inspect`, `pe.structure.analyze`, `elf.structure.analyze`, `macho.structure.analyze`, `strings.extract`, `code.xrefs.analyze`, `analysis.evidence.graph`, `artifact.read`, `report.generate`, `workflow.search` | Passive Itanium/MSVC C++ ABI vtable, RTTI/typeinfo, EH personality, and class-layout seed inventory; no execution, native load, link, debugger, external demangler, symbol-server download, source fetch, mutation, or network. |
| `kernel.driver-surface-static-inventory` | `kernel-driver-surface` | `kernel.driver.surface.inventory` | `pe.structure.analyze`, `pe.imports.extract`, `pe.security.profile`, `linux.binary.inventory`, `native.object.inventory`, `native.debug.types.inventory`, `strings.extract`, `code.xrefs.analyze`, `vuln.pattern.scan`, `analysis.evidence.graph`, `windows.runtime.plan`, `linux.runtime.plan`, `artifact.read`, `report.generate`, `workflow.search` | Passive Windows/Linux kernel driver surface inventory for IOCTL constants, device interfaces, dispatch hints, Linux module metadata, and risky primitives; no driver load, kernel module insertion, device open, IOCTL send, syscall, kernel probe, debugger, external tool, mutation, or network. |
| `syscall.abi-surface-static-inventory` | `syscall-abi-surface` | `syscall.abi.surface.inventory` | `artifact.read`, `metadata.extract`, `strings.extract`, `pe.imports.extract`, `linux.binary.inventory`, `native.object.inventory`, `code.xrefs.analyze`, `vuln.pattern.scan`, `analysis.evidence.graph`, `report.generate`, `workflow.search` | Passive syscall ABI and user-kernel boundary inventory for Windows direct syscall stubs, NT resolver strings, Linux syscall/seccomp hints, Mach traps, ARM SVC/RISC-V ecall patterns, and evasion risk routing; no sample execution, syscall invocation, ptrace/strace/ltrace, debugger, Frida, emulation, device open, driver load, external tool, mutation, or network. |
| `windows.interface-surface-static-inventory` | `windows-interface-surface` | `windows.interface.surface.inventory` | `artifact.read`, `metadata.extract`, `strings.extract`, `pe.imports.extract`, `pe.structure.analyze`, `static.resource.graph`, `pe.security.profile`, `windows.debug.metadata.inspect`, `code.xrefs.analyze`, `vuln.pattern.scan`, `host.correlate`, `analysis.evidence.graph`, `report.generate`, `workflow.search` | Passive Windows userland interface inventory for COM/DCOM CLSID/IID, RPC UUID/endpoints, ALPC/named-pipe IPC, ETW provider hints, WMI namespaces/classes, service-control references, and static workflow handoff; no sample execution, COM activation, RPC call, ALPC/named-pipe connection, WMI query, service start, ETW registration, debugger, external tool, network, or mutation. |
| `compiler.codegen-fingerprint-static-inventory` | `compiler-codegen` | `compiler.codegen.fingerprint` | `artifact.read`, `metadata.extract`, `native.object.inventory`, `native.debug.types.inventory`, `windows.debug.metadata.inspect`, `cpp.abi.layout.inventory`, `pe.structure.analyze`, `elf.structure.analyze`, `macho.structure.analyze`, `strings.extract`, `compiler.packer.detect`, `sbom.provenance.graph`, `sample.family.cluster`, `analysis.evidence.graph`, `report.generate`, `workflow.search` | Passive compiler/codegen provenance fingerprinting for PE Rich/CodeView, ELF `.comment`/build-id, language runtime markers, linker hints, section layout, and optimization/LTO/PGO evidence; no sample execution, native load, debugger, compiler/linker invocation, external tool, symbol-server download, source fetch, network, or mutation. |
| `rust.binary-static-inventory` | `rust-binary` | `rust.binary.inventory` | `compiler.codegen.fingerprint`, `native.object.inventory`, `native.debug.types.inventory`, `strings.extract`, `sbom.provenance.graph`, `sample.family.cluster`, `analysis.evidence.graph`, `report.generate`, `workflow.search` | Passive Rust language/runtime inventory for ELF, PE, Mach-O, object, rlib, and rmeta artifacts, covering Rust v0/legacy mangled symbol candidates, rustc/Cargo/crate hints, panic/unwind profile, allocator/runtime markers, and target triples; no sample execution, native load, rustc/cargo invocation, external demangler, symbol-server/source fetch, network, mutation, or rewriting. |
| `tee.enclave-static-inventory` | `tee-enclave` | `tee.enclave.inventory` | `artifact.read`, `metadata.extract`, `native.object.inventory`, `native.debug.types.inventory`, `compiler.codegen.fingerprint`, `elf.structure.analyze`, `pe.structure.analyze`, `strings.extract`, `sbom.provenance.graph`, `analysis.evidence.graph`, `report.generate`, `workflow.search` | Passive confidential-computing and TEE enclave inventory for SGX, OP-TEE/TrustZone TA, TDX, AMD SEV-SNP, and RISC-V enclave static evidence; no sample execution, enclave load, attestation request, quote generation, TEE/kernel driver call, key derivation, debugger, emulation, external tool, network, or mutation. |
| `uefi.smm-surface-static-inventory` | `uefi-smm-surface` | `uefi.smm.surface.inventory` | `artifact.read`, `firmware.scan`, `firmware.workflow.plan`, `pe.structure.analyze`, `pe.imports.extract`, `strings.extract`, `code.xrefs.analyze`, `vuln.pattern.scan`, `analysis.evidence.graph`, `report.generate`, `workflow.search` | Passive UEFI/SMM trust-boundary inventory for SMI handler, CommBuffer, protocol/service, NVRAM/Secure Boot variable, flash/capsule, MMIO, and MSR evidence; no firmware boot, SMI trigger, SMM execution, EFI variable write, NVRAM mutation, capsule apply, SPI flash/MMIO/MSR access, emulation, external tool, mutation, or network. |
| `llvm.bitcode-static-inventory` | `llvm-bitcode` | `llvm.bitcode.inventory` | `artifact.read`, `metadata.extract`, `strings.extract`, `analysis.evidence.graph`, `report.generate`, `workflow.search` | Passive LLVM bitcode and wrapper inventory; no LLVM toolchain, compile, link, JIT, interpreter, sample execution, mutation, or network. |
| `wabt.wasm.toolchain-plan` | `wabt` | `wabt.toolchain.plan` | `strings.extract`, `sbom.generate`, `wasm.runtime.plan`, `analysis.evidence.graph` | Plan-only WABT toolchain routing; no wasm2wat/wasm-objdump process, module instantiation, WASI grant, or network. |

### Explainable Local Function Matching

`kb.function.match` uses two explicit reference modes:

- With `match_against`, it compares the target function index with function evidence from the
  requested samples. Only a syntactically validated SHA-256 or SHA-512 function-byte digest can
  produce an authoritative exact match; weak, mismatched, or malformed digests fall back to feature
  matching. Legacy API-call plus size similarity remains visible for existing clients, but
  single-view results are capped below high-confidence and require analyst review.
- Without `match_against`, it queries a server-bounded `function_kb` candidate set, excluding every
  entry associated with the target sample after canonical SHA-256 identity normalization. API-only
  seed entries cannot cross the default match threshold by themselves. Indexed scan windows,
  per-row limits, total-byte budgets, and pair-count budgets bound the query and comparison set;
  truncation is explicit in warnings, diagnostics, and quality gates.

Non-exact matches use a deterministic multi-view profile over API calls, strings, CFG shape,
crypto constants, call context, and function size. It requires at least two independent strong
views for a KB match, normalizes over comparable evidence, and then applies coverage and stored
reference trust. Every match reports `score_breakdown`, `score_weights`, `shared_features`,
`match_basis`, `calibration`, comparable and matched evidence coverage, reference provenance, and
bounded alternatives with explicit truncation state. Candidates within the declared ambiguity
margin are marked for analyst review; stable tie-breaking keeps output independent of SQLite row
order. This profile is a documented heuristic rather than a statistically calibrated probability,
and the result remains a similarity hypothesis rather than proof of semantic equivalence, so
annotation propagation must follow evidence review.

## Advanced Safety Categories

Advanced plugin iteration is grouped by risk so CI can audit contracts without invoking heavy or
unsafe backends:

| Category | Applies to | Required default |
| --- | --- | --- |
| `passive-static` | file inventory, parsing, strings, package metadata, signatures | May read existing sample/workspace files only |
| `external-binary` | Ghidra, RetDec, Rizin, Volatility, JADX, APKTool, binwalk, DIE, YARA-X | Must degrade through readiness/systemDeps and focused tests |
| `runtime-gated` | sandbox, emulator, debugger, Frida, Wine, Qiling, Speakeasy, PANDA, wasmtime | Must be passive by default, opt-in, isolated, and visible through `tool.readiness` |
| `network-sensitive` | threat intel, IOC export, malware config enrichment, package/vulnerability lookups | Must be offline in tests and declare `no_network_by_default` unless explicitly record-only |
| `corpus-dependent` | similarity, binary diff, family clustering, KB memory | Must handle empty corpus and never require private datasets in CI |
| `container-or-installer` | firmware extraction, container archive traversal, MSI/MSIX/PKG/DMG/APK/IPA | No mount, install, launch, entrypoint, package script, or custom action execution by default |

## Worker-Backed Plugin Tools

Worker-backed tools are explicit execution surfaces that sit beside existing plan-only tools. They share `backend-worker.v1`, return structured `WorkerResult` payloads, and expose readiness metadata without starting external backends. Builtin mode is fixture-safe and deterministic; external mode requires a configured backend path or runtime handoff.

| Plugin | Plan-only tool | Worker-backed tool | Backend kind | Default boundary |
| --- | --- | --- | --- | --- |
| `restringer` | `restringer.deobfuscation.plan` | `restringer.deobfuscation.run` | external with builtin safe mode | Static JavaScript preprocessing only; no eval, Node/V8, browser, network, or source execution. |
| `jsimplifier` | `jsimplifier.pipeline.plan` | `jsimplifier.pipeline.run` | external with builtin safe mode | Static pass orchestration only; no JavaScript runtime, LLM call, or network. |
| `jsir-cascade` | `jsir.cascade.plan` | `jsir.cascade.normalize` | external with builtin safe mode | Static IR normalization only; no browser automation, Node/V8, or external deobfuscator by default. |
| `jsvmp-analysis` | `jsvmp.bytecode.plan` | `jsvmp.bytecode.recover` | external with builtin safe mode | Static bytecode/dispatcher recovery only; no JavaScript VM evaluation, Node/V8, browser, or network. |
| `gtirb` | `gtirb.ir.plan` | `gtirb.ir.generate` | external with builtin safe mode | Read-only IR artifact generation; no binary rewriting, loader mutation, or runtime execution. |
| `remill` | `remill.lift.plan` | `remill.lift.run` | external with builtin safe mode | Function/range-bounded lift handoff; no whole-program unbounded lifting, emulator, solver, debugger, or network. |
| `manifold` | `manifold.decompilation.plan` | `manifold.fact.extract` | external with builtin safe mode | Declarative fact extraction from local IR/CFG summaries; no decompiler/fact-engine process by default. |
| `qbdi` | `qbdi.instrumentation.plan` | `qbdi.trace.run` | delegated-runtime | Requires `approved=true`, isolation, and runtime handoff; the local Analyzer never starts QBDI directly. |
| `culifter` | `culifter.gpu.plan` | `culifter.gpu.artifact.inventory` | builtin safe inventory | No-GPU artifact inventory by default; no GPU driver, profiler, emulator, lifter, or sample execution. |
| `radare2` | `radare2.pipeline.plan` | `radare2.pipeline.run` | external with builtin safe mode | Read-only function, string, section, and xref summaries; external mode requires `RADARE2_PATH` and a bounded allowlist. |
| `wabt` | `wabt.toolchain.plan` | `wabt.toolchain.run` | external with builtin safe mode | Read-only WAT/objdump/validation planning; no WASM instantiation, WASI grant, or runtime execution. |
| `lief` | `lief.binary.plan` | `lief.binary.inspect` | external with builtin safe mode | Read-only binary inspection only; no mutation, signing changes, patching, or binary rewrite path. |
| `miasm` | `miasm.ir.plan` | `miasm.ir.lift` | external with builtin safe mode | Bounded static IR lifting only; license-gated external mode requires `MIASM_PYTHON`. |
| `triton` | `triton.symbolic.plan` | `triton.symbolic.slice` | external with builtin safe mode | Bounded symbolic slice summaries only; no emulator, solver run, debugger attach, or live execution. |
| `external-re-bridge` | Sidecar readiness metadata | `external_re.bridge.sync` | external/BYO sidecar contract with builtin safe mode | Normalizes provided local sidecar artifact manifests only; no sidecar startup or remote endpoint access. |

These tools are visible through `plugin.list`, `tools.discover`, `tool.help`, `tool.readiness`, and the plugin aspect matrix. `tool.readiness` returns `worker_backend_readiness` and preserves `does_not_start_backend: true`.

## Backend Auto-Install Tiers

Docker backend installation is an enforceable plugin contract. A plugin that declares a
`dockerFeature` must also declare a real install route or an explicit non-default policy through
`dockerInstallRoute` and `dockerInstallProfile`. The generator reports every route during
`--dry-run`; release tests fail if a backend route is implicitly `missing`.

Install routes:

- `installed`: installed by apt, a Docker fragment, a copied in-repo wrapper, or an existing base-image dependency.
- `profile-gated`: installed only when `--backend-profile` includes the declared profile.
- `validation-only`: planner/readiness metadata only; another plugin owns the executable backend.
- `byo`: bring your own pinned backend path through an env var or mounted directory.
- `sidecar`: use an intentionally supplied sidecar service or container image.

Backend profiles:

| Tier | Default behavior | Current examples |
| --- | --- | --- |
| `default` | Installed in normal analyzer images when static and low risk. | `restringer`, `jsimplifier`, `manifold`, `wabt`, LIEF validation |
| `optional` | Enabled with `--backend-profile=optional` or broader profiles. | `jsir-cascade`, `jsvmp-analysis`, `gtirb`, `radare2`, `triton` |
| `license-gated` | Excluded unless explicitly using `research` or `all`. | `miasm`, IDA/Binary Ninja sidecar profiles through `external-re-bridge` |
| `heavy` | Not silently installed; currently BYO/sidecar unless a future pinned fragment is added. | `remill`, `revng` |
| `runtime` | Delegated runtime or BYO only; analyzer does not start instrumentation. | `qbdi` |
| `gpu` | BYO only; no GPU driver load from discovery/readiness/test paths. | `culifter` |

Useful checks:

```bash
node scripts/generate-docker.mjs --dry-run
node scripts/generate-docker.mjs --dry-run --backend-profile=optional
node scripts/generate-docker.mjs --all-profiles --dry-run
```

## Plugin Matrix

The current plugin matrix is organized by `formats`, `platforms`, `execution`, `runtimes`, `safety`, `capabilities`, and `evidence` aspects. `plugin.list`, `tools.discover`, `tool.help`, `tool.readiness`, and `sample.profile.get` expose these fields so clients can route from a file type to the right static inventory, dynamic plan, or runtime-gated tool.

| Coverage | Static plugins | Dynamic or runtime-plan plugins | Safety boundary |
| --- | --- | --- | --- |
| Windows PE, DLL, SYS, MSI/MSIX/APPX/CAB/PDB, COM/RPC/ALPC/ETW/WMI/TypeLib/IDL | `pe-analysis`, `pe-signature`, `binary-hardening`, `rust-binary`, `kernel-driver-surface`, `syscall-abi-surface`, `windows-interface-surface`, `compiler-codegen`, `windows-installer`, `windows-debug-symbols`, `dotnet-managed`, `cpp-abi-layout`, `retdec`, `rizin`, `ghidra` | `windows-runtime`, `debug-session`, `wine`, `speakeasy`, `behavior-first`, `frida` | Static inventory is passive. Binary hardening inventory never loads PE files, invokes the Windows loader, runs exploit checks, starts debuggers, calls external checksec-style tools, or mutates samples. Rust binary inventory never loads PE files, invokes rustc/cargo, calls external demanglers, fetches source/symbols, or executes samples. Driver surface inventory never loads `.sys`, opens device objects, sends IOCTLs, starts a kernel debugger, or mutates samples. Syscall ABI inventory never invokes syscalls, traces, debugs, or emulates direct syscall stubs. Windows interface inventory never activates COM, calls RPC, connects ALPC/named pipes, queries WMI, starts services, registers ETW, or contacts interfaces. Compiler codegen fingerprinting never executes samples, loads native binaries, invokes compilers/linkers, contacts symbol/source servers, or uses external tools. Dynamic tools require opt-in, isolation, and runtime readiness. |
| UEFI firmware, PE/TE modules, firmware volumes, capsules, NVRAM/SMM | `uefi-smm-surface`, `firmware`, `pe-analysis`, `strings`, `vuln-scanner`, `reporting` | Runtime firmware boot/emulation is not enabled by default | No firmware boot, SMI trigger, SMM execution, EFI variable write, NVRAM mutation, capsule apply, SPI flash/MMIO/MSR access, firmware tooling process, emulation, network, or mutation by default. |
| Linux ELF, SO, core, modules, packages, eBPF, BTF, DWARF/CTF | `linux-binary`, `linux-package`, `binary-hardening`, `rust-binary`, `kernel-driver-surface`, `syscall-abi-surface`, `compiler-codegen`, `elf-macho`, `native-object`, `native-debug-types`, `cpp-abi-layout`, `container-analysis`, `btf`, `ebpf-bytecode` | `linux-runtime`, `qiling`, `debug-session`, `behavior-first` | No ELF execution, loader invocation, exploit testing, ptrace, strace, ltrace, kernel module loading, package install, eBPF load/attach, BTF verifier submission, rustc/cargo invocation, compiler/linker invocation, DWARF/CTF external dumpers, Rust/C++ external demanglers, symbol-server download, source fetch, IOCTL probing, syscall triggering, kernel probing, external hardening tools, or eBPF collection by default. |
| Confidential computing, TEE enclaves, SGX/OP-TEE/TDX/SEV-SNP/RISC-V enclave evidence | `tee-enclave`, `native-object`, `native-debug-types`, `compiler-codegen`, `elf-macho`, `linux-binary`, `firmware`, `strings`, `sbom`, `reporting` | Runtime enclave loading, quote generation, TEE driver calls, VM attestation, or emulation are not enabled by default | Static inventory reads bounded bytes only. It never creates or enters enclaves, requests quotes, verifies live attestation, opens `/dev/sgx_enclave`, `/dev/tdx-guest`, `/dev/sev-guest`, starts `tee-supplicant`, derives keys, starts a debugger/emulator, contacts collateral services, mutates samples, or uses the network. |
| Syscall ABI, direct syscall stubs, raw shellcode, Mach traps, SVC/ecall | `syscall-abi-surface`, `strings`, `pe-analysis`, `linux-binary`, `elf-macho`, `native-object`, `code-analysis`, `vuln-scanner`, `reporting` | `windows-runtime`, `linux-runtime`, `macos-runtime`, `debug-session` as opt-in planning only | Static inventory reads bounded bytes only. It never executes samples, invokes syscall/sysenter/int/SVC/ecall, attaches ptrace/strace/ltrace/debuggers/Frida, starts emulation, opens devices, loads drivers, invokes external tools, mutates files, or uses the network. |
| macOS Mach-O, app bundles, frameworks, DMG, PKG, dSYM | `apple-container`, `apple-signing`, `apple-objc-swift`, `binary-hardening`, `rust-binary`, `compiler-codegen`, `elf-macho`, `native-object`, `native-debug-types`, `cpp-abi-layout` | `macos-runtime`, `debug-session`, `frida`, `behavior-first` | No DMG mount, app launch, LLDB attach, DTrace, fs_usage capture, Objective-C runtime attach, Swift demangle process, rustc/cargo invocation, Rust/C++ external demangler, compiler/linker invocation, DWARF external dumpers, source fetch, external hardening tools, or external Apple tooling by default. |
| iOS IPA, Mach-O, provisioning, entitlements | `apple-container`, `apple-signing`, `apple-objc-swift`, `elf-macho` | `ios-runtime`, `frida`, `debug-session` | No IPA install, device connection, simulator start, Frida attach, LLDB attach, class-dump, swift-demangle, or app launch by default. |
| Android APK, AAB, APKS, XAPK, DEX/OAT/VDEX, AAR | `android-package`, `android`, `apk-smali`, `jvm`, `linux-binary` | `android-runtime`, `frida`, `behavior-first` | No emulator start, ADB install, APK launch, frida-server deployment, or device connection by default. |
| JVM, .NET, Unity, script bytecode | `jvm`, `dotnet-managed`, `dotnet-decompile`, `unity-managed`, `bytecode`, `strings` | `managed-sandbox`, `runtime-deobfuscate`, `behavior-first` | Runtime work is opt-in and delegated; metadata and bytecode inventory stay passive. |
| AI/ML model artifacts, checkpoints, tensor containers | `ml-model`, `container-analysis`, `metadata`, `strings`, `yara` | Runtime/model loading is not enabled by default | No `pickle.load`, `torch.load`, `numpy.load(... allow_pickle=True)`, ONNX Runtime, TensorFlow/TFLite delegate, PyTorch framework import, model inference, archive extraction, network/model hub download, or mutation by default. |
| GPU shader IR, WebGPU/Vulkan/DirectX/Metal shader artifacts | `shader-ir`, `cuda-binary`, `llvm-bitcode`, `strings`, `metadata` | `culifter` remains plan-only unless explicitly activated | No `spirv-val`, `spirv-dis`, `dxc`, `fxc`, `glslangValidator`, `spirv-cross`, `tint`, `naga`, `metal`, `metallib`, GPU driver, shader compilation, validation, disassembly, pipeline creation, sample execution, mutation, or network by default. |
| JavaScript, Node/browser bundles, source maps, JSVMP-like obfuscation | `javascript-deobfuscation`, `jsvmp-analysis`, `jsimplifier`, `jsir-cascade`, `restringer`, `strings`, `yara`, `yara-x`, `bytecode` | Worker-backed REstringer, JSIMPLIFIER, and JSIR/CASCADE tools remain explicit backend surfaces with builtin safe mode | No JavaScript evaluation, Node/V8 start, browser automation, dynamic trace, LLM call, network lookup, or external deobfuscator invocation by default. |
| Advanced native lifting, symbolic execution, IR, debug/type metadata, exploit mitigation posture, GPU artifacts, and backend comparison workflows | `binary-hardening`, `rust-binary`, `revng`, `triton`, `miasm`, `lief`, `radare2`, `remill`, `gtirb`, `manifold`, `compiler-codegen`, `native-debug-types`, `cpp-abi-layout`, `llvm-bitcode`, `shader-ir`, `cuda-binary`, `culifter`, `vm-analysis`, `rizin`, `ghidra`, `retdec` | Worker-backed GTIRB, Remill, Manifold, QBDI, and CuLifter surfaces are bounded and readiness-gated; runtime/emulation remains opt-in | Discovery/readiness/help/list paths emit backend plans and readiness metadata only; no LLVM toolchain, compiler/linker invocation, rustc/cargo invocation, debug dumper, external demangler, hardening checker process, heavy backend process, solver, emulator, fact engine, binary mutation, shader compiler, CUDA driver, GPU access, or sample execution starts during discovery. |
| Firmware, containers, archives, native objects | `firmware`, `uefi-smm-surface`, `container-analysis`, `native-object`, `linux-package`, `windows-installer` | `qiling`, `linux-runtime`, `wasm-runtime` when applicable | No mount, extraction-to-execute path, package install, module insertion, firmware boot, SMI trigger, capsule apply, flash access, or payload launch by default. |
| WASM/WASI and Component Model | `wasm`, `wasm-component`, `wabt`, `strings`, `sbom` | `wasm-runtime` | No module/component instantiation, WABT/wasm-tools process, wasmtime start, filesystem preopen, package fetch, or network grant by default. |
| Network, host, memory, reports | `pcap-analysis`, `host-correlation`, `memory-forensics`, `visualization`, `reporting` | `behavior-first`, `dynamic.behavior.diff`, `analysis.evidence.graph` | Correlation tools operate on existing artifacts and do not start live collection. |

## Aspect Authoring

Every new plugin should declare plugin-level aspects and tool-level metadata when a tool has a narrower scope:

- `formats`: file and container tags such as `pe`, `elf`, `macho`, `apk`, `ipa`, `wasm`, `deb`, `msi`, `firmware`, `syscall`, `direct-syscall`, `raw-shellcode`, `ntdll-stub`, `windows-interface`, `com`, `rpc`, `alpc`, `etw`, `wmi`, `named-pipe`, `service-control`, `typelib`, `idl`.
- `platforms`: `windows`, `linux`, `macos`, `ios`, `android`, `wasm`, `jvm`, `dotnet`, `embedded`, or `cross-platform`.
- `execution`: `static`, `dynamic`, `emulation`, `decompilation`, `triage`, or `correlation`.
- `runtimes`: runtime backends such as `windows-sandbox`, `hyperv`, `wine`, `speakeasy`, `qiling`, `gdb`, `lldb`, `dtrace`, `adb`, `android-emulator`, `frida`, `idevice-tools`, `wasmtime`.
- `safety`: `passive`, `opt_in_dynamic`, `requires_isolation`, `no_live_sample_by_default`, `no_network_by_default`, `no_auto_mount`, `no_installer_execution`, `no_syscall`, `no_ptrace`, `no_debugger`.
- `evidence`: `structure`, `imports`, `exports`, `strings`, `signatures`, `timeline`, `behavior`, `process`, `filesystem`, `registry`, `network`, `memory`, `method-calls`, `syscalls`, `abi`, `bytecode`, `evasion`, `risk`, `provenance`, `workflow`, `analysis-memory`, `correlation-graph`, `provenance-graph`.

## Dynamic Policy

Dynamic plugins are passive by default. A dynamic plugin or tool should declare `runtimePolicy` with:

The dynamic policy contract is additive metadata: it is reported by discovery and readiness tools before any runtime backend is contacted.

- `passiveByDefault: true`
- `requiresUserOptIn: true`
- `requiresIsolation: true`
- `allowedBackends`: explicit backend list
- `networkPolicy: "disabled"` unless a tool is explicitly designed for record-only or restricted networking
- `notes`: backend and confidence caveats

`tool.readiness` reports `runtime_policy_status`, `opt_in_required`, `policy_denied`, `isolation_missing`, and `backend_missing` without executing the target tool. Plan-only dynamic tools such as `windows.runtime.plan`, `linux.runtime.plan`, `macos.runtime.plan`, `ios.runtime.plan`, `android.runtime.plan`, and `wasm.runtime.plan` are local planning tools: they generate runtime guidance and command templates, but they do not start backends.

## Runtime Management Tools

| Tool | Purpose |
| --- | --- |
| `plugin.list` | List known plugins, status, registered tools, dependencies, and optional config schema |
| `plugin.enable` | Hot-load a known plugin when supported |
| `plugin.disable` | Unload a plugin when supported |
| `workflow.search` | Search/rank relevant workflow profiles and specialist tools for a sample, finding, or goal |
| `workflow.run` | Execute whitelisted gateway actions: upload, start, status, promote |
| `artifact.read` | Read full persisted artifact payloads |
| `tools.discover` | Low-level compatibility portal for progressive surface inspection/activation |
| `tool.readiness` | Explain prerequisites, runtime contract, policy requirements, and backend availability for a tool |

## Loading Configuration

`PLUGINS` controls the startup plugin set.

```bash
PLUGINS=*                 # default: all built-ins
PLUGINS=pe-analysis,yara  # only selected plugin IDs
PLUGINS=-dynamic          # all except listed plugin IDs
```

Docker profile generation also uses plugin metadata. Regenerate Docker files after adding or removing plugin dependencies:

```bash
npm run build
npm run docker:generate:all
```

## Discovery And Lifecycle

Startup discovery:

1. Discover built-ins from `dist/plugins` in built packages or `src/plugins` in development.
2. Discover external compiled plugins under repository-level `plugins/`.
3. Apply `PLUGINS` filtering.
4. Sort by plugin dependency graph.
5. Validate plugin shape and dependencies.
6. Check system dependencies and plugin `check()` hooks when present.
7. Register plugin tools.
8. Record plugin status and tool ownership.
9. Register plugin introspection tools and diagnostics.

Runtime lifecycle hooks:

- `onBeforeToolCall`
- `onAfterToolCall`
- `onToolError`

The executor only fires plugin hooks for tools owned by that plugin.

## Recommended Plugin Shape

```ts
import { z } from 'zod'
import { definePlugin, defineTool, ok } from '@rikune/plugin-sdk'

const echoTool = defineTool({
  name: 'example.echo',
  description: 'Return a message from the example plugin',
  inputSchema: z.object({
    message: z.string(),
  }),
  handler: () => async (args) => ok({ message: args.message }),
})

export default definePlugin({
  id: 'example',
  name: 'Example Plugin',
  description: 'Small external plugin example',
  version: '1.0.0',
  executionDomain: 'static',
  surfaceRules: { tier: 3, category: 'example' },
  register(server) {
    server.registerTool(echoTool.definition, echoTool.handlerFactory({}))
    return ['example.echo']
  },
})
```

External plugins should compile to ESM JavaScript and be placed under `plugins/<id>/index.js` or as a direct `.js`/`.mjs` file under `plugins/`.

The repository also includes:

```bash
node scripts/create-plugin.js my-feature --name "My Feature"
```

## Manifest-Backed Plugins

Plugins can keep metadata in `plugin.json` and export handlers from `index.js`. Manifest validation is part of the SDK.

Minimal shape:

```json
{
  "id": "my-feature",
  "name": "My Feature",
  "version": "1.0.0",
  "description": "External feature plugin",
  "executionDomain": "static",
  "tools": [
    {
      "name": "my_feature.inspect",
      "description": "Inspect a sample"
    }
  ]
}
```

## Runtime Contracts

Dynamic or delegated tools can declare runtime contracts. Contracts describe execution mode, required capabilities, input/output artifacts, timeout, and backend needs. Analyzer-side `RuntimeClient` validates the contract before dispatching to Runtime Node.

Common execution modes:

- `plan_only`
- `safe_simulation`
- `emulation`
- `live_sandbox`
- `live_hyperv`
- `manual_runtime`

Live modes should require explicit policy approval and an isolated runtime backend.

## System Dependencies

Plugin `systemDeps` can describe binaries, Python modules, files, environment variables, Docker install snippets, and validation commands. These surface in:

- Docker generation;
- `plugin.list`;
- readiness checks;
- setup guidance;
- dashboard readiness.

## Troubleshooting

Plugin does not load:

1. Check `PLUGINS`.
2. Run `plugin.list` with config/status details.
3. Check system dependency messages.
4. Confirm the plugin exports a valid default plugin object.
5. Rebuild TypeScript if using built-in plugin changes.

Tool is missing:

1. Confirm the plugin loaded.
2. Check progressive surface behavior with `workflow.search`; use `tools.discover` only for low-level compatibility/debug inspection.
3. Use `tool.readiness`.
4. Check aliases if the client normalizes dotted names.

Runtime-delegated tool fails:

1. Check `dynamic.runtime.status`.
2. Check `/api/v1/ready`.
3. Confirm `RUNTIME_MODE`, Host Agent endpoint, and API keys.
4. Verify the Runtime Node advertises the required capability.
5. Confirm policy approval for live execution.
