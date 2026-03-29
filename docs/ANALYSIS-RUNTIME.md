# Analysis Runtime

## Primary Model

The server now treats persisted staged runs as the primary orchestration model.

```text
Sample
  -> Canonical Evidence
  -> Analysis Run
     -> Stage
        -> Job (only when queued work is required)
```

- `workflow.analyze.start` creates or reuses a persisted run and executes only the bounded `fast_profile` stage inline.
- `workflow.analyze.status` is the primary progress surface for clients and AI agents.
- `workflow.analyze.promote` queues deeper stages without rerunning already compatible work.
- `task.status` remains available, but it is a low-level job inspection surface rather than the main workflow status model.

Read these run-level fields before assuming work is complete:

- `recovery_state`
- `recoverable_stages`
- `evidence_state`
- `provenance_visibility`
- `execution_bucket`
- `cost_class`
- `worker_family`
- `budget_deferral_reason`
- `warm_reuse`
- `cold_start`
- `expected_rss_mb`
- `current_rss_mb`
- `peak_rss_mb`
- `memory_limit_mb`
- `control_plane_headroom_mb`
- `active_expected_rss_mb`
- `latency_ms`
- `interruption_cause`

## Stage Graph

```text
fast_profile
  -> enrich_static
  -> function_map
  -> reconstruct
  -> dynamic_plan
  -> dynamic_execute
  -> summarize
```

Default backend roles:

- `fast_profile`: PE leaf tools, preview strings, `Rizin`, `YARA`, `YARA-X`, `UPX`
- `enrich_static`: full strings, FLOSS, capability triage, PE structure, context linkage, crypto, Rust profile
- `function_map`: `Ghidra` as the deep attribution backend, with bounded `Rizin` corroboration
- `reconstruct`: reconstruct workflow plus targeted `RetDec` and `angr` artifacts
- `dynamic_plan`: readiness probes, breakpoint planning, `Qiling`, `PANDA`
- `dynamic_execute`: safe simulation first, approval-gated execution paths later
- `summarize`: persisted summary digests and report views only

## Worker Pools And Budget Lanes

The runtime now separates fast reuse from deep isolation:

- `static_python.preview` and `static_python.full` use compatibility-keyed pooled helpers
- `rizin.preview` uses a pooled preview helper path keyed by backend path/version and operation
- `ghidra.deep` remains isolated and scheduler-governed instead of warm pooled

Execution is admitted through explicit budget lanes:

- `preview-static`
- `enrich-static`
- `deep-attribution`
- `dynamic-plan`
- `dynamic-execute`
- `manual-execution`
- `artifact-only`

Status surfaces now tell you whether work:

- reused a warm compatible worker
- cold-started a fresh helper
- deferred because a cheaper preview lane was waiting
- deferred because a deep lane was saturated
- remained blocked because the backend is manual-only

## Canonical Evidence

High-cost reusable outputs are persisted as canonical evidence per sample.

Current evidence families include:

- `strings`
- `binary_role`
- `context_link`
- `backend_preview`
- `summary`

Common evidence states now surfaced to clients are:

- `fresh`
- `reused`
- `partial`
- `stale`
- `incompatible`
- `missing`
- `deferred`

Large-sample heavy evidence may now expose a `chunk_manifest` instead of one giant inline tree.
Treat the manifest plus persisted artifact refs as the continuation path for:

- `strings.extract(mode='full')`
- `analysis.context.link(mode='full')`
- `crypto.identify(mode='full')`

Compatibility is keyed by:

- sample identity
- evidence family
- backend/tool family
- execution mode
- normalized argument hash
- optional freshness marker

Reuse precedence is:

1. compatible run stage output
2. canonical evidence
3. persisted artifact selection
4. generic tool cache
5. recomputation

## Legacy Facades

These entrypoints still exist, but they no longer own orchestration:

- `workflow.triage`: compatibility facade over `fast_profile`
- `workflow.analyze.auto`: intent translator over `start/promote`
- `report.summarize`: persisted-state report view only
- `workflow.summarize`: staged summary digest workflow over persisted state
- `report.generate`: export-only archival/report packaging surface
- `graphviz.render`: renderer/export helper over existing graph artifacts

Clients should not treat facade output as proof that deeper stages already completed.
Always read:

- `coverage_level`
- `completion_state`
- `coverage_gaps`
- `upgrade_paths`

## Explanation Graph Surfaces

Graph outputs are explanation surfaces first and rendering formats second.

Surface roles:

- explanation artifact: persisted graph used by `workflow.summarize` and `report.summarize`
- local navigation aid: bounded graph used for focused reverse-engineering navigation such as `code.function.cfg`
- render/export helper: serializer or renderer over an existing graph, such as `graphviz.render`

Required explanation metadata now includes:

- `graph_type`
- `surface_role`
- `confidence_state`
- `semantic_summary`
- `provenance_refs`
- `omissions`
- `recommended_next_tools`

Interpret confidence states narrowly:

- `observed`: backed directly by concrete extracted structure or trace evidence
- `correlated`: assembled from multiple persisted evidence sources or bounded heuristics
- `inferred`: plausible explanation layer that still needs targeted confirmation

Mermaid, DOT, SVG, and PNG should be treated as output encodings over the same graph semantics, not as separate analysis goals.

## Recommended Client Pattern

### Quick first pass

```text
workflow.analyze.start(sample_id, goal='triage')
  -> inspect fast_profile result
  -> decide whether to promote
```

### Deeper static / reverse engineering

```text
workflow.analyze.start(sample_id, goal='reverse')
workflow.analyze.promote(run_id, through_stage='function_map')
workflow.analyze.status(run_id)
```

### Reporting

```text
workflow.summarize(sample_id, through_stage='final')
report.summarize(sample_id)
```

Both summary surfaces read persisted state; they do not silently restart heavy prerequisite analysis.

They also expose:

- `persisted_state_visibility` to show which run stages were reused
- explicit deferred requirements instead of quietly backfilling missing prerequisites

## When To Use `task.status`

Use `task.status` only when you need raw queued job state:

- queue diagnostics
- low-level progress debugging
- cancellation follow-up
- investigating a failed stage job

For normal orchestration, prefer `workflow.analyze.status`.

## Large-Binary Practice

When sample size grows, prefer:

- `strings.extract(mode='preview')` first
- `binary.role.profile(mode='fast')` first
- `analysis.context.link(mode='preview')` first
- `crypto.identify(mode='preview')` first

Promote or queue full variants only when the preview result justifies the extra cost.

### Memory Guardrails

The scheduler now reserves explicit control-plane headroom before admitting heavy work.

Useful environment knobs:

- `ANALYSIS_RUNTIME_MEMORY_LIMIT_MB`
- `ANALYSIS_RUNTIME_CONTROL_PLANE_HEADROOM_MB`

If a stage is deferred because of memory, status surfaces return:

- `budget_deferral_reason` with `memory_headroom_guard`
- per-stage memory telemetry fields
- recoverable guidance telling the client to wait or promote later instead of retrying immediately

### Practical Large-Sample Order

```text
workflow.analyze.start(goal='triage')
workflow.analyze.status(run_id)
workflow.analyze.promote(run_id, through_stage='enrich_static')
workflow.analyze.status(run_id)
workflow.analyze.promote(run_id, through_stage='function_map')
workflow.summarize(sample_id, through_stage='final')
```

Keep `report.summarize` in `detail_level='compact'` for large or oversized samples.

## Packed Sample And Debug Session Lifecycle

Packed samples now flow through an explicit unpack/debug branch instead of being treated as ordinary deep-static inputs.

Primary fields to read on `workflow.analyze.start`, `workflow.analyze.status`, `workflow.summarize`, and `report.summarize`:

- `packed_state`
- `unpack_state`
- `unpack_confidence`
- `unpack_plan`
- `debug_state`
- `debug_session`
- `diff_digests` / `unpack_debug_diffs`

Interpret them narrowly:

- `packed_state=not_packed`: continue through ordinary staged analysis
- `packed_state=suspected_packed|confirmed_packed`: unpack/debug-aware planning is still relevant
- `unpack_state=unpack_planned|approval_gated|rebuild_required|unpack_failed_recoverable`: do not treat the original sample as already ready for deep reconstruction
- `debug_state=planned|armed`: a session exists, but capture has not produced bounded runtime evidence yet
- `debug_state=captured|correlated`: persisted dynamic evidence is available and should be summarized via diff digests first

### Recommended Packed-Sample Order

```text
workflow.analyze.start(sample_id, goal='dynamic' or 'reverse')
workflow.analyze.status(run_id)
workflow.analyze.promote(run_id, stages=['dynamic_plan'])
workflow.analyze.status(run_id)
workflow.analyze.promote(run_id, stages=['dynamic_execute'])
workflow.summarize(sample_id)
```

Use this order when:

- packer detection is strong
- `upx.inspect` or packer attribution suggests an unpack path
- the current question is blocked on unpacked imports, strings, OEP, or bounded runtime capture

### Safe And Approval-Gated Boundaries

- `upx.inspect(test|list)` is a safe preview probe
- `upx.inspect(decompress)` is a bounded transform path when the run already allows transformations
- `breakpoint.smart` and `trace.condition` are planning-only and should be treated as debug-session preparation
- `frida.trace.capture` and `wine.run(debug|run)` remain manual-only execution surfaces

### Diff Digests

The runtime now prefers bounded before/after digests over raw trees:

- `packed_vs_unpacked`
- `pre_vs_post_dynamic`
- `pre_vs_post_trace`

These digests are the AI-facing summary inputs. Raw dump, unpack, or trace artifacts should be opened only when the digest is insufficient.
