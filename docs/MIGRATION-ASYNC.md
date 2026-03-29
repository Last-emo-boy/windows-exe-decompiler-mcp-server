# Migration To The Staged Runtime

Older clients often assumed:

- long-running workflow -> immediate `job_id`
- poll `task.status(job_id)` until done

That still works for low-level execution details, but it is no longer the recommended top-level contract.

## New Primary Contract

Move clients to:

1. `workflow.analyze.start`
2. `workflow.analyze.status`
3. `workflow.analyze.promote`

This gives clients:

- persisted run reuse
- stage-aware progress
- canonical evidence reuse
- explicit recovery and re-promotion semantics after worker interruption
- explicit upgrade paths
- fewer repeated calls on the same sample

## Before

```text
ghidra.analyze(sample_id)
  -> job_id
task.status(job_id)
```

## After

```text
workflow.analyze.start(sample_id, goal='reverse')
  -> run_id
workflow.analyze.promote(run_id, through_stage='function_map')
workflow.analyze.status(run_id)
```

## What Changes For Clients

### Prefer `run_id` over `job_id`

Use `run_id` as the main handle for:

- progress inspection
- deeper promotion
- later summary/report reuse

### Treat `job_id` as supporting detail

Use `job_id` only when you need:

- queue debugging
- low-level failure details
- cancellation follow-up

### Expect bounded facades

Legacy facades now return bounded or persisted-state views:

- `workflow.triage`
- `workflow.analyze.auto`
- `report.summarize`

Do not assume these facades silently completed deep analysis.

## Client Checklist

- Detect and preserve `run_id`
- Prefer `workflow.analyze.status(run_id)` over `task.status(job_id)`
- Use `workflow.analyze.promote` instead of rerunning heavy workflows
- Read `recovery_state`, `recoverable_stages`, `evidence_state`, and `provenance_visibility`
- Read `execution_bucket`, `cost_class`, `worker_family`, `budget_deferral_reason`, `warm_reuse`, and `cold_start` when a stage is queued or reused
- Read `coverage_level`, `completion_state`, `coverage_gaps`, and `upgrade_paths`
- Treat `task.status` as low-level instrumentation, not the main progress API

## Backward Compatibility

Direct leaf tools and legacy workflows still exist for expert usage and compatibility.  
The migration is about choosing a single primary orchestration model, not removing expert control.

See [ANALYSIS-RUNTIME.md](./ANALYSIS-RUNTIME.md) for the current runtime model.
