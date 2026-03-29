# Async Job Pattern

This document now describes the **supporting job layer** under the staged analysis runtime.

If you are choosing a primary client flow, start with [ANALYSIS-RUNTIME.md](./ANALYSIS-RUNTIME.md).  
The authoritative orchestration pattern is:

- `workflow.analyze.start`
- `workflow.analyze.status`
- `workflow.analyze.promote`

`job_id` and `task.status` still matter, but they are no longer the main workflow contract.

## Where Jobs Fit

```text
workflow.analyze.start
  -> persisted run
  -> completed fast_profile inline

workflow.analyze.promote
  -> queued stage jobs
  -> task.status can inspect those jobs

workflow.analyze.status
  -> aggregates run + stage + deferred job state
```

Use `task.status` when you need:

- raw queue state
- low-level progress debugging
- failure diagnostics on a specific queued stage
- cancellation follow-up
- scheduler admission details such as `execution_bucket`, `cost_class`, and `budget_deferral_reason`
- pooled-helper telemetry such as `worker_family`, `warm_reuse`, and `cold_start`

Do not use `task.status` as the first or only status surface for normal staged analysis.

## Typical Pattern

### Preferred

```text
workflow.analyze.start(sample_id, goal='triage')
workflow.analyze.promote(run_id, through_stage='function_map')
workflow.analyze.status(run_id)
```

### Supporting raw-job inspection

```text
task.status(job_id)
```

## Tools That Commonly Queue Work

- `workflow.analyze.promote` for deeper stages
- `ghidra.analyze`
- `workflow.deep_static`
- `workflow.reconstruct`
- `workflow.semantic_name_review`
- `workflow.function_explanation_review`
- `workflow.module_reconstruction_review`

Some heavy leaf tools may also queue or return bounded preview-only results depending on mode and sample size:

- `strings.extract(mode='full')`
- `binary.role.profile(mode='full')`
- `analysis.context.link(mode='full')`
- `strings.floss.decode`

## Polling Guidance

When a stage is queued:

1. Prefer `workflow.analyze.status(run_id)` first.
2. Only use `task.status(job_id)` if you need raw job details.
3. Respect returned `polling_guidance` or equivalent wait recommendations instead of tight polling loops.

## Restart Behavior

Jobs remain execution records. Runs and canonical evidence remain the reusable analytical truth.

That means after restart:

- `workflow.analyze.status` should still be your first lookup
- completed compatible evidence and completed stages can still be reused
- interrupted or orphaned queued work should surface as `recovery_state != none`
- `recoverable_stages` tells you exactly which stages need re-promotion
- `task.status` helps explain what happened to specific queued work

## Migration Note

Older docs treated `job_id` as the primary async contract. That is now superseded by the run-level staged runtime.  
Use [MIGRATION-ASYNC.md](./MIGRATION-ASYNC.md) if your client still assumes every long-running workflow should be driven purely by `job_id`.
