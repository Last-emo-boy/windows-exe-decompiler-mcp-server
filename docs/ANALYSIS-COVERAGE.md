# Analysis Coverage Boundaries

Large or expensive samples do not always receive the same depth as a small sample, even when the high-level request sounds similar. The server now reports that boundary explicitly instead of forcing clients to infer it from warnings.

## Read These Fields First

- `coverage_level`
  - `quick`: first-pass profile only
  - `static_core`: static evidence plus bounded enrichment
  - `deep_static`: deep static stage completed
  - `reconstruction`: reconstruction/export boundary reached
  - `dynamic_verified`: dynamic-oriented verification boundary reached
- `completion_state`
  - `queued`: work has not completed yet
  - `bounded`: intentionally partial result
  - `degraded`: a deeper stage failed or fell back
  - `completed`: the workflow reached its intended boundary
  - `partial`: only a subset of the expected evidence was available
- `coverage_gaps`
  - Names the missing, skipped, queued, blocked, or degraded domains.
- `known_findings`
  - Strongest evidence-backed conclusions inside the current boundary.
- `suspected_findings`
  - Plausible but still heuristic conclusions.
- `unverified_areas`
  - Domains the workflow did not actually cover.
- `upgrade_paths`
  - Machine-readable next steps that close specific gaps.

## Why Large Samples May Look Partial

The server may intentionally hold a request at a bounded stage when:

- the sample falls into a `large` or `oversized` size tier
- the requested path would trigger disproportionate decompilation or validation cost
- the workflow is a quick-profile surface by design, such as `workflow.triage`
- a queued or degraded stage means the deeper evidence is not ready yet

This is not the same as silent failure. The boundary should appear in:

- `sample_size_tier`
- `analysis_budget_profile`
- `downgrade_reasons`
- `coverage_gaps`

## How To Deepen Safely

Use `upgrade_paths` instead of guessing.

Examples:

- Missing `ghidra_analysis` or `function_attribution`
  - Run `ghidra.analyze` or `analysis.context.link`
- Missing `reconstruction_export`
  - Run `workflow.reconstruct`
- Missing `summary_synthesis`
  - Run `workflow.summarize` through a later stage
- Missing `dynamic_behavior`
  - Start with `dynamic.dependencies` or `sandbox.execute`
  - Only move to `wine.run` when the execution boundary is explicitly approved

## Guidance For AI Clients

- Do not restate `suspected_findings` as confirmed behavior.
- Mention `unverified_areas` in analyst-facing summaries.
- If `completion_state` is `queued`, direct the user to `task.status` rather than pretending the result is complete.
- If `completion_state` is `bounded` or `degraded`, cite the relevant `upgrade_paths` before escalating to expensive workflows.
