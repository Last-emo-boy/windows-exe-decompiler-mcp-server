import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const { WorkspaceManager } = await import('../../dist/workspace-manager.js')
const { DatabaseManager } = await import('../../dist/database.js')
const { CacheManager } = await import('../../dist/cache-manager.js')
const { createWorkflowSummarizeHandler } = await import('../../dist/workflows/summarize.js')

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'summary-coverage-boundaries-'))
const workspaceRoot = path.join(tempRoot, 'workspaces')
const dbPath = path.join(tempRoot, 'test.db')
const cacheRoot = path.join(tempRoot, 'cache')

const workspaceManager = new WorkspaceManager(workspaceRoot)
const database = new DatabaseManager(dbPath)
const cacheManager = new CacheManager(cacheRoot, database)

try {
  const sampleId = `sha256:${'e'.repeat(64)}`
  database.insertSample({
    id: sampleId,
    sha256: 'e'.repeat(64),
    md5: 'e'.repeat(32),
    size: 2 * 1024 * 1024,
    file_type: 'PE32+',
    created_at: new Date().toISOString(),
    source: 'integration-test',
  })

  database.insertFunction({
    sample_id: sampleId,
    address: '0x401000',
    name: 'entry_main',
    size: 64,
    score: 0.91,
    tags: JSON.stringify(['entry']),
    summary: 'Entry point summary.',
    caller_count: 0,
    callee_count: 1,
    is_entry_point: 1,
    is_exported: 0,
    callees: JSON.stringify(['sub_401050']),
  })

  const handler = createWorkflowSummarizeHandler(
    workspaceManager,
    database,
    cacheManager,
    undefined,
    {
      reportSummarizeHandler: async () => ({
        ok: true,
        data: {
          detail_level: 'compact',
          tool_surface_role: 'compatibility',
          preferred_primary_tools: ['workflow.summarize'],
          coverage_level: 'static_core',
          completion_state: 'bounded',
          sample_size_tier: 'medium',
          analysis_budget_profile: 'balanced',
          downgrade_reasons: ['Stopped before final synthesis.'],
          coverage_gaps: [
            {
              domain: 'summary_synthesis',
              status: 'missing',
              reason: 'Final synthesis has not run yet.',
            },
          ],
          confidence_by_domain: {
            imports: 0.81,
            strings: 0.77,
          },
          known_findings: ['Observed process-manipulation imports.'],
          suspected_findings: ['Potential operator utility pattern.'],
          unverified_areas: ['Runtime behavior remains unverified.'],
          upgrade_paths: [
            {
              tool: 'workflow.summarize',
              purpose: 'Continue to final synthesis.',
              closes_gaps: ['summary_synthesis'],
              expected_coverage_gain: 'Adds final known/suspected/unverified synthesis.',
              cost_tier: 'medium',
              availability: 'ready',
              prerequisites: [],
              blockers: [],
              requires_approval: false,
            },
          ],
          summary: 'Compact staged report summary.',
          confidence: 0.78,
          threat_level: 'suspicious',
          iocs: {
            suspicious_imports: ['OpenProcess'],
            suspicious_strings: ['--pid 42'],
            yara_matches: ['rule_process_tooling'],
          },
          evidence: ['Observed suspicious process APIs.'],
          recommendation: 'Escalate to final synthesis only if a broader narrative is needed.',
          binary_profile_summary: {
            binary_role: 'dll',
            role_confidence: 0.91,
            packed: false,
            packing_confidence: 0.1,
            export_count: 1,
            notable_exports: ['DllRegisterServer'],
            dispatch_model: 'exports',
            host_hints: ['Plugin host extension'],
            analysis_priorities: ['trace_export_surface_first'],
            summary: 'Binary role profile suggests dll.',
          },
          rust_profile_summary: {
            suspected_rust: false,
            confidence: 0.11,
            primary_runtime: null,
            top_crates: [],
            recovered_symbol_count: 0,
            recovered_function_count: 0,
            analysis_priorities: [],
            summary: 'Rust-focused analysis did not strongly confirm Rust.',
          },
          static_capability_summary: {
            status: 'ready',
            capability_count: 2,
            top_groups: ['network'],
            top_capabilities: ['send HTTP request'],
            summary: 'Capability triage matched network behavior.',
          },
          pe_structure_summary: {
            status: 'ready',
            section_count: 4,
            import_function_count: 88,
            export_count: 1,
            resource_count: 1,
            overlay_present: false,
            parser_preference: 'lief',
            summary: 'PE structure looks normal.',
          },
          compiler_packer_summary: {
            status: 'ready',
            compiler_names: ['MSVC'],
            packer_names: [],
            protector_names: [],
            likely_primary_file_type: 'PE32+',
            summary: 'Toolchain attribution suggests MSVC.',
          },
          semantic_explanation_summary: {
            count: 0,
            top_behaviors: [],
            top_summaries: [],
            summary: 'No semantic explanations yet.',
          },
          artifact_refs: {
            supporting: [],
            explanation_graphs: [
              {
                id: 'artifact-runtime-graph',
                type: 'analysis_explanation_graph',
                path: 'reports/explanation/runtime_graph.json',
                sha256: 'a'.repeat(64),
                mime: 'application/json',
              },
            ],
          },
          explanation_graphs: [
            {
              graph_type: 'runtime_stage',
              surface_role: 'runtime_stage_view',
              title: 'Staged Analysis Runtime View',
              semantic_summary: 'Bounded staged-runtime explanation graph.',
              confidence_state: 'observed',
              confidence_states_present: ['observed', 'inferred'],
              node_count: 4,
              edge_count: 3,
              bounded: true,
              recommended_next_tools: ['workflow.analyze.status', 'workflow.analyze.promote'],
              artifact_ref: {
                id: 'artifact-runtime-graph',
                type: 'analysis_explanation_graph',
                path: 'reports/explanation/runtime_graph.json',
                sha256: 'a'.repeat(64),
                mime: 'application/json',
              },
            },
          ],
        },
      }),
    }
  )

  const result = await handler({
    sample_id: sampleId,
    through_stage: 'final',
    synthesis_mode: 'deterministic',
  })

  assert.equal(result.ok, true)
  assert.equal(result.data.tool_surface_role, 'primary')
  assert.equal(result.data.coverage_level, 'deep_static')
  assert.ok(Array.isArray(result.data.known_findings))
  assert.ok(Array.isArray(result.data.suspected_findings))
  assert.ok(Array.isArray(result.data.unverified_areas))
  assert.ok(result.data.unverified_areas.length > 0)
  assert.ok(result.data.upgrade_paths.length > 0)
  assert.equal(result.data.stages.final.coverage_level, 'deep_static')
  assert.ok(result.data.stages.final.known_findings.length > 0)
  assert.equal(result.data.explanation_graphs[0].graph_type, 'runtime_stage')
  assert.equal(result.data.explanation_artifacts[0].type, 'analysis_explanation_graph')

  console.log('summary coverage boundaries integration checks passed')
} finally {
  database.close()
  await fs.rm(tempRoot, { recursive: true, force: true })
}
