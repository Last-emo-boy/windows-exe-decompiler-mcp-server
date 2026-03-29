import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createWorkflowSummarizeHandler } from '../../src/workflows/summarize.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'

describe('workflow.summarize', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-workflow-summarize')
    testDbPath = path.join(process.cwd(), 'test-workflow-summarize.db')
    testCachePath = path.join(process.cwd(), 'test-cache-workflow-summarize')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
    cacheManager = new CacheManager(testCachePath, database)
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore
    }
    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }
  })

  function createCompactReportResult(sampleId: string): WorkerResult {
    return {
      ok: true,
      data: {
        detail_level: 'compact',
        tool_surface_role: 'compatibility',
        preferred_primary_tools: ['workflow.summarize'],
        coverage_level: 'static_core',
        completion_state: 'bounded',
        sample_size_tier: 'medium',
        analysis_budget_profile: 'balanced',
        downgrade_reasons: ['Static summary stops before final synthesis.'],
        coverage_gaps: [
          {
            domain: 'summary_synthesis',
            status: 'missing',
            reason: 'Final synthesis has not run yet.',
          },
        ],
        confidence_by_domain: {
          imports: 0.82,
          strings: 0.76,
          capabilities: 0.79,
        },
        known_findings: ['Observed suspicious process APIs.'],
        suspected_findings: ['Potential operator tooling behavior.'],
        unverified_areas: ['Runtime behavior is still unverified.'],
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
        summary: 'Compact triage summary for staged reporting.',
        confidence: 0.77,
        threat_level: 'suspicious',
        iocs: {
          suspicious_imports: ['OpenProcess', 'WriteProcessMemory'],
          suspicious_strings: ['akasha --pid 42'],
          yara_matches: ['rule_process_tooling'],
        },
        evidence: ['Process APIs are present.', 'Runtime hints suggest process injection staging.'],
        recommendation: 'Inspect staged digests before requesting a final narrative.',
        binary_profile_summary: {
          binary_role: 'dll',
          role_confidence: 0.91,
          packed: false,
          packing_confidence: 0.1,
          export_count: 2,
          notable_exports: ['DllRegisterServer'],
          dispatch_model: 'com_registration_and_class_factory',
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
          capability_count: 3,
          top_groups: ['network', 'execution'],
          top_capabilities: ['send HTTP request', 'execute command'],
          summary: 'Capability triage matched 3 finding(s) across network, execution.',
        },
        pe_structure_summary: {
          status: 'ready',
          section_count: 6,
          import_function_count: 148,
          export_count: 0,
          resource_count: 2,
          overlay_present: false,
          parser_preference: 'lief',
          summary: 'PE structure recovered 6 section(s).',
        },
        compiler_packer_summary: {
          status: 'ready',
          compiler_names: ['MSVC'],
          packer_names: ['UPX'],
          protector_names: [],
          likely_primary_file_type: 'PE32 executable',
          summary: 'Toolchain attribution suggests packer/protector signals (UPX).',
        },
        semantic_explanation_summary: {
          count: 1,
          top_behaviors: ['dispatch_process_control'],
          top_summaries: ['Dispatches process-control operations.'],
          summary: 'Semantic explanations are available for 1 function(s).',
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
              metadata: { surface_role: 'runtime_stage_view' },
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
        ghidra_execution: {
          analysis_id: 'analysis-ghidra',
          selected_source: 'latest_attempt',
          backend: 'ghidra',
          status: 'done',
          function_count: 12,
          finished_at: '2026-03-23T00:00:00.000Z',
          project_path: null,
          project_key: null,
          project_root: null,
          log_root: null,
          function_extraction_status: 'done',
          function_extraction_script: 'ExtractFunctions.java',
          command_log_paths: [],
          runtime_log_paths: [],
          progress_stages: [],
          readiness_status: {
            function_index: 'ready',
            decompile: 'ready',
            cfg: 'ready',
          },
          java_exception: null,
          warnings: [],
        },
        provenance: {
          runtime: {
            scope: 'all',
            session_selector: null,
            session_tags: [],
            artifact_count: 0,
            artifact_ids: [],
            earliest_artifact_at: null,
            latest_artifact_at: null,
            scope_note: 'No runtime artifacts.',
          },
          static_capabilities: {
            scope: 'latest',
            session_selector: null,
            session_tags: [],
            artifact_count: 0,
            artifact_ids: [],
            earliest_artifact_at: null,
            latest_artifact_at: null,
            scope_note: 'No static capability artifacts.',
          },
          pe_structure: {
            scope: 'latest',
            session_selector: null,
            session_tags: [],
            artifact_count: 0,
            artifact_ids: [],
            earliest_artifact_at: null,
            latest_artifact_at: null,
            scope_note: 'No PE structure artifacts.',
          },
          compiler_packer: {
            scope: 'latest',
            session_selector: null,
            session_tags: [],
            artifact_count: 0,
            artifact_ids: [],
            earliest_artifact_at: null,
            latest_artifact_at: null,
            scope_note: 'No compiler/packer artifacts.',
          },
          semantic_explanations: {
            scope: 'all',
            session_selector: null,
            session_tags: [],
            artifact_count: 0,
            artifact_ids: [],
            earliest_artifact_at: null,
            latest_artifact_at: null,
            scope_note: 'No semantic explanation artifacts.',
          },
        },
        selection_diffs: undefined,
      },
    }
  }

  test('should stop after static stage and persist triage/static digests', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '1'.repeat(64),
      md5: '1'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
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

    let reportCallCount = 0
    const reportSummarizeHandler = async (_args: ToolArgs): Promise<WorkerResult> => {
      reportCallCount += 1
      return createCompactReportResult(sampleId)
    }

    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      { reportSummarizeHandler }
    )

    const result = await handler({
      sample_id: sampleId,
      through_stage: 'static',
      session_tag: 'summary-alpha',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(reportCallCount).toBe(1)
    expect(data.completed_stages).toEqual(['triage', 'static'])
    expect(data.tool_surface_role).toBe('primary')
    expect(data.coverage_level).toBe('static_core')
    expect(data.known_findings).toContain('Observed suspicious process APIs.')
    expect(data.stages.triage.summary).toContain('Compact triage summary')
    expect(data.stages.static.key_findings.length).toBeGreaterThan(0)
    expect(data.stages.deep).toBeUndefined()
    expect(data.stages.final).toBeUndefined()
    expect(data.stage_artifacts.triage.path).toContain('reports/summary/summary-alpha')
    expect(data.stage_artifacts.static.path).toContain('reports/summary/summary-alpha')
  })

  test('should reuse persisted stage digests without rebuilding compact report', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '2'.repeat(64),
      md5: '2'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    let reportCallCount = 0
    const reportSummarizeHandler = async (_args: ToolArgs): Promise<WorkerResult> => {
      reportCallCount += 1
      return createCompactReportResult(sampleId)
    }

    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      { reportSummarizeHandler }
    )

    const first = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'reuse-session',
    })
    expect(first.ok).toBe(true)
    expect(reportCallCount).toBe(1)

    const second = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'reuse-session',
      reuse_digests: true,
    })
    expect(second.ok).toBe(true)
    expect(reportCallCount).toBe(1)
    const data = second.data as any
    expect(data.synthesis.used_existing_stage_artifacts).toBe(true)
    expect(data.stage_artifacts.final.path).toContain('reports/summary/reuse-session')
  })

  test('should produce deterministic final synthesis when sampling is unavailable', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '3'.repeat(64),
      md5: '3'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => createCompactReportResult(sampleId),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'deterministic',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.synthesis.resolved_mode).toBe('deterministic')
    expect(data.explanation_graphs[0].graph_type).toBe('runtime_stage')
    expect(data.explanation_artifacts[0].type).toBe('analysis_explanation_graph')
    expect(data.stages.final.executive_summary).toContain('Compact triage summary')
    expect(data.stages.final.next_steps.length).toBeGreaterThan(0)
    expect(data.known_findings.length).toBeGreaterThan(0)
    expect(Array.isArray(data.suspected_findings)).toBe(true)
    expect(Array.isArray(data.unverified_areas)).toBe(true)
  })

  test('should use client-mediated sampling for final synthesis when available', async () => {
    const sampleId = 'sha256:' + '4'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '4'.repeat(64),
      md5: '4'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => createCompactReportResult(sampleId),
        clientCapabilitiesProvider: () => ({ sampling: {} }),
        samplingRequester: async () => ({
          model: 'gpt-5.4',
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                executive_summary: 'Sampling executive summary.',
                analyst_summary: 'Sampling analyst summary.',
                key_findings: ['finding-a', 'finding-b'],
                next_steps: ['step-a'],
                unresolved_unknowns: ['unknown-a'],
              }),
            },
          ],
        }),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'sampling',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.synthesis.resolved_mode).toBe('sampling')
    expect(data.synthesis.model_name).toBe('gpt-5.4')
    expect(data.stages.final.executive_summary).toBe('Sampling executive summary.')
  })

  test('should fall back to deterministic synthesis when sampling response is invalid', async () => {
    const sampleId = 'sha256:' + '5'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '5'.repeat(64),
      md5: '5'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => createCompactReportResult(sampleId),
        clientCapabilitiesProvider: () => ({ sampling: {} }),
        samplingRequester: async () => ({
          model: 'gpt-5.4',
          content: [
            {
              type: 'text',
              text: 'not-json',
            },
          ],
        }),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'sampling',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.synthesis.resolved_mode).toBe('deterministic')
    expect(result.warnings?.some((item) => item.includes('Falling back to deterministic synthesis'))).toBe(
      true
    )
  })
})
