import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createReportGenerateHandler } from '../../src/tools/report-generate.js'
import { persistSemanticFunctionExplanationsArtifact } from '../../src/semantic-name-suggestion-artifacts.js'

describe('report.generate tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-report-generate')
    testDbPath = path.join(process.cwd(), 'test-report-generate.db')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
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
  })

  async function seedRuntimeArtifact(
    sampleId: string,
    fileName: string,
    sourceName: string,
    api: string,
    createdAt: string
  ) {
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const reportDir = path.join(workspace.reports, 'dynamic')
    fs.mkdirSync(reportDir, { recursive: true })
    const filePath = path.join(reportDir, fileName)
    fs.writeFileSync(
      filePath,
      JSON.stringify(
        {
          schema_version: '0.1.0',
          source_format: 'generic_json',
          evidence_kind: 'trace',
          source_name: sourceName,
          imported_at: createdAt,
          executed: true,
          raw_event_count: 2,
          api_calls: [
            {
              api,
              module: 'kernel32.dll',
              category: 'process_manipulation',
              count: 1,
              confidence: 0.91,
              sources: ['unit-test'],
            },
          ],
          memory_regions: [],
          modules: ['kernel32.dll'],
          strings: [sourceName],
          stages: ['prepare_remote_process_access'],
          risk_hints: [],
          notes: ['runtime artifact'],
        },
        null,
        2
      ),
      'utf-8'
    )

    database.insertArtifact({
      id: `artifact-${fileName}`,
      sample_id: sampleId,
      type: 'dynamic_trace_json',
      path: `reports/dynamic/${fileName}`,
      sha256: 'a'.repeat(64),
      mime: 'application/json',
      created_at: createdAt,
    })
  }

  test('should return error for a missing sample', async () => {
    const handler = createReportGenerateHandler(workspaceManager, database)
    const result = await handler({
      sample_id: 'sha256:' + 'f'.repeat(64),
      format: 'markdown',
    })

    expect(result.isError).toBe(true)
    const text = result.content.find((item) => item.type === 'text')?.text
    expect(text).toContain('Sample not found')
  })

  test('should generate a markdown report artifact from stored analyses', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: '1'.repeat(64),
      md5: '1'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    database.insertAnalysis({
      id: 'analysis-ghidra',
      sample_id: sampleId,
      stage: 'ghidra',
      backend: 'ghidra',
      status: 'done',
      started_at: createdAt,
      finished_at: createdAt,
      output_json: JSON.stringify({ function_count: 2 }),
      metrics_json: JSON.stringify({ elapsed_ms: 1234 }),
    })

    database.insertFunction({
      sample_id: sampleId,
      address: '0x401000',
      name: 'entry_main',
      size: 64,
      score: 0.98,
      tags: JSON.stringify(['entry_point', 'process_ops']),
      summary: 'Entry point',
      caller_count: 0,
      callee_count: 2,
      is_entry_point: 1,
      is_exported: 0,
      callees: JSON.stringify(['CreateProcessW', 'WriteProcessMemory']),
    })

    database.insertFunction({
      sample_id: sampleId,
      address: '0x401080',
      name: 'resolve_dynamic_apis',
      size: 48,
      score: 0.87,
      tags: JSON.stringify(['dynamic_resolution']),
      summary: 'Resolves APIs dynamically',
      caller_count: 1,
      callee_count: 1,
      is_entry_point: 0,
      is_exported: 0,
      callees: JSON.stringify(['GetProcAddress']),
    })

    const handler = createReportGenerateHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      format: 'markdown',
    })

    expect(result.isError).toBeUndefined()

    const payload = JSON.parse(result.content.find((item) => item.type === 'text')!.text!)
    expect(payload.ok).toBe(true)
    expect(payload.data.artifact_id).toBeDefined()
    expect(payload.data.format).toBe('markdown')
    expect(fs.existsSync(payload.data.path)).toBe(true)

    const reportContent = fs.readFileSync(payload.data.path, 'utf-8')
    expect(reportContent).toContain('# Analysis Report:')
    expect(reportContent).toContain('## Sample Information')
    expect(reportContent).toContain('## Function Statistics')
    expect(reportContent).toContain('## Confidence Semantics')
    expect(reportContent).toContain('entry_main')

    const artifacts = database.findArtifacts(sampleId)
    expect(artifacts.some((artifact) => artifact.type === 'report_markdown')).toBe(true)
  })

  test('should include scoped runtime evidence in generated json report', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    const createdAt = '2026-03-11T00:00:00.000Z'

    database.insertSample({
      id: sampleId,
      sha256: '2'.repeat(64),
      md5: '2'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)
    await seedRuntimeArtifact(sampleId, 'alpha.json', 'alpha-session', 'WriteProcessMemory', createdAt)
    await seedRuntimeArtifact(sampleId, 'beta.json', 'beta-session', 'CreateRemoteThread', '2026-03-11T00:01:00.000Z')

    const handler = createReportGenerateHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      format: 'json',
      evidence_scope: 'session',
      evidence_session_tag: 'alpha-session',
    })

    expect(result.isError).toBeUndefined()
    const payload = JSON.parse(result.content.find((item) => item.type === 'text')!.text!)
    expect(payload.ok).toBe(true)

    const reportContent = JSON.parse(fs.readFileSync(payload.data.path, 'utf-8'))
    expect(reportContent.evidence_scope).toBe('session')
    expect(reportContent.evidence_session_tag).toBe('alpha-session')
    expect(reportContent.dynamic_evidence.observed_apis).toContain('WriteProcessMemory')
    expect(reportContent.dynamic_evidence.observed_apis).not.toContain('CreateRemoteThread')
    expect(reportContent.dynamic_evidence.session_selector).toBe('alpha-session')
    expect(reportContent.provenance.runtime.scope).toBe('session')
    expect(reportContent.provenance.runtime.artifact_count).toBe(1)
    expect(reportContent.provenance.runtime.session_tags).toContain('alpha-session')
    expect(reportContent.confidence_semantics.score_kind).toBe('report_assessment')
    expect(reportContent.confidence_semantics.calibrated).toBe(false)
  })

  test('should include binary role profile section in generated markdown report', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: 'b'.repeat(64),
      md5: 'b'.repeat(32),
      size: 4096,
      file_type: 'PE32 executable (DLL)',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    const handler = createReportGenerateHandler(workspaceManager, database, undefined, {
      binaryRoleProfileHandler: async () => ({
        ok: true,
        data: {
          sample_id: sampleId,
          original_filename: 'demo.dll',
          binary_role: 'dll',
          role_confidence: 0.91,
          runtime_hint: {
            is_dotnet: false,
            dotnet_version: null,
            target_framework: null,
            primary_runtime: 'native',
          },
          export_surface: {
            total_exports: 2,
            total_forwarders: 0,
            notable_exports: ['DllRegisterServer', 'RunPlugin'],
            com_related_exports: ['DllRegisterServer'],
            service_related_exports: [],
            plugin_related_exports: ['RunPlugin'],
            forwarded_exports: [],
          },
          import_surface: {
            dll_count: 3,
            notable_dlls: ['kernel32.dll', 'ole32.dll'],
            com_related_imports: ['ole32.dll'],
            service_related_imports: [],
            network_related_imports: [],
            process_related_imports: ['kernel32.dll'],
          },
          packed: false,
          packing_confidence: 0.08,
          indicators: {
            com_server: { likely: true, confidence: 0.8, evidence: ['export:DllRegisterServer'] },
            service_binary: { likely: false, confidence: 0.1, evidence: [] },
            plugin_binary: { likely: true, confidence: 0.67, evidence: ['export:RunPlugin'] },
            driver_binary: { likely: false, confidence: 0.05, evidence: [] },
          },
          export_dispatch_profile: {
            command_like_exports: ['RunPlugin'],
            callback_like_exports: [],
            registration_exports: ['DllRegisterServer'],
            ordinal_only_exports: 0,
            likely_dispatch_model: 'com_registration_and_class_factory',
            confidence: 0.74,
          },
          com_profile: {
            clsid_strings: [],
            progid_strings: ['Acme.Plugin'],
            interface_hints: ['IClassFactory'],
            registration_strings: ['InprocServer32'],
            class_factory_exports: ['DllRegisterServer'],
            confidence: 0.8,
          },
          host_interaction_profile: {
            likely_hosted: true,
            host_hints: ['Plugin host extension'],
            callback_exports: [],
            callback_strings: [],
            service_hooks: [],
            confidence: 0.61,
          },
          analysis_priorities: ['trace_export_surface_first'],
          strings_considered: 14,
        },
      }),
    })
    const result = await handler({
      sample_id: sampleId,
      format: 'markdown',
    })

    expect(result.isError).toBeUndefined()
    const payload = JSON.parse(result.content.find((item) => item.type === 'text')!.text!)
    const reportContent = fs.readFileSync(payload.data.path, 'utf-8')
    expect(reportContent).toContain('## Binary Role Profile')
    expect(reportContent).toContain('**Binary Role:** dll')
    expect(reportContent).toContain('DllRegisterServer')
    expect(reportContent).toContain('**Likely Dispatch Model:** com_registration_and_class_factory')
    expect(reportContent).toContain('trace_export_surface_first')
  })

  test('should include rust binary profile section in generated markdown report', async () => {
    const sampleId = 'sha256:' + 'd'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: 'd'.repeat(64),
      md5: 'd'.repeat(32),
      size: 8192,
      file_type: 'PE32+ executable',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    const handler = createReportGenerateHandler(workspaceManager, database, undefined, {
      rustBinaryAnalyzeHandler: async () => ({
        ok: true,
        data: {
          sample_id: sampleId,
          suspected_rust: true,
          confidence: 0.85,
          primary_runtime: 'rust',
          runtime_hints: ['rust', 'msvc'],
          cargo_paths: ['cargo\\registry\\src\\goblin-0.8.0\\src\\pe'],
          rust_markers: ['rust_panic'],
          async_runtime_markers: ['tokio'],
          panic_markers: ['panic'],
          crate_hints: ['goblin', 'tokio'],
          library_profile: {
            ecosystems: ['rust'],
            top_crates: ['goblin', 'tokio'],
            notable_libraries: ['goblin', 'tokio'],
            evidence: ['cargo registry path'],
          },
          recovered_function_count: 31,
          recovered_function_strategy: ['pdata_runtime_function'],
          recovered_symbol_count: 7,
          recovered_symbol_preview: [],
          components: {
            runtime_detect: { ok: true, warning_count: 0, error_count: 0 },
            strings_extract: { ok: true, warning_count: 0, error_count: 0 },
            smart_recover: { ok: true, warning_count: 0, error_count: 0 },
            symbols_recover: { ok: true, warning_count: 0, error_count: 0 },
            binary_role_profile: { ok: true, warning_count: 0, error_count: 0 },
          },
          importable_with_code_functions_define: true,
          evidence: ['Recovered functions from exception metadata.'],
          analysis_priorities: ['feed_recovered_boundaries_into_code.functions.define'],
          next_steps: ['Use code.functions.define to materialize the recovered index.'],
        },
      }),
    })
    const result = await handler({
      sample_id: sampleId,
      format: 'markdown',
    })

    expect(result.isError).toBeUndefined()
    const payload = JSON.parse(result.content.find((item) => item.type === 'text')!.text!)
    const reportContent = fs.readFileSync(payload.data.path, 'utf-8')
    expect(reportContent).toContain('## Rust Binary Profile')
    expect(reportContent).toContain('**Suspected Rust:** Yes')
    expect(reportContent).toContain('goblin, tokio')
    expect(reportContent).toContain('feed_recovered_boundaries_into_code.functions.define')
  })

  test('should include semantic function explanations in generated reports', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    const createdAt = '2026-03-11T00:00:00.000Z'

    database.insertSample({
      id: sampleId,
      sha256: '3'.repeat(64),
      md5: '3'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)
    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: createdAt,
      session_tag: 'alpha-session',
      client_name: 'claude-desktop',
      model_name: 'generic-tool-calling-llm',
      explanations: [
        {
          address: '0x401000',
          function: 'entry_main',
          summary: 'Initializes the runtime and dispatches remote process operations.',
          behavior: 'dispatch_remote_process_ops',
          confidence: 0.83,
          assumptions: ['The same initialization path feeds later process operations.'],
          evidence_used: ['runtime:prepare_remote_process_access'],
          rewrite_guidance: ['Separate initialization from dispatch logic.'],
        },
      ],
    })

    const handler = createReportGenerateHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      format: 'markdown',
    })

    expect(result.isError).toBeUndefined()
    const payload = JSON.parse(result.content.find((item) => item.type === 'text')!.text!)
    const reportContent = fs.readFileSync(payload.data.path, 'utf-8')
    expect(reportContent).toContain('## Analysis Provenance')
    expect(reportContent).toContain('Semantic Session Tags')
    expect(reportContent).toContain('## Function Explanations')
    expect(reportContent).toContain('dispatch_remote_process_ops')
    expect(reportContent).toContain('Separate initialization from dispatch logic.')
  })

  test('should scope semantic function explanations in generated reports', async () => {
    const sampleId = 'sha256:' + '4'.repeat(64)
    const createdAt = '2026-03-11T00:00:00.000Z'

    database.insertSample({
      id: sampleId,
      sha256: '4'.repeat(64),
      md5: '4'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)
    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: createdAt,
      session_tag: 'semantic-alpha',
      client_name: 'alpha-client',
      model_name: 'alpha-model',
      explanations: [
        {
          address: '0x401000',
          function: 'entry_main',
          summary: 'alpha summary',
          behavior: 'alpha_behavior',
          confidence: 0.72,
          rewrite_guidance: ['alpha guidance'],
        },
      ],
    })
    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: '2026-03-11T00:01:00.000Z',
      session_tag: 'semantic-beta',
      client_name: 'beta-client',
      model_name: 'beta-model',
      explanations: [
        {
          address: '0x401000',
          function: 'entry_main',
          summary: 'beta summary',
          behavior: 'beta_behavior',
          confidence: 0.92,
          rewrite_guidance: ['beta guidance'],
        },
      ],
    })

    const handler = createReportGenerateHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      format: 'json',
      semantic_scope: 'session',
      semantic_session_tag: 'semantic-beta',
    })

    expect(result.isError).toBeUndefined()
    const payload = JSON.parse(result.content.find((item) => item.type === 'text')!.text!)
    const reportContent = JSON.parse(fs.readFileSync(payload.data.path, 'utf-8'))
    expect(reportContent.provenance.semantic_explanations.scope).toBe('session')
    expect(reportContent.provenance.semantic_explanations.artifact_count).toBe(1)
    expect(reportContent.provenance.semantic_explanations.session_tags).toContain('semantic-beta')
    expect(reportContent.semantic_scope).toBe('session')
    expect(reportContent.semantic_session_tag).toBe('semantic-beta')
    expect(reportContent.function_explanations).toHaveLength(1)
    expect(reportContent.function_explanations[0].behavior).toBe('beta_behavior')
  })

  test('should include semantic selection diff in generated json reports', async () => {
    const sampleId = 'sha256:' + '5'.repeat(64)
    const createdAt = '2026-03-11T00:00:00.000Z'

    database.insertSample({
      id: sampleId,
      sha256: '5'.repeat(64),
      md5: '5'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)
    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: createdAt,
      session_tag: 'semantic-alpha',
      client_name: 'alpha-client',
      model_name: 'alpha-model',
      explanations: [
        {
          address: '0x401000',
          function: 'entry_main',
          summary: 'alpha summary',
          behavior: 'alpha_behavior',
          confidence: 0.72,
          rewrite_guidance: ['alpha guidance'],
        },
      ],
    })
    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: '2026-03-11T00:01:00.000Z',
      session_tag: 'semantic-beta',
      client_name: 'beta-client',
      model_name: 'beta-model',
      explanations: [
        {
          address: '0x401000',
          function: 'entry_main',
          summary: 'beta summary',
          behavior: 'beta_behavior',
          confidence: 0.92,
          rewrite_guidance: ['beta guidance'],
        },
      ],
    })

    const handler = createReportGenerateHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      format: 'json',
      semantic_scope: 'session',
      semantic_session_tag: 'semantic-beta',
      compare_semantic_scope: 'session',
      compare_semantic_session_tag: 'semantic-alpha',
    })

    expect(result.isError).toBeUndefined()
    const payload = JSON.parse(result.content.find((item) => item.type === 'text')!.text!)
    const reportContent = JSON.parse(fs.readFileSync(payload.data.path, 'utf-8'))
    expect(reportContent.selection_diffs.semantic_explanations.current.scope).toBe('session')
    expect(reportContent.selection_diffs.semantic_explanations.baseline.session_selector).toBe('semantic-alpha')
    expect(reportContent.selection_diffs.semantic_explanations.added_artifact_ids).toHaveLength(1)
    expect(reportContent.selection_diffs.semantic_explanations.removed_artifact_ids).toHaveLength(1)
  })
})
