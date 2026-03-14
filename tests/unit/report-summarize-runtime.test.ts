import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createReportSummarizeHandler } from '../../src/tools/report-summarize.js'
import { persistSemanticFunctionExplanationsArtifact } from '../../src/semantic-name-suggestion-artifacts.js'
import type { WorkerResult, ToolArgs } from '../../src/types.js'

describe('report.summarize runtime evidence integration', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-report-runtime')
    testDbPath = path.join(process.cwd(), 'test-report-runtime.db')
    testCachePath = path.join(process.cwd(), 'test-cache-report-runtime')

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

  async function seedRuntimeArtifact(
    sampleId: string,
    options?: {
      fileName?: string
      sourceName?: string
      api?: string
      importedAt?: string
      createdAt?: string
      executed?: boolean
    }
  ) {
    const workspace = await workspaceManager.createWorkspace(sampleId)
    const reportDir = path.join(workspace.reports, 'dynamic')
    fs.mkdirSync(reportDir, { recursive: true })
    const fileName = options?.fileName || 'imported_runtime.json'
    const importedAt = options?.importedAt || new Date().toISOString()
    const createdAt = options?.createdAt || importedAt
    const api = options?.api || 'WriteProcessMemory'
    const sourceName = options?.sourceName || 'runtime-default'
    const executed = options?.executed ?? true
    const filePath = path.join(reportDir, fileName)
    fs.writeFileSync(
      filePath,
      JSON.stringify(
        {
          schema_version: '0.1.0',
          source_format: 'generic_json',
          evidence_kind: 'trace',
          source_name: sourceName,
          imported_at: importedAt,
          executed,
          raw_event_count: 3,
          api_calls: [
            {
              api,
              module: 'kernel32.dll',
              category: 'process_manipulation',
              count: 1,
              confidence: 0.93,
              sources: ['frida'],
            },
            {
              api: 'GetProcAddress',
              module: 'kernel32.dll',
              category: 'dynamic_resolution',
              count: 1,
              confidence: 0.87,
              sources: ['frida'],
            },
          ],
          memory_regions: [
            {
              region_type: 'dispatch_table',
              purpose: 'process_operation_plan',
              source: 'frida',
              confidence: 0.91,
              base_address: '0x1000',
              size: 512,
              protection: 'read_write_plan',
              module_name: 'akasha.exe',
              segment_name: '.text',
              indicators: ['WriteProcessMemory', 'ResumeThread'],
            },
          ],
          modules: ['kernel32.dll', 'akasha.exe'],
          strings: ['remote thread'],
          stages: ['prepare_remote_process_access', 'resolve_dynamic_apis'],
          risk_hints: ['Process-memory manipulation APIs were observed in runtime evidence.'],
          notes: ['Imported runtime trace'],
        },
        null,
        2
      ),
      'utf-8'
    )

    database.insertArtifact({
      id: `runtime-artifact-id-${fileName}`,
      sample_id: sampleId,
      type: 'dynamic_trace_json',
      path: `reports/dynamic/${fileName}`,
      sha256: 'a'.repeat(64),
      mime: 'application/json',
      created_at: createdAt,
    })
  }

  test('should merge imported runtime evidence into triage output', async () => {
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
    await seedRuntimeArtifact(sampleId)

    const triageHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        summary: 'Static triage suggests dual-use process tooling.',
        confidence: 0.74,
        threat_level: 'clean',
        iocs: {
          suspicious_imports: ['OpenProcess'],
          suspicious_strings: ['akasha --pid 1234'],
          yara_matches: [],
          high_value_iocs: {
            suspicious_apis: ['OpenProcess'],
          },
        },
        evidence: ['Static imports include process APIs.'],
        evidence_weights: {
          import: 0.6,
          string: 0.25,
          runtime: 0.15,
        },
        inference: {
          classification: 'benign',
          hypotheses: ['This could be an operator utility.'],
          false_positive_risks: ['Strings may overstate offensive use.'],
        },
        recommendation: 'Review top-ranked functions.',
      },
    })

    const handler = createReportSummarizeHandler(workspaceManager, database, cacheManager, {
      triageHandler,
    })
    const result = await handler({
      sample_id: sampleId,
      mode: 'triage',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.summary).toContain('Runtime evidence:')
    expect(data.summary).toContain('Evidence layers: static_only -> executed_trace.')
    expect(data.threat_level).toBe('suspicious')
    expect(data.iocs.high_value_iocs.suspicious_apis).toContain('WriteProcessMemory')
    expect(data.evidence.some((item: string) => item.includes('Imported runtime trace observed'))).toBe(true)
    expect(data.evidence).toContain('Runtime protections: read_write_plan.')
    expect(data.evidence).toContain('Runtime region owners: akasha.exe.')
    expect(data.evidence).toContain('Runtime observed modules: kernel32.dll, akasha.exe.')
    expect(data.evidence).toContain('Runtime segment names: .text.')
    expect(data.evidence_lineage.layers.some((item: any) => item.layer === 'static_only')).toBe(true)
    expect(data.evidence_lineage.layers.some((item: any) => item.layer === 'executed_trace')).toBe(true)
    expect(data.evidence_lineage.latest_runtime_artifact_at).toBeTruthy()
    expect(data.evidence_lineage.scope_note).toContain('single registered artifact')
    expect(data.provenance.runtime.artifact_count).toBe(1)
    expect(data.provenance.runtime.artifact_ids).toHaveLength(1)
    expect(data.evidence_weights.runtime).toBeGreaterThan(0.7)
    expect(data.inference.classification).toBe('suspicious')
    expect(data.confidence_semantics.assessment.score_kind).toBe('report_assessment')
    expect(data.confidence_semantics.assessment.calibrated).toBe(false)
    expect(data.confidence_semantics.assessment.drivers).toContain('executed_trace=yes')
  })

  test('should attach binary role profile and priorities to report summary output', async () => {
    const sampleId = 'sha256:' + 'a'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'a'.repeat(64),
      md5: 'a'.repeat(32),
      size: 4096,
      file_type: 'PE32 executable (DLL)',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const triageHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        summary: 'Static triage suggests operator tooling.',
        confidence: 0.7,
        threat_level: 'clean',
        iocs: {
          suspicious_imports: [],
          suspicious_strings: [],
          yara_matches: [],
        },
        evidence: ['Static hint.'],
        recommendation: 'Review exports first.',
        inference: {
          classification: 'unknown',
          hypotheses: ['Static imports suggest loader-like behavior.'],
          false_positive_risks: ['Static-only evidence can overstate role.'],
        },
      },
    })
    const binaryRoleProfileHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        sample_id: sampleId,
        original_filename: 'demo.dll',
        binary_role: 'dll',
        role_confidence: 0.92,
        runtime_hint: {
          is_dotnet: false,
          dotnet_version: null,
          target_framework: null,
          primary_runtime: 'native',
        },
        export_surface: {
          total_exports: 3,
          total_forwarders: 0,
          notable_exports: ['DllRegisterServer', 'RunPlugin'],
          com_related_exports: ['DllRegisterServer'],
          service_related_exports: [],
          plugin_related_exports: ['RunPlugin'],
          forwarded_exports: [],
        },
        import_surface: {
          dll_count: 4,
          notable_dlls: ['kernel32.dll', 'ole32.dll'],
          com_related_imports: ['ole32.dll'],
          service_related_imports: [],
          network_related_imports: [],
          process_related_imports: ['kernel32.dll'],
        },
        packed: false,
        packing_confidence: 0.12,
        indicators: {
          com_server: { likely: true, confidence: 0.81, evidence: ['export:DllRegisterServer'] },
          service_binary: { likely: false, confidence: 0.1, evidence: [] },
          plugin_binary: { likely: true, confidence: 0.69, evidence: ['export:RunPlugin'] },
          driver_binary: { likely: false, confidence: 0.05, evidence: [] },
        },
        export_dispatch_profile: {
          command_like_exports: ['RunPlugin'],
          callback_like_exports: [],
          registration_exports: ['DllRegisterServer'],
          ordinal_only_exports: 0,
          likely_dispatch_model: 'com_registration_and_class_factory',
          confidence: 0.73,
        },
        lifecycle_surface: ['DllMain', 'DLL_PROCESS_ATTACH'],
        com_profile: {
          clsid_strings: [],
          progid_strings: ['Acme.Plugin'],
          interface_hints: ['IClassFactory'],
          registration_strings: ['InprocServer32'],
          class_factory_exports: ['DllRegisterServer'],
          class_factory_surface: ['DllGetClassObject', 'IClassFactory::CreateInstance'],
          confidence: 0.81,
        },
        host_interaction_profile: {
          likely_hosted: true,
          host_hints: ['Plugin host extension'],
          callback_exports: [],
          callback_surface: ['InitializePlugin'],
          callback_strings: [],
          service_hooks: [],
          confidence: 0.6,
        },
        analysis_priorities: ['trace_export_surface_first', 'trace_com_activation_and_class_factory_flow'],
        strings_considered: 10,
      },
    })

    const handler = createReportSummarizeHandler(workspaceManager, database, cacheManager, {
      triageHandler,
      binaryRoleProfileHandler,
    })
    const result = await handler({
      sample_id: sampleId,
      mode: 'triage',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.binary_profile.binary_role).toBe('dll')
    expect(data.summary).toContain('Binary role profile suggests dll')
    expect(data.summary).toContain('registration_exports=DllRegisterServer')
    expect(data.summary).toContain('dll_lifecycle=DllMain, DLL_PROCESS_ATTACH')
    expect(data.summary).toContain('class_factory_exports=DllRegisterServer')
    expect(data.summary).toContain('class_factory_surface=DllGetClassObject, IClassFactory::CreateInstance')
    expect(data.summary).toContain('callback_surface=InitializePlugin')
    expect(data.summary).toContain('host_hints=Plugin host extension')
    expect(data.evidence.some((item: string) => item.includes('binary_profile_priority'))).toBe(true)
    expect(data.evidence.some((item: string) => item.includes('binary_profile_surface: class_factory_export=DllRegisterServer'))).toBe(true)
    expect(data.evidence.some((item: string) => item.includes('binary_profile_surface: dll_lifecycle=DllMain'))).toBe(true)
    expect(data.recommendation).toContain('trace_export_surface_first')
  })

  test('should attach rust recovery profile and compiler artifacts to report summary output', async () => {
    const sampleId = 'sha256:' + 'c'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'c'.repeat(64),
      md5: 'c'.repeat(32),
      size: 8192,
      file_type: 'PE32+ executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const triageHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        summary: 'Static triage suggests a command-driven PE utility.',
        confidence: 0.68,
        threat_level: 'clean',
        iocs: {
          suspicious_imports: [],
          suspicious_strings: [],
          yara_matches: [],
        },
        evidence: ['Static hint.'],
        recommendation: 'Review code paths.',
        inference: {
          classification: 'unknown',
          hypotheses: ['The binary may be a utility framework.'],
          false_positive_risks: ['Static evidence alone is ambiguous.'],
          tooling_assessment: {
            help_text_detected: false,
            cli_surface_detected: true,
            framework_hints: [],
            toolchain_markers: [],
          },
        },
      },
    })
    const rustBinaryAnalyzeHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        sample_id: sampleId,
        suspected_rust: true,
        confidence: 0.87,
        primary_runtime: 'rust',
        runtime_hints: ['rust', 'msvc'],
        cargo_paths: ['cargo\\registry\\src\\tokio-1.0.0\\src\\runtime'],
        rust_markers: ['rust_panic'],
        async_runtime_markers: ['tokio'],
        panic_markers: ['panic'],
        crate_hints: ['tokio', 'goblin'],
        library_profile: {
          ecosystems: ['rust'],
          top_crates: ['tokio', 'goblin'],
          notable_libraries: ['tokio', 'goblin'],
          evidence: ['cargo registry path'],
        },
        binary_profile: undefined,
        recovered_function_count: 42,
        recovered_function_strategy: ['pdata_runtime_function'],
        recovered_symbol_count: 8,
        recovered_symbol_preview: [
          {
            address: '0x140001000',
            recovered_name: 'rust_entry_point_00001000',
            name_strategy: 'rust_entry_point',
            confidence: 0.88,
          },
        ],
        components: {
          runtime_detect: { ok: true, warning_count: 0, error_count: 0 },
          strings_extract: { ok: true, warning_count: 0, error_count: 0 },
          smart_recover: { ok: true, warning_count: 0, error_count: 0 },
          symbols_recover: { ok: true, warning_count: 0, error_count: 0 },
          binary_role_profile: { ok: true, warning_count: 0, error_count: 0 },
        },
        importable_with_code_functions_define: true,
        evidence: ['Recovered function boundaries from .pdata.'],
        analysis_priorities: ['feed_recovered_boundaries_into_code.functions.define'],
        next_steps: ['Use code.functions.define to materialize the recovered index.'],
      },
    })

    const handler = createReportSummarizeHandler(workspaceManager, database, cacheManager, {
      triageHandler,
      rustBinaryAnalyzeHandler,
    })
    const result = await handler({
      sample_id: sampleId,
      mode: 'triage',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.rust_profile.suspected_rust).toBe(true)
    expect(data.summary).toContain('Rust-focused analysis suggests a Rust-oriented binary')
    expect(data.iocs.compiler_artifacts.cargo_paths).toContain('cargo\\registry\\src\\tokio-1.0.0\\src\\runtime')
    expect(data.iocs.compiler_artifacts.rust_markers).toContain('rust_panic')
    expect(data.iocs.compiler_artifacts.library_profile.top_crates).toContain('tokio')
    expect(data.evidence.some((item: string) => item.includes('rust_analysis_priority'))).toBe(true)
    expect(data.recommendation).toContain('feed_recovered_boundaries_into_code.functions.define')
  })

  test('should return runtime-evidence fallback when triage fails', async () => {
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
    await seedRuntimeArtifact(sampleId)

    const triageHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: false,
      errors: ['triage failed'],
    })

    const handler = createReportSummarizeHandler(workspaceManager, database, cacheManager, {
      triageHandler,
    })
    const result = await handler({
      sample_id: sampleId,
      mode: 'triage',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.summary).toContain('imported runtime evidence is available')
    expect(data.summary).toContain('Evidence layers: static_only -> executed_trace.')
    expect(data.iocs.high_value_iocs.suspicious_apis).toContain('WriteProcessMemory')
    expect(data.evidence_lineage.layers.some((item: any) => item.layer === 'static_only')).toBe(true)
    expect(data.evidence_lineage.layers.some((item: any) => item.layer === 'executed_trace')).toBe(true)
    expect(data.evidence_weights.runtime).toBeGreaterThan(0.8)
    expect(result.warnings?.some((item) => item.includes('runtime-evidence fallback'))).toBe(true)
    expect(data.confidence_semantics.assessment.score_kind).toBe('report_assessment')
    expect(data.confidence_semantics.assessment.band).not.toBe('none')
  })

  test('should limit runtime evidence to latest artifact window when evidence_scope=latest', async () => {
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
    await seedRuntimeArtifact(sampleId, {
      fileName: 'older_runtime.json',
      sourceName: 'older-session',
      api: 'CreateRemoteThread',
      importedAt: '2026-03-10T00:00:00.000Z',
      createdAt: '2026-03-10T00:00:00.000Z',
    })
    await seedRuntimeArtifact(sampleId, {
      fileName: 'latest_runtime.json',
      sourceName: 'latest-session',
      api: 'WriteProcessMemory',
      importedAt: '2026-03-11T00:00:05.000Z',
      createdAt: '2026-03-11T00:00:05.000Z',
    })

    const triageHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        summary: 'Static triage suggests process tooling.',
        confidence: 0.7,
        threat_level: 'clean',
        iocs: {
          suspicious_imports: [],
          suspicious_strings: [],
          yara_matches: [],
        },
        evidence: ['Static hint.'],
        recommendation: 'Review runtime evidence.',
      },
    })

    const handler = createReportSummarizeHandler(workspaceManager, database, cacheManager, {
      triageHandler,
    })
    const result = await handler({
      sample_id: sampleId,
      mode: 'triage',
      evidence_scope: 'latest',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.iocs.high_value_iocs.suspicious_apis).toContain('WriteProcessMemory')
    expect(data.iocs.high_value_iocs.suspicious_apis).not.toContain('CreateRemoteThread')
    expect(data.evidence_lineage.scope_note).toContain('latest artifact window')
    expect(data.provenance.runtime.scope).toBe('latest')
    expect(data.provenance.runtime.artifact_count).toBe(1)
    expect(data.provenance.runtime.session_tags).toContain('latest-session')
  })

  test('should limit runtime evidence to the requested session selector when evidence_scope=session', async () => {
    const sampleId = 'sha256:' + '6'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '6'.repeat(64),
      md5: '6'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    await seedRuntimeArtifact(sampleId, {
      fileName: 'session_alpha.json',
      sourceName: 'alpha-session',
      api: 'CreateRemoteThread',
      importedAt: '2026-03-10T00:00:00.000Z',
      createdAt: '2026-03-10T00:00:00.000Z',
    })
    await seedRuntimeArtifact(sampleId, {
      fileName: 'session_beta.json',
      sourceName: 'beta-session',
      api: 'WriteProcessMemory',
      importedAt: '2026-03-11T00:00:00.000Z',
      createdAt: '2026-03-11T00:00:00.000Z',
    })

    const triageHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        summary: 'Static triage suggests process tooling.',
        confidence: 0.7,
        threat_level: 'clean',
        iocs: {
          suspicious_imports: [],
          suspicious_strings: [],
          yara_matches: [],
        },
        evidence: ['Static hint.'],
        recommendation: 'Review runtime evidence.',
      },
    })

    const handler = createReportSummarizeHandler(workspaceManager, database, cacheManager, {
      triageHandler,
    })
    const result = await handler({
      sample_id: sampleId,
      mode: 'triage',
      evidence_scope: 'session',
      evidence_session_tag: 'alpha-session',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.iocs.high_value_iocs.suspicious_apis).toContain('CreateRemoteThread')
    expect(data.iocs.high_value_iocs.suspicious_apis).not.toContain('WriteProcessMemory')
    expect(data.evidence_lineage.scope_note).toContain('alpha-session')
    expect(data.provenance.runtime.scope).toBe('session')
    expect(data.provenance.runtime.artifact_count).toBe(1)
    expect(data.provenance.runtime.session_tags).toContain('alpha-session')
  })

  test('should include runtime selection diff when compare_evidence_scope is provided', async () => {
    const sampleId = 'sha256:' + '9'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '9'.repeat(64),
      md5: '9'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    await seedRuntimeArtifact(sampleId, {
      fileName: 'session_alpha.json',
      sourceName: 'alpha-session',
      api: 'CreateRemoteThread',
      importedAt: '2026-03-10T00:00:00.000Z',
      createdAt: '2026-03-10T00:00:00.000Z',
    })
    await seedRuntimeArtifact(sampleId, {
      fileName: 'session_beta.json',
      sourceName: 'beta-session',
      api: 'WriteProcessMemory',
      importedAt: '2026-03-11T00:00:00.000Z',
      createdAt: '2026-03-11T00:00:00.000Z',
    })

    const triageHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        summary: 'Static triage suggests process tooling.',
        confidence: 0.7,
        threat_level: 'clean',
        iocs: {
          suspicious_imports: [],
          suspicious_strings: [],
          yara_matches: [],
        },
        evidence: ['Static hint.'],
        recommendation: 'Review runtime evidence.',
      },
    })

    const handler = createReportSummarizeHandler(workspaceManager, database, cacheManager, {
      triageHandler,
    })
    const result = await handler({
      sample_id: sampleId,
      mode: 'triage',
      evidence_scope: 'session',
      evidence_session_tag: 'beta-session',
      compare_evidence_scope: 'session',
      compare_evidence_session_tag: 'alpha-session',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.selection_diffs.runtime.current.scope).toBe('session')
    expect(data.selection_diffs.runtime.baseline.session_selector).toBe('alpha-session')
    expect(data.selection_diffs.runtime.added_artifact_ids).toHaveLength(1)
    expect(data.selection_diffs.runtime.removed_artifact_ids).toHaveLength(1)
    expect(data.selection_diffs.runtime.summary).toContain('baseline scope=session')
  })

  test('should surface semantic function explanations in triage summaries', async () => {
    const sampleId = 'sha256:' + '7'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '7'.repeat(64),
      md5: '7'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: new Date().toISOString(),
      session_tag: 'alpha-session',
      client_name: 'claude-desktop',
      model_name: 'generic-tool-calling-llm',
      explanations: [
        {
          address: '0x401000',
          function: 'entry_main',
          summary: 'Initializes the runtime and dispatches process-control operations.',
          behavior: 'dispatch_process_control',
          confidence: 0.81,
          assumptions: ['The same branch reaches later process-control logic.'],
          evidence_used: ['xref:CreateProcessW'],
          rewrite_guidance: ['Split command parsing from operation dispatch.'],
        },
      ],
    })

    const triageHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        summary: 'Static triage suggests process tooling.',
        confidence: 0.71,
        threat_level: 'clean',
        iocs: {
          suspicious_imports: [],
          suspicious_strings: [],
          yara_matches: [],
        },
        evidence: ['Static hint.'],
        recommendation: 'Review top-ranked functions.',
      },
    })

    const handler = createReportSummarizeHandler(workspaceManager, database, cacheManager, {
      triageHandler,
    })
    const result = await handler({
      sample_id: sampleId,
      mode: 'triage',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.function_explanations).toHaveLength(1)
    expect(data.function_explanations[0].behavior).toBe('dispatch_process_control')
    expect(data.provenance.semantic_explanations.artifact_count).toBe(1)
    expect(data.provenance.semantic_explanations.session_tags).toContain('alpha-session')
    expect(data.evidence.some((item: string) => item.includes('External semantic explanations are available'))).toBe(true)
    expect(data.recommendation).toContain('Cross-check the attached function explanations')
  })

  test('should scope semantic function explanations by semantic session selector', async () => {
    const sampleId = 'sha256:' + '8'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '8'.repeat(64),
      md5: '8'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: '2026-03-11T00:00:00.000Z',
      session_tag: 'semantic-alpha',
      client_name: 'alpha-client',
      model_name: 'alpha-model',
      explanations: [
        {
          address: '0x401000',
          function: 'entry_main',
          summary: 'alpha summary',
          behavior: 'alpha_behavior',
          confidence: 0.81,
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
          confidence: 0.9,
          rewrite_guidance: ['beta guidance'],
        },
      ],
    })

    const triageHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        summary: 'Static triage suggests process tooling.',
        confidence: 0.71,
        threat_level: 'clean',
        iocs: {
          suspicious_imports: [],
          suspicious_strings: [],
          yara_matches: [],
        },
        evidence: ['Static hint.'],
        recommendation: 'Review top-ranked functions.',
      },
    })

    const handler = createReportSummarizeHandler(workspaceManager, database, cacheManager, {
      triageHandler,
    })
    const result = await handler({
      sample_id: sampleId,
      mode: 'triage',
      semantic_scope: 'session',
      semantic_session_tag: 'semantic-beta',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.provenance.semantic_explanations.scope).toBe('session')
    expect(data.provenance.semantic_explanations.artifact_count).toBe(1)
    expect(data.provenance.semantic_explanations.session_tags).toContain('semantic-beta')
    expect(data.function_explanations).toHaveLength(1)
    expect(data.function_explanations[0].behavior).toBe('beta_behavior')
    expect(data.function_explanations[0].summary).toContain('beta summary')
  })
})
