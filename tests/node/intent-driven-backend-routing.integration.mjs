import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const { WorkspaceManager } = await import('../../dist/workspace-manager.js')
const { DatabaseManager } = await import('../../dist/database.js')
const { CacheManager } = await import('../../dist/cache-manager.js')
const { PolicyGuard } = await import('../../dist/policy-guard.js')
const { createAnalyzeAutoWorkflowHandler } = await import('../../dist/workflows/analyze-auto.js')
const { createTriageWorkflowHandler } = await import('../../dist/workflows/triage.js')
const { createReconstructWorkflowHandler } = await import('../../dist/workflows/reconstruct.js')

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'intent-routing-integration-'))
const workspaceRoot = path.join(tempRoot, 'workspaces')
const dbPath = path.join(tempRoot, 'test.db')
const cacheRoot = path.join(tempRoot, 'cache')
const auditPath = path.join(tempRoot, 'audit.log')

const workspaceManager = new WorkspaceManager(workspaceRoot)
const database = new DatabaseManager(dbPath)
const cacheManager = new CacheManager(cacheRoot, database)
const policyGuard = new PolicyGuard(auditPath)

function createReadyBackends() {
  return {
    capa_cli: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    capa_rules: { available: false, source: 'none', path: null, error: null },
    die: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    graphviz: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    rizin: { available: true, source: 'path', path: '/tool/rizin', version: '1', checked_candidates: ['rizin'], error: null },
    upx: { available: true, source: 'path', path: '/tool/upx', version: '1', checked_candidates: ['upx'], error: null },
    wine: { available: true, source: 'path', path: '/tool/wine', version: '1', checked_candidates: ['wine'], error: null },
    winedbg: { available: true, source: 'path', path: '/tool/winedbg', version: '1', checked_candidates: ['winedbg'], error: null },
    frida_cli: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    yara_x: { available: true, source: 'path', path: '/tool/python', version: '1', checked_candidates: ['python3'], error: null },
    qiling: { available: true, source: 'path', path: '/tool/qiling', version: '1', checked_candidates: ['python3'], error: null },
    angr: { available: true, source: 'path', path: '/tool/angr', version: '1', checked_candidates: ['python3'], error: null },
    panda: { available: true, source: 'path', path: '/tool/panda', version: '1', checked_candidates: ['python3'], error: null },
    retdec: { available: true, source: 'path', path: '/tool/retdec', version: '1', checked_candidates: ['retdec'], error: null },
  }
}

function createBinaryProfilePayload(sampleId) {
  return {
    sample_id: sampleId,
    original_filename: 'sample.exe',
    binary_role: 'executable',
    role_confidence: 0.88,
    runtime_hint: {
      is_dotnet: false,
      dotnet_version: null,
      target_framework: null,
      primary_runtime: 'native',
    },
    export_surface: {
      total_exports: 0,
      total_forwarders: 0,
      notable_exports: [],
      com_related_exports: [],
      service_related_exports: [],
      plugin_related_exports: [],
      forwarded_exports: [],
    },
    import_surface: {
      dll_count: 2,
      notable_dlls: ['kernel32.dll'],
      com_related_imports: [],
      service_related_imports: [],
      network_related_imports: [],
      process_related_imports: ['WriteProcessMemory'],
    },
    packed: false,
    packing_confidence: 0.1,
    indicators: {
      com_server: { likely: false, confidence: 0.01, evidence: [] },
      service_binary: { likely: false, confidence: 0.01, evidence: [] },
      plugin_binary: { likely: false, confidence: 0.01, evidence: [] },
      driver_binary: { likely: false, confidence: 0.01, evidence: [] },
    },
    export_dispatch_profile: {
      command_like_exports: [],
      callback_like_exports: [],
      registration_exports: [],
      ordinal_only_exports: 0,
      likely_dispatch_model: 'none',
      confidence: 0.05,
    },
    com_profile: {
      clsid_strings: [],
      progid_strings: [],
      interface_hints: [],
      registration_strings: [],
      class_factory_exports: [],
      confidence: 0.01,
    },
    host_interaction_profile: {
      likely_hosted: false,
      host_hints: [],
      callback_exports: [],
      callback_strings: [],
      service_hooks: [],
      confidence: 0.05,
    },
    analysis_priorities: ['recover_functions'],
    strings_considered: 20,
  }
}

async function setupSample(sampleId, hashChar) {
  database.insertSample({
    id: sampleId,
    sha256: hashChar.repeat(64),
    md5: hashChar.repeat(32),
    size: 4096,
    file_type: 'PE32+',
    created_at: new Date().toISOString(),
    source: 'test',
  })
  const workspace = await workspaceManager.createWorkspace(sampleId)
  await fs.writeFile(path.join(workspace.original, 'sample.exe'), Buffer.from('MZtest'))
}

async function runAutoRoutingCases() {
  const sampleId = `sha256:${'a'.repeat(64)}`
  await setupSample(sampleId, 'a')

  const handler = createAnalyzeAutoWorkflowHandler(
    workspaceManager,
    database,
    cacheManager,
    policyGuard,
    undefined,
    {
      triageHandler: async () => ({
        ok: true,
        data: {
          summary: 'quick triage',
          recommended_next_tools: ['ghidra.analyze'],
          next_actions: ['continue triage'],
          goal: 'triage',
          depth: 'balanced',
          backend_policy: 'auto',
          backend_considered: [{ backend: 'rizin', tool: 'rizin.analyze', reason: 'considered' }],
          backend_selected: [{ backend: 'rizin', tool: 'rizin.analyze', reason: 'selected' }],
          backend_skipped: [],
          backend_escalation_reasons: ['selected'],
          manual_only_backends: [],
        },
      }),
      deepStaticHandler: async () => ({
        content: [{ type: 'text', text: JSON.stringify({ ok: true, data: { status: 'queued', job_id: 'job-1', result_mode: 'queued', recommended_next_tools: ['task.status'], next_actions: ['poll'] } }) }],
        structuredContent: { ok: true, data: { status: 'queued', job_id: 'job-1', result_mode: 'queued', recommended_next_tools: ['task.status'], next_actions: ['poll'] } },
      }),
      reconstructHandler: async () => ({
        ok: true,
        data: {
          selected_path: 'native',
          result_mode: 'completed',
          recommended_next_tools: ['artifact.read'],
          next_actions: ['inspect export'],
          goal: 'reverse',
          depth: 'deep',
          backend_policy: 'prefer_new',
          backend_considered: [{ backend: 'angr', tool: 'angr.analyze', reason: 'considered' }],
          backend_selected: [{ backend: 'angr', tool: 'angr.analyze', reason: 'selected' }],
          backend_skipped: [],
          backend_escalation_reasons: ['selected'],
          manual_only_backends: [],
        },
      }),
      dynamicDependenciesHandler: async () => ({
        ok: true,
        data: {
          status: 'ready',
          components: {
            speakeasy: { available: false },
            qiling: { available: true, rootfs_exists: true },
            panda: { available: true },
          },
        },
      }),
      sandboxExecuteHandler: async () => ({
        ok: true,
        data: {
          status: 'completed',
          mode: 'safe_simulation',
          simulated: true,
        },
      }),
      qilingInspectHandler: async () => ({
        ok: true,
        data: { status: 'ready', summary: 'qiling ready' },
      }),
      pandaInspectHandler: async () => ({
        ok: true,
        data: { status: 'ready', summary: 'panda ready' },
      }),
      resolveBackends: createReadyBackends,
    }
  )

  const triageResult = await handler({ sample_id: sampleId, goal: 'triage' })
  assert.equal(triageResult.ok, true)
  assert.equal(triageResult.data.routed_tool, 'workflow.triage')
  assert.equal(triageResult.data.backend_selected[0].tool, 'rizin.analyze')

  const staticResult = await handler({ sample_id: sampleId, goal: 'static' })
  assert.equal(staticResult.ok, true)
  assert.equal(staticResult.data.routed_tool, 'workflow.deep_static')
  assert.equal(staticResult.data.result_mode, 'queued')
  assert.equal(staticResult.data.job_id, 'job-1')

  const reverseResult = await handler({
    sample_id: sampleId,
    goal: 'reverse',
    depth: 'deep',
    backend_policy: 'prefer_new',
  })
  assert.equal(reverseResult.ok, true)
  assert.equal(reverseResult.data.routed_tool, 'workflow.reconstruct')
  assert.equal(reverseResult.data.backend_selected[0].tool, 'angr.analyze')

  const dynamicResult = await handler({ sample_id: sampleId, goal: 'dynamic', depth: 'balanced' })
  assert.equal(dynamicResult.ok, true)
  assert.equal(dynamicResult.data.routed_tool, 'dynamic.dependencies+sandbox.execute')
  assert.ok(dynamicResult.data.manual_only_backends.some((item) => item.tool === 'wine.run'))
  assert.equal(dynamicResult.data.backend_enrichments.qiling.summary, 'qiling ready')
  assert.equal(dynamicResult.data.backend_enrichments.panda.summary, 'panda ready')
}

async function runTriageEnrichmentCase() {
  const sampleId = `sha256:${'b'.repeat(64)}`
  await setupSample(sampleId, 'b')

  const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager, {
    peFingerprint: async () => ({ ok: true, data: { machine_name: 'IMAGE_FILE_MACHINE_AMD64', sections: [] } }),
    runtimeDetect: async () => ({ ok: true, data: { suspected: [{ runtime: 'native', confidence: 0.7, evidence: ['imports'] }], import_dlls: ['KERNEL32.dll'] } }),
    peImportsExtract: async () => ({ ok: true, data: { imports: { 'KERNEL32.dll': ['WriteProcessMemory'] }, delay_imports: {} } }),
    stringsExtract: async () => ({ ok: true, data: { strings: [{ string: 'http://evil.example', offset: 16, encoding: 'ascii' }], summary: { cluster_counts: {}, context_windows: [] } } }),
    yaraScan: async () => ({ ok: true, data: { matches: [], quality_notes: [] } }),
    staticCapabilityTriage: async () => ({ ok: true, data: { status: 'ready', capability_count: 0, capability_groups: {}, capabilities: [] } }),
    peStructureAnalyze: async () => ({ ok: true, data: { status: 'partial', summary: { section_count: 3, resource_count: 0, forwarder_count: 0, parser_preference: 'lief', overlay_present: true } } }),
    compilerPackerDetect: async () => ({ ok: true, data: { status: 'ready', compiler_findings: [], packer_findings: [{ name: 'UPX' }], protector_findings: [], file_type_findings: [], summary: { compiler_count: 0, packer_count: 1, protector_count: 0, file_type_count: 0, likely_primary_file_type: 'pe32+' } } }),
    analysisContextLink: async () => ({ ok: true, data: { status: 'partial', xref_status: 'unavailable', merged_strings: { analyst_relevant_count: 1, total_records: 1, kept_records: 1, runtime_noise_count: 0, encoded_candidate_count: 0, merged_sources: true, truncated: false, top_suspicious: [], top_iocs: [], top_decoded: [], context_windows: [] }, function_contexts: [], source_artifact_refs: [] } }),
    upxInspect: async () => ({ ok: true, data: { status: 'ready', operation: 'test', summary: 'UPX validation completed.', recommended_next_tools: [], next_actions: [] } }),
    yaraXScan: async () => ({ ok: true, data: { status: 'ready', match_count: 1, matches: [{ identifier: 'triage_match' }], summary: 'YARA-X found one rule match.', recommended_next_tools: [], next_actions: [] } }),
    rizinAnalyze: async () => ({ ok: true, data: { status: 'ready', operation: 'sections', preview: [{ name: '.text' }], summary: 'Rizin section inspection complete.', recommended_next_tools: [], next_actions: [] } }),
    resolveBackends: createReadyBackends,
  })

  const result = await handler({
    sample_id: sampleId,
    backend_policy: 'prefer_new',
    depth: 'deep',
  })

  assert.equal(result.ok, true)
  assert.ok(result.data.backend_selected.some((item) => item.tool === 'upx.inspect'))
  assert.ok(result.data.backend_selected.some((item) => item.tool === 'yara_x.scan'))
  assert.ok(result.data.backend_selected.some((item) => item.tool === 'rizin.analyze'))
  assert.equal(result.data.raw_results.backend_enrichments.yara_x.match_count, 1)
}

async function runReconstructCorroborationCase() {
  const sampleId = `sha256:${'c'.repeat(64)}`
  await setupSample(sampleId, 'c')

  const handler = createReconstructWorkflowHandler(workspaceManager, database, cacheManager, {
    runtimeDetectHandler: async () => ({
      ok: true,
      data: {
        is_dotnet: false,
        suspected: [{ runtime: 'native', confidence: 0.81, evidence: ['imports'] }],
      },
    }),
    binaryRoleProfileHandler: async () => ({ ok: true, data: createBinaryProfilePayload(sampleId) }),
    dllExportProfileHandler: async () => ({
      ok: true,
      data: {
        library_like: true,
        role_confidence: 0.6,
        likely_entry_model: 'dllmain',
        dll_entry_hints: ['DllMain present'],
        export_dispatch_profile: { likely_dispatch_model: 'exports' },
        host_interaction_profile: { host_hints: [] },
        lifecycle_surface: { exports: [], suspicious_behaviors: [], entry_callbacks: [] },
        class_factory_surface: [],
        callback_surface: [],
        analysis_priorities: [],
      },
    }),
    comRoleProfileHandler: async () => ({
      ok: true,
      data: {
        likely_com_server: false,
        com_confidence: 0.05,
        activation_model: 'none',
        class_factory_exports: [],
        registration_exports: [],
        clsid_strings: [],
        progid_strings: [],
        interface_hints: [],
        class_factory_surface: [],
        activation_steps: [],
        analysis_priorities: [],
      },
    }),
    rustBinaryAnalyzeHandler: async () => ({
      ok: true,
      data: {
        suspected_rust: true,
        confidence: 0.94,
        primary_runtime: 'rust',
        runtime_hints: ['panic_unwind'],
        crate_hints: ['tokio'],
        cargo_paths: [],
        recovered_function_count: 4,
        recovered_symbol_count: 4,
        importable_with_code_functions_define: true,
        analysis_priorities: ['recover_function_index_from_pdata'],
      },
    }),
    functionIndexRecoverHandler: async () => ({
      ok: true,
      data: {
        applied: true,
        define_from: 'smart_recover',
        recovered_function_count: 6,
        recovered_symbol_count: 6,
        imported_count: 6,
        function_index_status: 'ready',
        decompile_status: 'missing',
        cfg_status: 'missing',
        recovery_strategy: ['smart_recover'],
        next_steps: ['export'],
      },
    }),
    planHandler: async () => ({
      ok: true,
      data: {
        feasibility: 'low',
        confidence: 0.44,
        restoration_expectation: 'partial only',
        blockers: ['weak function coverage'],
        recommendations: ['use alternate backends'],
      },
    }),
    nativeExportHandler: async () => ({
      ok: true,
      data: {
        export_root: 'reports/reconstruct/alt',
        manifest_path: 'reports/reconstruct/alt/manifest.json',
        gaps_path: 'reports/reconstruct/alt/gaps.md',
        notes_path: 'reports/reconstruct/alt/reverse_notes.md',
        module_count: 1,
        unresolved_count: 12,
        degraded_mode: true,
        binary_profile: {
          binary_role: 'executable',
          original_filename: 'alt.exe',
          export_count: 0,
          forwarder_count: 0,
          notable_exports: [],
          packed: false,
          packing_confidence: 0.1,
          analysis_priorities: ['recover_functions'],
        },
      },
    }),
    rizinAnalyzeHandler: async () => ({
      ok: true,
      data: { status: 'ready', operation: 'functions', item_count: 12, preview: [{ name: 'sub_140001000' }], summary: 'Rizin function inspection complete.', recommended_next_tools: [], next_actions: [] },
    }),
    angrAnalyzeHandler: async () => ({
      ok: true,
      data: { status: 'ready', analysis: 'cfg_fast', function_count: 18, functions: [{ name: 'entry', address: '0x401000' }], summary: 'angr CFGFast complete.', recommended_next_tools: [], next_actions: [] },
    }),
    retdecDecompileHandler: async () => ({
      ok: true,
      data: { status: 'ready', output_format: 'plain', preview: { inline_text: 'int main() {}', truncated: false, char_count: 14 }, summary: 'RetDec output ready.', recommended_next_tools: [], next_actions: [] },
    }),
    resolveBackends: createReadyBackends,
  })

  const result = await handler({
    sample_id: sampleId,
    path: 'native',
    depth: 'deep',
    backend_policy: 'prefer_new',
  })

  assert.equal(result.ok, true)
  assert.ok(result.data.backend_selected.some((item) => item.tool === 'rizin.analyze'))
  assert.ok(result.data.backend_selected.some((item) => item.tool === 'angr.analyze'))
  assert.ok(result.data.backend_selected.some((item) => item.tool === 'retdec.decompile'))
  assert.equal(result.data.alternate_backends.rizin.operation, 'functions')
  assert.equal(result.data.alternate_backends.angr.analysis, 'cfg_fast')
  assert.equal(result.data.alternate_backends.retdec.output_format, 'plain')
}

try {
  await runAutoRoutingCases()
  await runTriageEnrichmentCase()
  await runReconstructCorroborationCase()
  console.log('intent-driven backend routing integration checks passed')
} finally {
  database.close()
  await fs.rm(tempRoot, { recursive: true, force: true })
}
