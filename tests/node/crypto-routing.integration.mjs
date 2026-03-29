import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const { WorkspaceManager } = await import('../../dist/workspace-manager.js')
const { DatabaseManager } = await import('../../dist/database.js')
const { CacheManager } = await import('../../dist/cache-manager.js')
const { createTriageWorkflowHandler } = await import('../../dist/workflows/triage.js')
const { createTraceConditionHandler } = await import('../../dist/tools/trace-condition.js')
const { createCryptoIdentifyHandler } = await import('../../dist/tools/crypto-identify.js')
const { createBreakpointSmartHandler } = await import('../../dist/tools/breakpoint-smart.js')

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'crypto-routing-integration-'))
const workspaceRoot = path.join(tempRoot, 'workspaces')
const dbPath = path.join(tempRoot, 'test.db')
const cacheRoot = path.join(tempRoot, 'cache')

const workspaceManager = new WorkspaceManager(workspaceRoot)
const database = new DatabaseManager(dbPath)
const cacheManager = new CacheManager(cacheRoot, database)

function createUnavailableBackends() {
  return {
    capa_cli: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    capa_rules: { available: false, source: 'none', path: null, error: null },
    die: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    graphviz: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    rizin: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    upx: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    wine: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    winedbg: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    frida_cli: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    yara_x: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    qiling: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    angr: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    panda: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    retdec: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
  }
}

async function setupSample(sampleId) {
  const hashChar = sampleId.at(-1) || 'a'
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

async function runTriageRecommendationCase() {
  const sampleId = `sha256:${'c'.repeat(64)}`
  await setupSample(sampleId)

  const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager, {
    peFingerprint: async () => ({ ok: true, data: { machine_name: 'IMAGE_FILE_MACHINE_AMD64', sections: [] } }),
    runtimeDetect: async () => ({ ok: true, data: { suspected: [{ runtime: 'native', confidence: 0.8, evidence: ['imports'] }], import_dlls: ['advapi32.dll'] } }),
    peImportsExtract: async () => ({ ok: true, data: { imports: { 'advapi32.dll': ['CryptEncrypt'] }, delay_imports: {} } }),
    stringsExtract: async () => ({ ok: true, data: { strings: [{ string: 'AES-256-CBC', offset: 32, encoding: 'ascii' }], summary: { cluster_counts: {}, context_windows: [] } } }),
    yaraScan: async () => ({ ok: true, data: { matches: [] } }),
    staticCapabilityTriage: async () => ({
      ok: true,
      data: {
        behavior_namespaces: ['cryptography/encryption'],
        capability_groups: { crypto: 1 },
        capabilities: [{ name: 'encrypt data', namespace: 'cryptography', group: 'crypto' }],
        summary: 'Recovered cryptographic capability.',
      },
    }),
    peStructureAnalyze: async () => ({ ok: true, data: { imports: { imports: { 'advapi32.dll': ['CryptEncrypt'] } } } }),
    compilerPackerDetect: async () => ({ ok: true, data: { detections: [] } }),
    analysisContextLink: async () => ({
      ok: true,
      data: {
        xref_status: 'available',
        merged_strings: { top_iocs: [], top_decoded: [] },
        function_contexts: [
          {
            function: 'FUN_140023A50',
            address: '0x140023a50',
            top_strings: ['AES-256-CBC'],
            sensitive_apis: ['CryptEncrypt'],
            rationale: ['string:AES-256-CBC'],
          },
        ],
        summary: 'context ready',
        source_artifact_refs: [],
      },
    }),
    resolveBackends: createUnavailableBackends,
  })

  const result = await handler({ sample_id: sampleId, raw_result_mode: 'compact' })
  assert.equal(result.ok, true)
  assert.ok(result.data.recommended_next_tools.includes('crypto.identify'))
  assert.ok(result.data.recommended_next_tools.includes('breakpoint.smart'))
  assert.ok(result.data.recommended_next_tools.includes('trace.condition'))
}

async function runPlannerLeafToolCases() {
  const sampleId = `sha256:${'e'.repeat(64)}`
  await setupSample(sampleId)

  const cryptoHandler = createCryptoIdentifyHandler(workspaceManager, database, cacheManager, {
    stringsExtract: async () => ({
      ok: true,
      data: {
        enriched: {
          records: [
            {
              value: 'AES-256-CBC',
              labels: ['analyst_relevant'],
              categories: ['string'],
              function_refs: [{ address: '0x140023a50', name: 'FUN_140023A50' }],
            },
            {
              value: '637c777bf26b6fc53001672bfed7ab76ca82c97d',
              labels: ['encoded_candidate'],
              categories: ['string'],
              function_refs: [{ address: '0x140023a50', name: 'FUN_140023A50' }],
            },
          ],
        },
      },
    }),
    stringsFlossDecode: async () => ({
      ok: true,
      data: {
        enriched: {
          records: [
            {
              value: 'AES_encrypt',
              labels: ['decoded_signal'],
              categories: ['suspicious_api'],
              function_refs: [{ address: '0x140023a50', name: 'FUN_140023A50' }],
            },
          ],
        },
      },
    }),
    analysisContextLink: async () => ({
      ok: true,
      data: {
        xref_status: 'available',
        function_contexts: [
          {
            function: 'FUN_140023A50',
            address: '0x140023a50',
            top_strings: ['AES-256-CBC'],
            sensitive_apis: ['AES_encrypt'],
            rationale: ['string:AES-256-CBC'],
          },
        ],
        source_artifact_refs: [],
      },
    }),
    peImportsExtract: async () => ({
      ok: true,
      data: {
        imports: {
          'custom.dll': ['AES_encrypt'],
        },
      },
    }),
    staticCapabilityTriage: async () => ({
      ok: true,
      data: {
        behavior_namespaces: ['cryptography/encryption'],
        capability_groups: { crypto: 1 },
        capabilities: [{ name: 'encrypt data', namespace: 'cryptography', group: 'crypto' }],
      },
    }),
    loadDynamicTrace: async () => ({
      observed_apis: ['AES_encrypt'],
    }),
  })

  const cryptoResult = await cryptoHandler({
    sample_id: sampleId,
    persist_artifact: false,
    reuse_cached: false,
  })
  assert.equal(cryptoResult.ok, true)
  assert.equal(cryptoResult.data.algorithms[0].algorithm_family, 'aes')
  assert.ok(cryptoResult.data.recommended_next_tools.includes('breakpoint.smart'))

  const breakpointHandler = createBreakpointSmartHandler(workspaceManager, database, cacheManager, {
    cryptoIdentify: async () => cryptoResult,
    dynamicDependencies: async () => ({
      ok: true,
      data: {
        available_components: ['frida', 'worker'],
        components: {
          frida: { available: true },
          worker: { available: true },
        },
      },
    }),
    loadDynamicTrace: async () => ({
      observed_apis: ['AES_encrypt'],
    }),
  })

  const breakpointResult = await breakpointHandler({
    sample_id: sampleId,
    persist_artifact: false,
    reuse_cached: false,
  })
  assert.equal(breakpointResult.ok, true)
  assert.ok(breakpointResult.data.recommended_breakpoints.length > 0)
  assert.equal(breakpointResult.data.runtime_readiness.ready, true)
}

async function runTracePlannerCase() {
  const sampleId = `sha256:${'d'.repeat(64)}`
  await setupSample(sampleId)

  const handler = createTraceConditionHandler(workspaceManager, database, cacheManager, {
    breakpointSmart: async () => ({
      ok: true,
      data: {
        recommended_breakpoints: [
          {
            kind: 'api_call',
            api: 'CryptEncrypt',
            module: 'advapi32.dll',
            reason: 'CryptEncrypt is a likely crypto transition point',
            confidence: 0.82,
            context_capture: ['rcx', 'rdx', 'return_value'],
            evidence_sources: ['pe.imports.extract:import'],
            dynamic_support: false,
          },
        ],
      },
    }),
    dynamicDependencies: async () => ({
      ok: true,
      data: {
        available_components: ['worker'],
        components: {
          frida: { available: false },
          worker: { available: true },
        },
      },
    }),
  })

  const result = await handler({
    sample_id: sampleId,
    persist_artifact: false,
    reuse_cached: false,
    max_memory_bytes: 96,
    condition: {
      logic: 'all',
      predicates: [
        {
          source: 'buffer_length',
          argument_index: 0,
          operator: 'gte',
          value: 32,
        },
      ],
    },
  })

  assert.equal(result.ok, true)
  assert.equal(result.data.status, 'setup_required')
  assert.equal(result.data.normalized_plan.runtime_mapping.recommended_tool, 'frida.runtime.instrument')
  assert.ok(result.data.capture_summary.includes('stack='))
}

await runTriageRecommendationCase()
await runPlannerLeafToolCases()
await runTracePlannerCase()

console.log('crypto-routing integration passed')
