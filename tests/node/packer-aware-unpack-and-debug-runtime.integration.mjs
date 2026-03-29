import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const { WorkspaceManager } = await import('../../dist/workspace-manager.js')
const { DatabaseManager } = await import('../../dist/database.js')
const { CacheManager } = await import('../../dist/cache-manager.js')
const { createReportSummarizeHandler } = await import('../../dist/tools/report-summarize.js')
const { createAnalyzeWorkflowStatusHandler } = await import('../../dist/workflows/analyze-pipeline.js')
const {
  createOrReuseAnalysisRun,
  upsertAnalysisRunStage,
} = await import('../../dist/analysis-run-state.js')
const {
  ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE,
  DEBUG_SESSION_ARTIFACT_TYPE,
  UNPACK_PLAN_ARTIFACT_TYPE,
  buildDynamicBehaviorDiffDigest,
  buildPackedVsUnpackedDiffDigest,
  buildUnpackPlan,
  createDebugSessionRecord,
  persistUnpackDebugJsonArtifact,
  toDatabaseDebugSession,
} = await import('../../dist/unpack-debug-runtime.js')

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'packer-unpack-debug-runtime-'))
const workspaceRoot = path.join(tempRoot, 'workspaces')
const dbPath = path.join(tempRoot, 'test.db')
const cacheRoot = path.join(tempRoot, 'cache')

const workspaceManager = new WorkspaceManager(workspaceRoot)
const database = new DatabaseManager(dbPath)
const cacheManager = new CacheManager(cacheRoot, database)

function readyBackends() {
  return {
    capa_cli: { available: true, source: 'path', path: '/tool/capa', version: '1', checked_candidates: ['capa'], error: null },
    capa_rules: { available: true, source: 'env', path: '/rules/capa', error: null },
    die: { available: true, source: 'path', path: '/tool/diec', version: '1', checked_candidates: ['diec'], error: null },
    graphviz: { available: true, source: 'path', path: '/tool/dot', version: '1', checked_candidates: ['dot'], error: null },
    rizin: { available: true, source: 'path', path: '/tool/rizin', version: '1', checked_candidates: ['rizin'], error: null },
    upx: { available: true, source: 'path', path: '/tool/upx', version: '1', checked_candidates: ['upx'], error: null },
    wine: { available: true, source: 'path', path: '/tool/wine', version: '1', checked_candidates: ['wine'], error: null },
    winedbg: { available: true, source: 'path', path: '/tool/winedbg', version: '1', checked_candidates: ['winedbg'], error: null },
    frida_cli: { available: true, source: 'path', path: '/tool/frida-ps', version: '1', checked_candidates: ['frida-ps'], error: null },
    yara_x: { available: true, source: 'path', path: '/tool/python3', version: '1', checked_candidates: ['python3'], error: null },
    qiling: { available: true, source: 'path', path: '/tool/qiling-python', version: '1', checked_candidates: ['python3'], error: null },
    angr: { available: true, source: 'path', path: '/tool/angr-python', version: '1', checked_candidates: ['python3'], error: null },
    panda: { available: true, source: 'path', path: '/tool/panda-python', version: '1', checked_candidates: ['python3'], error: null },
    retdec: { available: true, source: 'path', path: '/tool/retdec-decompiler', version: '1', checked_candidates: ['retdec-decompiler'], error: null },
  }
}

try {
  const sampleId = `sha256:${'7'.repeat(64)}`
  const sample = {
    id: sampleId,
    sha256: '7'.repeat(64),
    md5: '7'.repeat(32),
    size: 3 * 1024 * 1024,
    file_type: 'PE32+',
    created_at: new Date().toISOString(),
    source: 'integration-test',
  }

  database.insertSample(sample)
  const workspace = await workspaceManager.createWorkspace(sampleId)
  await fs.writeFile(path.join(workspace.original, 'packed.exe'), Buffer.from('MZUPX'))

  const runState = createOrReuseAnalysisRun(database, {
    sample,
    goal: 'dynamic',
    depth: 'balanced',
    backendPolicy: 'auto',
    metadata: {
      allow_transformations: true,
      allow_live_execution: false,
    },
  })

  const unpackPlan = buildUnpackPlan({
    sample,
    packerDetected: true,
    packerConfidence: 0.94,
    packerNames: ['UPX'],
    compilerPackerNames: ['UPX'],
    upxValidationPassed: true,
    upxReady: true,
    rizinReady: true,
    allowTransformations: true,
    allowLiveExecution: false,
  })

  const unpackPlanArtifact = await persistUnpackDebugJsonArtifact(
    workspaceManager,
    database,
    sampleId,
    UNPACK_PLAN_ARTIFACT_TYPE,
    'unpack_plan',
    unpackPlan,
    `analysis/${runState.run.id}`
  )

  upsertAnalysisRunStage(database, {
    runId: runState.run.id,
    stage: 'fast_profile',
    status: 'completed',
    executionState: 'completed',
    tool: 'workflow.analyze.start',
    result: {
      sample_id: sampleId,
      summary: 'Packed sample triage completed.',
      confidence: 0.76,
      threat_level: 'suspicious',
      iocs: {
        suspicious_imports: ['kernel32!LoadLibraryA'],
        suspicious_strings: ['UPX!'],
        yara_matches: ['packer.upx'],
        urls: [],
        ip_addresses: [],
      },
      evidence: ['UPX markers were present in the initial bounded profile.'],
      recommendation: 'Follow the unpack-aware dynamic path before deep reconstruction.',
      raw_results: {
        imports: {
          'kernel32.dll': ['LoadLibraryA'],
        },
        strings: [
          {
            string: 'UPX!',
            offset: 64,
            encoding: 'ascii',
          },
        ],
      },
      packed_state: unpackPlan.packed_state,
      unpack_state: unpackPlan.unpack_state,
      unpack_confidence: unpackPlan.unpack_confidence,
      unpack_plan: unpackPlan,
      debug_state: 'not_requested',
      recommended_next_tools: ['workflow.analyze.promote', 'workflow.analyze.status', 'upx.inspect'],
      next_actions: ['Promote into dynamic_plan before deeper unpack or debug execution.'],
    },
    artifactRefs: [unpackPlanArtifact],
  })

  const plannedDebugSession = createDebugSessionRecord({
    runId: runState.run.id,
    sample,
    status: 'correlated',
    debugState: 'correlated',
    backend: 'frida.trace.capture',
    currentPhase: 'correlation',
    sessionTag: `debug/${runState.run.id}`,
    guidance: {
      recommended_next_tools: ['workflow.summarize', 'report.summarize'],
      next_actions: ['Reuse the bounded debug-session digest instead of reopening raw trace output inline.'],
    },
    metadata: {
      source_stage: 'dynamic_execute',
    },
  })

  const debugSessionArtifact = await persistUnpackDebugJsonArtifact(
    workspaceManager,
    database,
    sampleId,
    DEBUG_SESSION_ARTIFACT_TYPE,
    'debug_session',
    plannedDebugSession,
    plannedDebugSession.session_tag
  )

  const persistedDebugSession = {
    ...plannedDebugSession,
    artifact_refs: [debugSessionArtifact],
  }
  database.insertDebugSession(toDatabaseDebugSession(persistedDebugSession))

  const packedDiff = buildPackedVsUnpackedDiffDigest({
    sampleId,
    beforeRef: unpackPlanArtifact,
    afterRef: {
      id: 'artifact-unpacked',
      type: 'upx_decompress',
      path: 'reports/unpack_execution/debug/sample_unpacked.exe',
      sha256: '8'.repeat(64),
      mime: 'application/octet-stream',
    },
    sizeBefore: sample.size,
    sizeAfter: sample.size + 1024 * 1024,
    importsBefore: ['kernel32!LoadLibraryA'],
    importsAfter: ['kernel32!LoadLibraryA', 'advapi32!RegSetValueExW'],
    stringsBefore: ['UPX!'],
    stringsAfter: ['UPX!', 'http://example.invalid'],
    sectionCountBefore: 3,
    sectionCountAfter: 6,
    sourceArtifactRefs: [unpackPlanArtifact],
  })
  const packedDiffArtifact = await persistUnpackDebugJsonArtifact(
    workspaceManager,
    database,
    sampleId,
    ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE,
    'packed_vs_unpacked_diff',
    packedDiff,
    persistedDebugSession.session_tag
  )

  const dynamicDiff = buildDynamicBehaviorDiffDigest({
    sampleId,
    diffType: 'pre_vs_post_dynamic',
    beforeSummary: {
      observed_apis: ['CreateFileW'],
      stages: ['safe_simulation'],
      risk_hints: ['filesystem'],
    },
    afterSummary: {
      observed_apis: ['CreateFileW', 'WinHttpSendRequest'],
      stages: ['safe_simulation', 'trace_capture'],
      risk_hints: ['filesystem', 'network'],
      summary: 'Network communication became visible after bounded dynamic capture.',
    },
    sourceArtifactRefs: [debugSessionArtifact],
  })
  const dynamicDiffArtifact = await persistUnpackDebugJsonArtifact(
    workspaceManager,
    database,
    sampleId,
    ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE,
    'pre_vs_post_dynamic',
    dynamicDiff,
    persistedDebugSession.session_tag
  )

  upsertAnalysisRunStage(database, {
    runId: runState.run.id,
    stage: 'dynamic_plan',
    status: 'completed',
    executionState: 'completed',
    tool: 'workflow.analyze.stage',
    result: {
      sample_id: sampleId,
      packed_state: unpackPlan.packed_state,
      unpack_state: unpackPlan.unpack_state,
      unpack_confidence: unpackPlan.unpack_confidence,
      unpack_plan: unpackPlan,
      debug_state: persistedDebugSession.debug_state,
      debug_session: persistedDebugSession,
      recommended_next_tools: ['workflow.analyze.status', 'workflow.analyze.promote'],
      next_actions: ['Inspect the persisted debug session before executing further capture.'],
    },
    artifactRefs: [debugSessionArtifact],
  })

  upsertAnalysisRunStage(database, {
    runId: runState.run.id,
    stage: 'dynamic_execute',
    status: 'completed',
    executionState: 'completed',
    tool: 'workflow.analyze.stage',
    result: {
      sample_id: sampleId,
      packed_state: unpackPlan.packed_state,
      unpack_state: 'unpacked',
      unpack_confidence: 0.95,
      unpack_plan: unpackPlan,
      debug_state: persistedDebugSession.debug_state,
      debug_session: persistedDebugSession,
      diff_digests: [packedDiff, dynamicDiff],
      recommended_next_tools: ['workflow.summarize', 'report.summarize'],
      next_actions: ['Use the bounded diff digests instead of reopening raw unpack or trace artifacts inline.'],
    },
    artifactRefs: [packedDiffArtifact, dynamicDiffArtifact, debugSessionArtifact],
  })

  const statusHandler = createAnalyzeWorkflowStatusHandler(database, { resolveBackends: readyBackends })
  const status = await statusHandler({ run_id: runState.run.id })

  assert.equal(status.ok, true)
  assert.equal(status.data.packed_state, 'confirmed_packed')
  assert.equal(status.data.unpack_state, 'unpacked')
  assert.equal(status.data.debug_state, 'correlated')
  assert.ok(status.data.unpack_plan)
  assert.equal(status.data.unpack_plan.strategy, 'upx_decompress')
  assert.ok(Array.isArray(status.data.diff_digests))
  assert.equal(status.data.diff_digests.length, 2)
  assert.ok(status.data.recommended_next_tools.includes('workflow.summarize'))

  const reportHandler = createReportSummarizeHandler(workspaceManager, database, cacheManager)
  const report = await reportHandler({
    sample_id: sampleId,
    mode: 'triage',
    detail_level: 'compact',
  })

  assert.equal(report.ok, true)
  assert.equal(report.data.packed_state, 'confirmed_packed')
  assert.equal(report.data.unpack_state, 'unpacked')
  assert.equal(report.data.debug_state, 'correlated')
  assert.ok(Array.isArray(report.data.unpack_debug_diffs))
  assert.equal(report.data.unpack_debug_diffs.length, 2)
  assert.ok(Array.isArray(report.data.artifact_refs?.supporting))
  assert.ok(report.data.artifact_refs.supporting.some((item) => item.type === ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE))
  assert.ok(
    report.data.unpack_debug_diffs.some((item) => item.diff_type === 'packed_vs_unpacked')
  )
  assert.ok(
    report.data.unpack_debug_diffs.some((item) => item.diff_type === 'pre_vs_post_dynamic')
  )

  console.log('packer-aware unpack/debug runtime integration checks passed')
} finally {
  try {
    database.close()
  } catch {
    // ignore
  }
  await fs.rm(tempRoot, { recursive: true, force: true })
}
