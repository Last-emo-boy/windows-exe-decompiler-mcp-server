import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const { WorkspaceManager } = await import('../../dist/workspace-manager.js')
const { DatabaseManager } = await import('../../dist/database.js')
const { CacheManager } = await import('../../dist/cache-manager.js')
const { PolicyGuard } = await import('../../dist/policy-guard.js')
const { JobQueue } = await import('../../dist/job-queue.js')
const {
  createAnalyzeWorkflowPromoteHandler,
  createAnalyzeWorkflowStartHandler,
  createAnalyzeWorkflowStatusHandler,
} = await import('../../dist/workflows/analyze-pipeline.js')
const { upsertAnalysisRunStage } = await import('../../dist/analysis-run-state.js')
const { createTriageWorkflowHandler } = await import('../../dist/workflows/triage.js')
const { createReportSummarizeHandler } = await import('../../dist/tools/report-summarize.js')
const { createWorkflowSummarizeHandler } = await import('../../dist/workflows/summarize.js')
const { createRizinAnalyzeHandler } = await import('../../dist/tools/docker-backend-tools.js')

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'analysis-runtime-convergence-'))
const workspaceRoot = path.join(tempRoot, 'workspaces')
const dbPath = path.join(tempRoot, 'test.db')
const cacheRoot = path.join(tempRoot, 'cache')
const auditPath = path.join(tempRoot, 'audit.log')

const workspaceManager = new WorkspaceManager(workspaceRoot)
const database = new DatabaseManager(dbPath)
const cacheManager = new CacheManager(cacheRoot, database)
const policyGuard = new PolicyGuard(auditPath)
const jobQueue = new JobQueue(database)

function readyBackends() {
  return {
    capa_cli: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    capa_rules: { available: false, source: 'none', path: null, error: null },
    die: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
    graphviz: { available: true, source: 'path', path: '/tool/dot', version: '1', checked_candidates: ['dot'], error: null },
    rizin: { available: true, source: 'path', path: '/tool/rizin', version: '1', checked_candidates: ['rizin'], error: null },
    upx: { available: true, source: 'path', path: '/tool/upx', version: '1', checked_candidates: ['upx'], error: null },
    wine: { available: true, source: 'path', path: '/tool/wine', version: '1', checked_candidates: ['wine'], error: null },
    winedbg: { available: true, source: 'path', path: '/tool/winedbg', version: '1', checked_candidates: ['winedbg'], error: null },
    frida_cli: { available: true, source: 'path', path: '/tool/frida-ps', version: '1', checked_candidates: ['frida-ps'], error: null },
    yara_x: { available: true, source: 'path', path: '/tool/python', version: '1', checked_candidates: ['python3'], error: null },
    qiling: { available: true, source: 'path', path: '/tool/qiling', version: '1', checked_candidates: ['python3'], error: null },
    angr: { available: true, source: 'path', path: '/tool/angr', version: '1', checked_candidates: ['python3'], error: null },
    panda: { available: true, source: 'path', path: '/tool/panda', version: '1', checked_candidates: ['python3'], error: null },
    retdec: { available: true, source: 'path', path: '/tool/retdec', version: '1', checked_candidates: ['retdec'], error: null },
  }
}

async function seedSample(sampleId, fillChar, size = 8192) {
  database.insertSample({
    id: sampleId,
    sha256: fillChar.repeat(64),
    md5: fillChar.repeat(32),
    size,
    file_type: 'PE32+',
    created_at: new Date().toISOString(),
    source: 'integration-test',
  })
  const workspace = await workspaceManager.createWorkspace(sampleId)
  await fs.writeFile(path.join(workspace.original, 'sample.exe'), Buffer.from(`MZ${fillChar}`))
}

async function verifyBackendEvidenceReuse() {
  const sampleId = `sha256:${'a'.repeat(64)}`
  await seedSample(sampleId, 'a')

  let executeCalls = 0
  const handler = createRizinAnalyzeHandler(workspaceManager, database, {
    resolveBackends: readyBackends,
    executeCommand: async () => {
      executeCalls += 1
      return {
        stdout: JSON.stringify({
          bin: { arch: 'x86', bits: 64 },
          core: { format: 'pe', file: 'sample.exe' },
        }),
        stderr: '',
        exitCode: 0,
        timedOut: false,
      }
    },
  })

  const first = await handler({
    sample_id: sampleId,
    operation: 'info',
    persist_artifact: false,
  })
  const second = await handler({
    sample_id: sampleId,
    operation: 'info',
    persist_artifact: false,
  })

  assert.equal(first.ok, true)
  assert.equal(second.ok, true)
  assert.equal(executeCalls, 1)
  assert.equal(first.data.preview.bin.arch, 'x86')
  assert.ok(second.warnings.some((item) => item.includes('Reused canonical evidence')))
}

async function verifyRunReuseAndFacadeBehavior() {
  const sampleId = `sha256:${'b'.repeat(64)}`
  await seedSample(sampleId, 'b', 2 * 1024 * 1024)

  const callCounts = {
    peFingerprint: 0,
    runtimeDetect: 0,
    peImportsExtract: 0,
    stringsExtract: 0,
    yaraScan: 0,
    packerDetect: 0,
    compilerPackerDetect: 0,
    binaryRoleProfile: 0,
    rizinAnalyze: 0,
  }

  const startHandler = createAnalyzeWorkflowStartHandler(
    workspaceManager,
    database,
    cacheManager,
    policyGuard,
    undefined,
    {
      peFingerprint: async () => {
        callCounts.peFingerprint += 1
        return { ok: true, data: { machine_name: 'IMAGE_FILE_MACHINE_AMD64', sections: [] } }
      },
      runtimeDetect: async () => {
        callCounts.runtimeDetect += 1
        return { ok: true, data: { suspected: [{ runtime: 'native', confidence: 0.7, evidence: ['imports'] }] } }
      },
      peImportsExtract: async () => {
        callCounts.peImportsExtract += 1
        return { ok: true, data: { imports: { 'kernel32.dll': ['WriteProcessMemory'] } } }
      },
      stringsExtract: async () => {
        callCounts.stringsExtract += 1
        return { ok: true, data: { strings: [{ string: 'http://example.invalid', offset: 16, encoding: 'ascii' }] } }
      },
      yaraScan: async () => {
        callCounts.yaraScan += 1
        return { ok: true, data: { matches: [] } }
      },
      packerDetect: async () => {
        callCounts.packerDetect += 1
        return { ok: true, data: { packed: false } }
      },
      compilerPackerDetect: async () => {
        callCounts.compilerPackerDetect += 1
        return {
          ok: true,
          data: {
            status: 'ready',
            summary: {
              compiler_count: 1,
              packer_count: 0,
              protector_count: 0,
              file_type_count: 1,
              likely_primary_file_type: 'PE32+',
            },
          },
        }
      },
      binaryRoleProfile: async () => {
        callCounts.binaryRoleProfile += 1
        return {
          ok: true,
          data: {
            sample_id: sampleId,
            binary_role: 'executable',
            role_confidence: 0.81,
            analysis_priorities: ['recover_functions'],
          },
        }
      },
      rizinAnalyze: async () => {
        callCounts.rizinAnalyze += 1
        return {
          ok: true,
          data: {
            status: 'ready',
            operation: 'info',
            item_count: 1,
            preview: { core: { format: 'pe' } },
            summary: 'Rizin preview complete.',
            recommended_next_tools: [],
            next_actions: [],
          },
        }
      },
      resolveBackends: readyBackends,
    },
    jobQueue
  )

  const first = await startHandler({
    sample_id: sampleId,
    goal: 'triage',
    depth: 'balanced',
  })
  const second = await startHandler({
    sample_id: sampleId,
    goal: 'triage',
    depth: 'balanced',
  })

  assert.equal(first.ok, true)
  assert.equal(second.ok, true)
  assert.equal(first.data.run_id, second.data.run_id)
  assert.equal(second.data.reused, true)
  assert.equal(second.data.execution_state, 'reused')
  assert.ok(Array.isArray(first.data.stage_backend_roles))
  assert.ok(first.data.stage_backend_roles.some((item) => item.stage === 'fast_profile' && item.backend === 'rizin'))
  assert.ok(first.data.provenance_visibility)
  assert.ok(typeof first.data.provenance_visibility.evidence_counts.reused === 'number')
  assert.equal(callCounts.peFingerprint, 1)
  assert.equal(callCounts.stringsExtract, 1)
  assert.equal(callCounts.rizinAnalyze, 1)

  const triageFacade = createTriageWorkflowHandler(workspaceManager, database, cacheManager, {
    analyzeStart: startHandler,
  })
  const triageResult = await triageFacade({ sample_id: sampleId })
  assert.equal(triageResult.ok, true)
  assert.equal(triageResult.data.run_id, first.data.run_id)
  assert.ok(triageResult.data.recommended_next_tools.includes('workflow.analyze.promote'))
  assert.ok(
    triageResult.data.next_actions.some(
      (item) =>
        item.includes('Promote to enrich_static') ||
        item.includes('workflow.analyze.promote') ||
        item.includes('persisted run')
    )
  )
}

async function verifyPromoteStatusAndPersistedSummaries() {
  const sampleId = `sha256:${'c'.repeat(64)}`
  await seedSample(sampleId, 'c', 3 * 1024 * 1024)

  const startHandler = createAnalyzeWorkflowStartHandler(
    workspaceManager,
    database,
    cacheManager,
    policyGuard,
    undefined,
    {
      peFingerprint: async () => ({ ok: true, data: { machine_name: 'IMAGE_FILE_MACHINE_AMD64', sections: [] } }),
      runtimeDetect: async () => ({ ok: true, data: { suspected: [{ runtime: 'native', confidence: 0.7, evidence: ['imports'] }] } }),
      peImportsExtract: async () => ({ ok: true, data: { imports: { 'kernel32.dll': ['CreateRemoteThread'] } } }),
      stringsExtract: async () => ({ ok: true, data: { strings: [{ string: 'cmd.exe /c calc', offset: 32, encoding: 'ascii' }] } }),
      yaraScan: async () => ({ ok: true, data: { matches: [{ rule: 'suspicious_cli' }] } }),
      packerDetect: async () => ({ ok: true, data: { packed: false } }),
      compilerPackerDetect: async () => ({
        ok: true,
        data: {
          status: 'ready',
          summary: {
            compiler_count: 1,
            packer_count: 0,
            protector_count: 0,
            file_type_count: 1,
            likely_primary_file_type: 'PE32+',
          },
          compiler_findings: [],
          packer_findings: [],
          protector_findings: [],
        },
      }),
      binaryRoleProfile: async () => ({
        ok: false,
        errors: ['binary-role profile intentionally omitted in this persisted-summary fixture'],
      }),
      rizinAnalyze: async () => ({
        ok: true,
        data: {
          status: 'ready',
          operation: 'info',
          item_count: 1,
          preview: { core: { format: 'pe' } },
          summary: 'Rizin preview complete.',
          recommended_next_tools: [],
          next_actions: [],
        },
      }),
      resolveBackends: readyBackends,
    },
    jobQueue
  )

  const start = await startHandler({
    sample_id: sampleId,
    goal: 'reverse',
    depth: 'balanced',
  })
  assert.equal(start.ok, true)

  const promoteHandler = createAnalyzeWorkflowPromoteHandler(
    workspaceManager,
    database,
    cacheManager,
    policyGuard,
    undefined,
    {
      resolveBackends: readyBackends,
    },
    jobQueue
  )
  const promote = await promoteHandler({
    run_id: start.data.run_id,
    through_stage: 'enrich_static',
  })
  assert.equal(promote.ok, true)
  assert.equal(promote.data.execution_state, 'queued')
  assert.ok(promote.data.deferred_jobs.some((item) => item.stage === 'enrich_static'))

  const statusHandler = createAnalyzeWorkflowStatusHandler(database, { resolveBackends: readyBackends }, jobQueue)
  const status = await statusHandler({ run_id: start.data.run_id })
  assert.equal(status.ok, true)
  assert.equal(status.data.execution_state, 'queued')
  assert.ok(status.data.recommended_next_tools.includes('workflow.analyze.status'))
  assert.ok(status.data.deferred_jobs.some((item) => item.stage === 'enrich_static'))
  assert.ok(Array.isArray(status.data.provenance_visibility.deferred_domains))

  let unexpectedCalls = 0
  const unexpected = async () => {
    unexpectedCalls += 1
    throw new Error('legacy heavy fallback should not be called')
  }

  const reportHandler = createReportSummarizeHandler(workspaceManager, database, cacheManager, {
    triageHandler: unexpected,
    binaryRoleProfileHandler: unexpected,
    rustBinaryAnalyzeHandler: unexpected,
  })
  const report = await reportHandler({
    sample_id: sampleId,
    mode: 'triage',
    detail_level: 'compact',
    force_refresh: true,
  })
  assert.equal(report.ok, true)
  assert.equal(unexpectedCalls, 0)
  assert.ok(report.warnings.some((item) => item.includes('persisted-state only')))
  assert.ok(report.warnings.some((item) => item.includes('Reused persisted fast_profile stage')))
  assert.ok(report.data.summary.length > 0)

  const summarizeHandler = createWorkflowSummarizeHandler(
    workspaceManager,
    database,
    cacheManager,
    undefined,
    { reportSummarizeHandler: reportHandler }
  )
  const summarize = await summarizeHandler({
    sample_id: sampleId,
    through_stage: 'triage',
    synthesis_mode: 'deterministic',
  })
  assert.equal(summarize.ok, true)
  assert.ok(summarize.data.completed_stages.includes('triage'))
  assert.equal(summarize.data.synthesis.used_existing_stage_artifacts, false)
  assert.ok(summarize.data.stage_artifacts.triage.id)
  assert.equal(summarize.data.persisted_state_visibility.persisted_run_id, start.data.run_id)
}

async function verifyInterruptedStageRecovery() {
  const sampleId = `sha256:${'d'.repeat(64)}`
  await seedSample(sampleId, 'd', 4 * 1024 * 1024)

  const startHandler = createAnalyzeWorkflowStartHandler(
    workspaceManager,
    database,
    cacheManager,
    policyGuard,
    undefined,
    {
      peFingerprint: async () => ({ ok: true, data: { machine_name: 'IMAGE_FILE_MACHINE_AMD64', sections: [] } }),
      runtimeDetect: async () => ({ ok: true, data: { suspected: [{ runtime: 'native', confidence: 0.7, evidence: ['imports'] }] } }),
      peImportsExtract: async () => ({ ok: true, data: { imports: { 'kernel32.dll': ['CreateRemoteThread'] } } }),
      stringsExtract: async () => ({
        ok: true,
        data: {
          strings: [{ string: 'powershell -enc test', offset: 48, encoding: 'ascii' }],
          evidence_state: [
            {
              evidence_family: 'strings',
              backend: 'strings.extract',
              mode: 'preview',
              state: 'fresh',
              source: 'analysis_evidence',
              updated_at: new Date().toISOString(),
              freshness_marker: null,
              reason: 'fresh',
            },
          ],
        },
      }),
      yaraScan: async () => ({ ok: true, data: { matches: [] } }),
      packerDetect: async () => ({ ok: true, data: { packed: false } }),
      compilerPackerDetect: async () => ({
        ok: true,
        data: { status: 'ready', summary: { compiler_count: 1, packer_count: 0, protector_count: 0, file_type_count: 1, likely_primary_file_type: 'PE32+' } },
      }),
      binaryRoleProfile: async () => ({
        ok: true,
        data: {
          sample_id: sampleId,
          binary_role: 'executable',
          role_confidence: 0.7,
          analysis_priorities: ['recover_functions'],
          evidence_state: [
            {
              evidence_family: 'binary_role',
              backend: 'binary.role.profile',
              mode: 'fast',
              state: 'fresh',
              source: 'analysis_evidence',
              updated_at: new Date().toISOString(),
              freshness_marker: null,
              reason: 'fresh',
            },
          ],
        },
      }),
      rizinAnalyze: async () => ({
        ok: true,
        data: { status: 'ready', operation: 'info', item_count: 1, preview: { core: { format: 'pe' } }, summary: 'Rizin preview complete.', recommended_next_tools: [], next_actions: [] },
      }),
      resolveBackends: readyBackends,
    },
    jobQueue
  )

  const start = await startHandler({ sample_id: sampleId, goal: 'reverse', depth: 'balanced' })
  assert.equal(start.ok, true)

  upsertAnalysisRunStage(database, {
    runId: start.data.run_id,
    stage: 'enrich_static',
    status: 'running',
    executionState: 'queued',
    tool: 'workflow.analyze.stage',
    jobId: 'orphan-stage-job',
    metadata: { force_refresh: false },
    startedAt: new Date().toISOString(),
  })

  const statusHandler = createAnalyzeWorkflowStatusHandler(database, { resolveBackends: readyBackends }, jobQueue)
  const status = await statusHandler({ run_id: start.data.run_id })
  assert.equal(status.ok, true)
  assert.equal(status.data.recovery_state, 'recoverable')
  assert.ok(status.data.recoverable_stages.some((stage) => stage.stage === 'enrich_static'))
  assert.equal(status.data.execution_state, 'partial')
}

try {
  await verifyBackendEvidenceReuse()
  await verifyRunReuseAndFacadeBehavior()
  await verifyPromoteStatusAndPersistedSummaries()
  await verifyInterruptedStageRecovery()
  console.log('analysis runtime convergence integration checks passed')
} finally {
  database.close()
  await fs.rm(tempRoot, { recursive: true, force: true })
}
