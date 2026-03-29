import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const { WorkspaceManager } = await import('../../dist/workspace-manager.js')
const { DatabaseManager } = await import('../../dist/database.js')
const { CacheManager } = await import('../../dist/cache-manager.js')
const { createReportSummarizeHandler } = await import('../../dist/tools/report-summarize.js')
const {
  createOrReuseAnalysisRun,
  upsertAnalysisRunStage,
} = await import('../../dist/analysis-run-state.js')

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'large-sample-runtime-'))
const workspaceRoot = path.join(tempRoot, 'workspaces')
const dbPath = path.join(tempRoot, 'test.db')
const cacheRoot = path.join(tempRoot, 'cache')

const workspaceManager = new WorkspaceManager(workspaceRoot)
const database = new DatabaseManager(dbPath)
const cacheManager = new CacheManager(cacheRoot, database)

try {
  const sampleId = `sha256:${'9'.repeat(64)}`
  const sample = {
    id: sampleId,
    sha256: '9'.repeat(64),
    md5: '9'.repeat(32),
    size: 64 * 1024 * 1024,
    file_type: 'PE32 executable',
    created_at: new Date().toISOString(),
    source: 'integration-test',
  }

  database.insertSample(sample)
  await workspaceManager.createWorkspace(sampleId)

  const runState = createOrReuseAnalysisRun(database, {
    sample,
    goal: 'triage',
    depth: 'balanced',
    backendPolicy: 'auto',
  })

  upsertAnalysisRunStage(database, {
    runId: runState.run.id,
    stage: 'fast_profile',
    status: 'completed',
    executionState: 'completed',
    tool: 'workflow.analyze.start',
    result: {
      sample_id: sampleId,
      summary: 'Large-sample fast profile is already persisted.',
      confidence: 0.72,
      threat_level: 'suspicious',
      iocs: {
        suspicious_imports: ['kernel32!CreateFileW'],
        suspicious_strings: ['cmd.exe'],
        yara_matches: ['rule.large.sample'],
        urls: [],
        ip_addresses: [],
      },
      evidence: ['preview evidence'],
      recommendation: 'Promote deeper stages only as needed.',
      raw_results: {},
    },
    artifactRefs: [],
  })

  const handler = createReportSummarizeHandler(workspaceManager, database, cacheManager)
  const result = await handler({
    sample_id: sampleId,
    mode: 'triage',
    detail_level: 'full',
  })

  assert.equal(result.ok, true)
  assert.equal(result.data?.detail_level, 'compact')
  assert.ok(result.warnings?.some((item) => item.includes('downgraded to compact')))
} finally {
  try {
    database.close()
  } catch {
    // ignore
  }
  await fs.rm(tempRoot, { recursive: true, force: true })
}
