import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const { WorkspaceManager } = await import('../../dist/workspace-manager.js')
const { DatabaseManager } = await import('../../dist/database.js')
const { CacheManager } = await import('../../dist/cache-manager.js')
const { PolicyGuard } = await import('../../dist/policy-guard.js')
const { createAnalyzeAutoWorkflowHandler } = await import('../../dist/workflows/analyze-auto.js')

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'analysis-coverage-boundaries-'))
const workspaceRoot = path.join(tempRoot, 'workspaces')
const dbPath = path.join(tempRoot, 'test.db')
const cacheRoot = path.join(tempRoot, 'cache')
const auditPath = path.join(tempRoot, 'audit.log')

const workspaceManager = new WorkspaceManager(workspaceRoot)
const database = new DatabaseManager(dbPath)
const cacheManager = new CacheManager(cacheRoot, database)
const policyGuard = new PolicyGuard(auditPath)

try {
  const sampleId = `sha256:${'d'.repeat(64)}`
  database.insertSample({
    id: sampleId,
    sha256: 'd'.repeat(64),
    md5: 'd'.repeat(32),
    size: 25 * 1024 * 1024,
    file_type: 'PE32+',
    created_at: new Date().toISOString(),
    source: 'integration-test',
  })

  const handler = createAnalyzeAutoWorkflowHandler(
    workspaceManager,
    database,
    cacheManager,
    policyGuard,
    undefined,
    {
      deepStaticHandler: async () => ({
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              ok: true,
              data: {
                status: 'queued',
                job_id: 'job-large-static',
                result_mode: 'queued',
                recommended_next_tools: ['task.status'],
                next_actions: ['poll'],
              },
            }),
          },
        ],
        structuredContent: {
          ok: true,
          data: {
            status: 'queued',
            job_id: 'job-large-static',
            result_mode: 'queued',
            recommended_next_tools: ['task.status'],
            next_actions: ['poll'],
          },
        },
      }),
    }
  )

  const result = await handler({
    sample_id: sampleId,
    goal: 'static',
    depth: 'deep',
  })

  assert.equal(result.ok, true)
  assert.equal(result.data.sample_size_tier, 'oversized')
  assert.equal(result.data.analysis_budget_profile, 'balanced')
  assert.equal(result.data.coverage_level, 'static_core')
  assert.equal(result.data.completion_state, 'queued')
  assert.ok(result.data.downgrade_reasons.some((item) => item.includes('downgraded requested deep analysis')))
  assert.ok(result.data.coverage_gaps.some((item) => item.status === 'queued'))
  assert.ok(result.data.upgrade_paths.some((item) => item.tool === 'task.status'))

  console.log('analysis coverage boundaries integration checks passed')
} finally {
  database.close()
  await fs.rm(tempRoot, { recursive: true, force: true })
}
