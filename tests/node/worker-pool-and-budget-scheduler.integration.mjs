import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const { DatabaseManager } = await import('../../dist/database.js')
const { JobQueue, JobPriority } = await import('../../dist/job-queue.js')
const {
  AnalysisBudgetScheduler,
} = await import('../../dist/analysis-budget-scheduler.js')
const {
  RuntimeWorkerPool,
  buildRizinPreviewCompatibilityKey,
} = await import('../../dist/runtime-worker-pool.js')
const { createTaskStatusHandler } = await import('../../dist/tools/task-status.js')

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'worker-pool-budget-integration-'))
const database = new DatabaseManager(path.join(tempRoot, 'test.db'))
const jobQueue = new JobQueue(database)

function parseStructured(result) {
  return result.structuredContent
}

function insertSample(fill, size = 4 * 1024 * 1024) {
  database.insertSample({
    id: 'sha256:' + fill.repeat(64),
    sha256: fill.repeat(64),
    md5: fill.repeat(32),
    size,
    file_type: 'PE32+',
    created_at: new Date().toISOString(),
    source: 'integration-test',
  })
}

async function verifyWarmReuseIntegration() {
  const pool = new RuntimeWorkerPool()
  let createdWorkers = 0

  pool.buildDeploymentKey = () => 'deploy-shared'
  pool.createWorker = function createWorker(family, compatibilityKey, deploymentKey) {
    const worker = {
      id: `worker-${++createdWorkers}`,
      family,
      compatibilityKey,
      deploymentKey,
      child: {
        kill() {},
      },
      busy: false,
      unhealthy: false,
      createdAt: new Date().toISOString(),
      lastUsedAt: new Date().toISOString(),
      stdoutBuffer: '',
    }
    this.workers.set(worker.id, worker)
    return worker
  }
  pool.sendRequest = async function sendRequest(_worker, request) {
    return {
      job_id: request.job_id,
      ok: true,
      warnings: [],
      errors: [],
      data: {
        echo: request.command,
      },
      artifacts: [],
      metrics: {},
    }
  }

  const compatibilityKey = buildRizinPreviewCompatibilityKey({
    backendPath: '/tool/rizin',
    backendVersion: '0.8.2',
    operation: 'info',
    helperPath: '/workers/rizin_preview_worker.py',
  })
  const spawnConfig = {
    command: 'python3',
    args: ['/workers/rizin_preview_worker.py'],
  }

  const first = await pool.executeHelperWorker(
    {
      job_id: 'rizin-job-1',
      backend_path: '/tool/rizin',
      sample_path: '/tmp/sample.exe',
      command: 'ij',
      timeout_ms: 1000,
    },
    {
      database,
      family: 'rizin.preview',
      compatibilityKey,
      spawnConfig,
      timeoutMs: 1000,
    }
  )
  const second = await pool.executeHelperWorker(
    {
      job_id: 'rizin-job-2',
      backend_path: '/tool/rizin',
      sample_path: '/tmp/sample.exe',
      command: 'ij',
      timeout_ms: 1000,
    },
    {
      database,
      family: 'rizin.preview',
      compatibilityKey,
      spawnConfig,
      timeoutMs: 1000,
    }
  )

  assert.equal(createdWorkers, 1)
  assert.equal(first.lease.cold_start, true)
  assert.equal(first.lease.warm_reuse, false)
  assert.equal(second.lease.cold_start, false)
  assert.equal(second.lease.warm_reuse, true)

  const familyStates = database.findRuntimeWorkerFamilyStates('rizin.preview')
  assert.ok(familyStates.length > 0)
  assert.ok(familyStates[0].cold_start_count >= 1)
  assert.ok(familyStates[0].warm_reuse_count >= 1)
}

async function verifyBudgetDeferralAndDeepLaneIsolation() {
  const scheduler = new AnalysisBudgetScheduler(database)
  insertSample('a')
  insertSample('b', 8 * 1024 * 1024)
  insertSample('c', 8 * 1024 * 1024)

  const runningDeepJobId = jobQueue.enqueue({
    type: 'decompile',
    tool: 'workflow.analyze.stage',
    sampleId: 'sha256:' + 'a'.repeat(64),
    args: { run_id: 'run-a', stage: 'function_map', sample_size_tier: 'medium' },
    priority: JobPriority.HIGH,
    timeout: 60_000,
  })
  jobQueue.startQueuedJob(runningDeepJobId)

  const previewJobId = jobQueue.enqueue({
    type: 'static',
    tool: 'strings.extract',
    sampleId: 'sha256:' + 'b'.repeat(64),
    args: { mode: 'preview', sample_size_tier: 'large' },
    priority: JobPriority.NORMAL,
    timeout: 15_000,
  })
  const blockedDeepJobId = jobQueue.enqueue({
    type: 'decompile',
    tool: 'workflow.analyze.stage',
    sampleId: 'sha256:' + 'c'.repeat(64),
    args: { run_id: 'run-b', stage: 'reconstruct', sample_size_tier: 'large' },
    priority: JobPriority.HIGH,
    timeout: 60_000,
  })

  const selection = scheduler.selectNextJob(jobQueue)
  assert.equal(selection?.job.id, previewJobId)
  assert.equal(selection?.plan.execution_bucket, 'preview-static')
  jobQueue.startQueuedJob(previewJobId)

  const secondSelection = scheduler.selectNextJob(jobQueue)
  assert.equal(secondSelection, null)

  const blockedDeepEvent = database.findLatestSchedulerEventForJob(blockedDeepJobId)
  assert.equal(blockedDeepEvent?.decision, 'deferred')
  assert.match(blockedDeepEvent?.reason || '', /lane_saturated:deep-attribution/)

  const taskStatusHandler = createTaskStatusHandler(jobQueue, database)
  const taskStatus = parseStructured(await taskStatusHandler({ job_id: blockedDeepJobId }))
  assert.equal(taskStatus.ok, true)
  assert.equal(taskStatus.data.job.execution_bucket, 'deep-attribution')
  assert.equal(taskStatus.data.job.scheduler_decision, 'deferred')
  assert.match(taskStatus.data.job.budget_deferral_reason || '', /lane_saturated:deep-attribution/)
}

try {
  await verifyWarmReuseIntegration()
  await verifyBudgetDeferralAndDeepLaneIsolation()
  console.log('worker pool and budget scheduler integration checks passed')
} finally {
  database.close()
  await fs.rm(tempRoot, { recursive: true, force: true })
}
