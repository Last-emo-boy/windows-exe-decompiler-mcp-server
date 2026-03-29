import fs from 'fs'
import { JobQueue } from '../../src/job-queue.js'
import { DatabaseManager } from '../../src/database.js'
import { createTaskStatusHandler } from '../../src/tools/task-status.js'
import { createTaskCancelHandler } from '../../src/tools/task-cancel.js'
import { createTaskSweepHandler } from '../../src/tools/task-sweep.js'

function parseToolText(result: { content: Array<{ text?: string }> }): any {
  return JSON.parse(result.content[0]?.text || '{}')
}

describe('task tools', () => {
  test('task.status should list queued jobs', async () => {
    const queue = new JobQueue()
    const statusHandler = createTaskStatusHandler(queue)

    queue.enqueue({
      type: 'decompile',
      tool: 'ghidra.analyze',
      sampleId: 'sha256:test',
      args: {},
      priority: 5,
      timeout: 30_000,
    })

    const result = await statusHandler({ limit: 10 })
    const payload = parseToolText(result)

    expect(payload.ok).toBe(true)
    expect(payload.data.total_jobs).toBe(1)
    expect(payload.data.jobs.length).toBe(1)
    expect(payload.data.jobs[0].status).toBe('queued')
    expect(payload.data.jobs[0].polling_guidance.recommended_wait_seconds).toBeGreaterThan(0)
    expect(payload.data.polling_guidance.prefer_sleep).toBe(true)
    expect(payload.data.result_mode).toBe('queue_summary')
    expect(payload.data.next_actions[0]).toContain('polling_guidance')
    expect((result as any).structuredContent.data.result_mode).toBe('queue_summary')
  })

  test('task.cancel should cancel queued job', async () => {
    const queue = new JobQueue()
    const cancelHandler = createTaskCancelHandler(queue)
    const statusHandler = createTaskStatusHandler(queue)

    const jobId = queue.enqueue({
      type: 'decompile',
      tool: 'ghidra.analyze',
      sampleId: 'sha256:test',
      args: {},
      priority: 5,
      timeout: 30_000,
    })

    const cancelResult = await cancelHandler({ job_id: jobId, reason: 'user requested stop' })
    const cancelPayload = parseToolText(cancelResult)
    expect(cancelPayload.ok).toBe(true)
    expect(cancelPayload.data.cancelled).toBe(true)

    const statusResult = await statusHandler({ job_id: jobId })
    const statusPayload = parseToolText(statusResult)
    expect(statusPayload.data.job.status).toBe('cancelled')
    expect(statusPayload.data.job.error).toContain('Cancelled')
    expect(statusPayload.data.job.polling_guidance).toBeNull()
    expect(statusPayload.data.result_mode).toBe('job_lookup')
  })

  test('task.sweep should clear old finished records', async () => {
    const queue = new JobQueue()
    const sweepHandler = createTaskSweepHandler(queue)

    const jobId = queue.enqueue({
      type: 'decompile',
      tool: 'ghidra.analyze',
      sampleId: 'sha256:test',
      args: {},
      priority: 5,
      timeout: 30_000,
    })
    queue.cancel(jobId, 'test cleanup')

    const sweepResult = await sweepHandler({
      stale_running_ms: 60_000,
      clear_finished_older_ms: 60_000,
    })
    const sweepPayload = parseToolText(sweepResult)

    expect(sweepPayload.ok).toBe(true)
    expect(sweepPayload.data.cleared_finished_count).toBeGreaterThanOrEqual(0)
  })

  test('task.sweep should reap stale persisted analyses', async () => {
    const dbPath = './test-task-sweep.db'
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath)
    }

    const database = new DatabaseManager(dbPath)
    const queue = new JobQueue()
    const sweepHandler = createTaskSweepHandler(queue, database)

    database.insertSample({
      id: 'sha256:' + 'a'.repeat(64),
      sha256: 'a'.repeat(64),
      md5: 'b'.repeat(32),
      size: 128,
      file_type: 'PE32',
      created_at: new Date().toISOString(),
      source: 'test',
    })
    database.insertAnalysis({
      id: 'analysis-stale',
      sample_id: 'sha256:' + 'a'.repeat(64),
      stage: 'ghidra',
      backend: 'ghidra',
      status: 'running',
      started_at: '2024-01-01T00:00:00Z',
      finished_at: null,
      output_json: JSON.stringify({}),
      metrics_json: JSON.stringify({}),
    })

    const sweepResult = await sweepHandler({
      stale_running_ms: 1000,
      clear_finished_older_ms: 60_000,
    })
    const sweepPayload = parseToolText(sweepResult)

    expect(sweepPayload.ok).toBe(true)
    expect(sweepPayload.data.reaped_persisted_analysis_count).toBe(1)
    expect(sweepPayload.data.reaped_persisted_analyses).toContain('analysis-stale')

    database.close()
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath)
    }
  })

  test('task.sweep should not reap running jobs or analyses when stale_running_ms is omitted', async () => {
    const dbPath = './test-task-sweep-no-stale.db'
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath)
    }

    const database = new DatabaseManager(dbPath)
    const queue = new JobQueue()
    const sweepHandler = createTaskSweepHandler(queue, database)

    database.insertSample({
      id: 'sha256:' + 'c'.repeat(64),
      sha256: 'c'.repeat(64),
      md5: 'd'.repeat(32),
      size: 128,
      file_type: 'PE32',
      created_at: new Date().toISOString(),
      source: 'test',
    })
    database.insertAnalysis({
      id: 'analysis-running',
      sample_id: 'sha256:' + 'c'.repeat(64),
      stage: 'ghidra',
      backend: 'ghidra',
      status: 'running',
      started_at: '2024-01-01T00:00:00Z',
      finished_at: null,
      output_json: JSON.stringify({}),
      metrics_json: JSON.stringify({}),
    })

    const jobId = queue.enqueue({
      type: 'decompile',
      tool: 'ghidra.analyze',
      sampleId: 'sha256:test',
      args: {},
      priority: 5,
      timeout: 30_000,
    })
    queue.dequeue()

    const sweepResult = await sweepHandler({
      clear_finished_older_ms: 60_000,
    })
    const sweepPayload = parseToolText(sweepResult)

    expect(sweepPayload.ok).toBe(true)
    expect(sweepPayload.data.reaped_count).toBe(0)
    expect(sweepPayload.data.reaped_persisted_analysis_count).toBe(0)
    expect(queue.getStatus(jobId)?.status).toBe('running')
    expect(database.findAnalysis('analysis-running')?.status).toBe('running')

    database.close()
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath)
    }
  })
})
