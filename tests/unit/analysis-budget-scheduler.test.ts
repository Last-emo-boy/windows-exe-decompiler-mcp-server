import { describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { AnalysisBudgetScheduler } from '../../src/analysis-budget-scheduler.js'
import { JobQueue, JobPriority } from '../../src/job-queue.js'

describe('analysis budget scheduler', () => {
  test('prioritizes preview work ahead of deep attribution and records deferral reasons', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'analysis-budget-scheduler-'))
    const database = new DatabaseManager(path.join(tempDir, 'test.db'))
    const jobQueue = new JobQueue(database)
    const scheduler = new AnalysisBudgetScheduler(database)

    try {
      database.insertSample({
        id: 'sha256:' + 'a'.repeat(64),
        sha256: 'a'.repeat(64),
        md5: 'a'.repeat(32),
        size: 8 * 1024 * 1024,
        file_type: 'PE32+',
        created_at: new Date().toISOString(),
        source: 'unit-test',
      })
      database.insertSample({
        id: 'sha256:' + 'b'.repeat(64),
        sha256: 'b'.repeat(64),
        md5: 'b'.repeat(32),
        size: 8 * 1024 * 1024,
        file_type: 'PE32+',
        created_at: new Date().toISOString(),
        source: 'unit-test',
      })
      const deepJobId = jobQueue.enqueue({
        type: 'decompile',
        tool: 'workflow.analyze.stage',
        sampleId: 'sha256:' + 'a'.repeat(64),
        args: { run_id: 'run-deep', stage: 'function_map', sample_size_tier: 'large' },
        priority: JobPriority.HIGH,
        timeout: 60_000,
      })
      const previewJobId = jobQueue.enqueue({
        type: 'static',
        tool: 'strings.extract',
        sampleId: 'sha256:' + 'b'.repeat(64),
        args: { mode: 'preview', sample_size_tier: 'large' },
        priority: JobPriority.NORMAL,
        timeout: 15_000,
      })

      const selection = scheduler.selectNextJob(jobQueue)
      expect(selection?.job.id).toBe(previewJobId)
      expect(selection?.plan.execution_bucket).toBe('preview-static')

      const previewEvent = database.findLatestSchedulerEventForJob(previewJobId)
      expect(previewEvent?.decision).toBe('admitted')
      expect(previewEvent?.execution_bucket).toBe('preview-static')
      expect(database.findLatestSchedulerEventForJob(deepJobId)).toBeUndefined()
    } finally {
      database.close()
      fs.rmSync(tempDir, { recursive: true, force: true })
    }
  })

  test('keeps manual-only work deferred and honors deep-lane saturation', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'analysis-budget-scheduler-'))
    const database = new DatabaseManager(path.join(tempDir, 'test.db'))
    const jobQueue = new JobQueue(database)
    const scheduler = new AnalysisBudgetScheduler(database)

    try {
      for (const fill of ['c', 'd', 'e']) {
        database.insertSample({
          id: 'sha256:' + fill.repeat(64),
          sha256: fill.repeat(64),
          md5: fill.repeat(32),
          size: 4 * 1024 * 1024,
          file_type: 'PE32+',
          created_at: new Date().toISOString(),
          source: 'unit-test',
        })
      }
      const runningDeepJobId = jobQueue.enqueue({
        type: 'decompile',
        tool: 'workflow.analyze.stage',
        sampleId: 'sha256:' + 'c'.repeat(64),
        args: { run_id: 'run-1', stage: 'function_map', sample_size_tier: 'medium' },
        priority: JobPriority.HIGH,
        timeout: 60_000,
      })
      jobQueue.startQueuedJob(runningDeepJobId)

      const queuedDeepJobId = jobQueue.enqueue({
        type: 'decompile',
        tool: 'workflow.analyze.stage',
        sampleId: 'sha256:' + 'd'.repeat(64),
        args: { run_id: 'run-2', stage: 'reconstruct', sample_size_tier: 'medium' },
        priority: JobPriority.HIGH,
        timeout: 60_000,
      })
      const manualJobId = jobQueue.enqueue({
        type: 'sandbox',
        tool: 'wine.run',
        sampleId: 'sha256:' + 'e'.repeat(64),
        args: { mode: 'run', approved: true, sample_size_tier: 'medium' },
        priority: JobPriority.NORMAL,
        timeout: 60_000,
      })

      const selection = scheduler.selectNextJob(jobQueue)
      expect(selection).toBeNull()

      const deepEvent = database.findLatestSchedulerEventForJob(queuedDeepJobId)
      expect(deepEvent?.decision).toBe('deferred')
      expect(deepEvent?.reason).toContain('lane_saturated:deep-attribution')

      const manualEvent = database.findLatestSchedulerEventForJob(manualJobId)
      expect(manualEvent?.decision).toBe('deferred')
      expect(manualEvent?.reason).toContain('manual_only_bucket_requires_explicit_approval')
      expect(manualEvent?.execution_bucket).toBe('manual-execution')
    } finally {
      database.close()
      fs.rmSync(tempDir, { recursive: true, force: true })
    }
  })

  test('defers heavy work before control-plane memory headroom is exhausted', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'analysis-budget-scheduler-'))
    const database = new DatabaseManager(path.join(tempDir, 'test.db'))
    const jobQueue = new JobQueue(database)
    const scheduler = new AnalysisBudgetScheduler(database, {
      memoryLimitMb: 1024,
      controlPlaneHeadroomMb: 900,
    })

    try {
      database.insertSample({
        id: 'sha256:' + 'f'.repeat(64),
        sha256: 'f'.repeat(64),
        md5: 'f'.repeat(32),
        size: 64 * 1024 * 1024,
        file_type: 'PE32+',
        created_at: new Date().toISOString(),
        source: 'unit-test',
      })

      const jobId = jobQueue.enqueue({
        type: 'static',
        tool: 'strings.extract',
        sampleId: 'sha256:' + 'f'.repeat(64),
        args: { mode: 'full', sample_size_tier: 'oversized' },
        priority: JobPriority.HIGH,
        timeout: 60_000,
      })

      const selection = scheduler.selectNextJob(jobQueue)
      expect(selection).toBeNull()

      const event = database.findLatestSchedulerEventForJob(jobId)
      expect(event?.decision).toBe('deferred')
      expect(event?.reason).toContain('memory_headroom_guard')
      const metadata = JSON.parse(event?.metadata_json || '{}')
      expect(metadata.expected_rss_mb).toBeGreaterThan(0)
      expect(metadata.memory_limit_mb).toBe(1024)
      expect(metadata.control_plane_headroom_mb).toBe(900)
    } finally {
      database.close()
      fs.rmSync(tempDir, { recursive: true, force: true })
    }
  })
})
