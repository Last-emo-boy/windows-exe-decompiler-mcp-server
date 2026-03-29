import { describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { JobQueue } from '../../src/job-queue.js'
import {
  createOrReuseAnalysisRun,
  getAnalysisRunSummary,
  upsertAnalysisRunStage,
} from '../../src/analysis-run-state.js'

describe('runtime hardening', () => {
  test('reconciles orphaned queued and running stages into recoverable state', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runtime-hardening-'))
    const dbPath = path.join(tempDir, 'test.db')
    const database = new DatabaseManager(dbPath)
    const jobQueue = new JobQueue(database)

    try {
      const sample = {
        id: 'sha256:' + 'f'.repeat(64),
        sha256: 'f'.repeat(64),
        md5: 'f'.repeat(32),
        size: 8 * 1024 * 1024,
        file_type: 'PE32+',
        created_at: new Date().toISOString(),
        source: 'unit-test',
      }
      database.insertSample(sample)

      const runState = createOrReuseAnalysisRun(database, {
        sample,
        goal: 'reverse',
        depth: 'balanced',
        backendPolicy: 'auto',
      })

      upsertAnalysisRunStage(database, {
        runId: runState.run.id,
        stage: 'enrich_static',
        status: 'queued',
        executionState: 'queued',
        tool: 'workflow.analyze.stage',
        jobId: 'job-enrich',
      })
      upsertAnalysisRunStage(database, {
        runId: runState.run.id,
        stage: 'function_map',
        status: 'running',
        executionState: 'queued',
        tool: 'workflow.analyze.stage',
        jobId: 'job-function-map',
        startedAt: new Date().toISOString(),
      })

      const summary = getAnalysisRunSummary(database, runState.run.id, jobQueue)
      expect(summary).not.toBeNull()
      expect(summary?.recovery_state).toBe('recoverable')
      expect(summary?.recoverable_stages.map((stage) => stage.stage)).toEqual(
        expect.arrayContaining(['enrich_static', 'function_map'])
      )

      const enrichStage = summary?.stages.find((stage) => stage.stage === 'enrich_static')
      const functionMapStage = summary?.stages.find((stage) => stage.stage === 'function_map')
      expect(enrichStage?.status).toBe('recoverable')
      expect(enrichStage?.recovery_state).toBe('recoverable')
      expect(functionMapStage?.status).toBe('interrupted')
      expect(functionMapStage?.recovery_state).toBe('interrupted')
    } finally {
      database.close()
      fs.rmSync(tempDir, { recursive: true, force: true })
    }
  })
})
