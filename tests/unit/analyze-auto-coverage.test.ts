import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { createAnalyzeAutoWorkflowHandler } from '../../src/workflows/analyze-auto.js'

describe('workflow.analyze.auto coverage boundaries', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let policyGuard: PolicyGuard
  let tempRoot: string

  beforeEach(async () => {
    tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'analyze-auto-coverage-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'test.db'))
    cacheManager = new CacheManager(path.join(tempRoot, 'cache'), database)
    policyGuard = new PolicyGuard(path.join(tempRoot, 'audit.log'))
  })

  afterEach(async () => {
    database.close()
    await fs.promises.rm(tempRoot, { recursive: true, force: true })
  })

  test('should expose quick coverage boundaries for triage routing', async () => {
    const sampleId = `sha256:${'1'.repeat(64)}`
    database.insertSample({
      id: sampleId,
      sha256: '1'.repeat(64),
      md5: '1'.repeat(32),
      size: 512 * 1024,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

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
            summary: 'Quick triage summary.',
            recommended_next_tools: ['ghidra.analyze'],
            next_actions: ['continue'],
            goal: 'triage',
            depth: 'balanced',
            backend_policy: 'auto',
            backend_considered: [],
            backend_selected: [],
            backend_skipped: [],
            backend_escalation_reasons: [],
            manual_only_backends: [],
          },
        }),
      }
    )

    const result = await handler({ sample_id: sampleId, goal: 'triage' })
    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.coverage_level).toBe('quick')
    expect(data.completion_state).toBe('bounded')
    expect(data.coverage_gaps.some((item: any) => item.domain === 'ghidra_analysis')).toBe(true)
    expect(data.upgrade_paths.some((item: any) => item.tool === 'ghidra.analyze')).toBe(true)
  })

  test('should expose queued bounded coverage for large static routing', async () => {
    const sampleId = `sha256:${'2'.repeat(64)}`
    database.insertSample({
      id: sampleId,
      sha256: '2'.repeat(64),
      md5: '2'.repeat(32),
      size: 12 * 1024 * 1024,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'unit-test',
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
                  job_id: 'job-static-1',
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
              job_id: 'job-static-1',
              result_mode: 'queued',
              recommended_next_tools: ['task.status'],
              next_actions: ['poll'],
            },
          },
        }),
      }
    )

    const result = await handler({ sample_id: sampleId, goal: 'static', depth: 'deep' })
    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.coverage_level).toBe('static_core')
    expect(data.completion_state).toBe('queued')
    expect(data.sample_size_tier).toBe('large')
    expect(data.analysis_budget_profile).toBe('balanced')
    expect(data.coverage_gaps.some((item: any) => item.status === 'queued')).toBe(true)
    expect(data.upgrade_paths[0].tool).toBe('task.status')
  })

  test('should expose completed reconstruction coverage for deep reverse routing', async () => {
    const sampleId = `sha256:${'3'.repeat(64)}`
    database.insertSample({
      id: sampleId,
      sha256: '3'.repeat(64),
      md5: '3'.repeat(32),
      size: 900 * 1024,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const handler = createAnalyzeAutoWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      {
        reconstructHandler: async () => ({
          ok: true,
          data: {
            selected_path: 'native',
            degraded: false,
            result_mode: 'completed',
            recommended_next_tools: ['artifact.read'],
            next_actions: ['inspect export'],
            goal: 'reverse',
            depth: 'deep',
            backend_policy: 'auto',
            backend_considered: [],
            backend_selected: [],
            backend_skipped: [],
            backend_escalation_reasons: [],
            manual_only_backends: [],
          },
        }),
      }
    )

    const result = await handler({ sample_id: sampleId, goal: 'reverse', depth: 'deep' })
    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.coverage_level).toBe('reconstruction')
    expect(data.completion_state).toBe('completed')
    expect(data.sample_size_tier).toBe('small')
    expect(data.upgrade_paths.some((item: any) => item.tool === 'artifact.read')).toBe(true)
  })
})
