import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { JobQueue } from '../../src/job-queue.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import {
  createModuleReconstructionReviewWorkflowHandler,
  moduleReconstructionReviewWorkflowInputSchema,
} from '../../src/workflows/module-reconstruction-review.js'

describe('workflow.module_reconstruction_review tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-module-review-workflow')
    testDbPath = path.join(process.cwd(), 'test-module-review-workflow.db')
    testCachePath = path.join(process.cwd(), 'test-cache-module-review-workflow')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
    cacheManager = new CacheManager(testCachePath, database)
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore
    }
    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }
  })

  async function setupSample(sampleId: string, hashChar: string) {
    database.insertSample({
      id: sampleId,
      sha256: hashChar.repeat(64),
      md5: hashChar.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    await workspaceManager.createWorkspace(sampleId)
  }

  test('should apply workflow defaults', () => {
    const parsed = moduleReconstructionReviewWorkflowInputSchema.parse({
      sample_id: 'sha256:' + 'a'.repeat(64),
    })

    expect(parsed.topk).toBe(12)
    expect(parsed.module_limit).toBe(6)
    expect(parsed.evidence_scope).toBe('all')
    expect(parsed.semantic_scope).toBe('all')
    expect(parsed.rerun_export).toBe(true)
    expect(parsed.export_path).toBe('auto')
  })

  test('should enqueue module reconstruction review workflow as async job when queue is provided', async () => {
    const sampleId = 'sha256:' + '9'.repeat(64)
    await setupSample(sampleId, '9')

    const queue = new JobQueue()
    const handler = createModuleReconstructionReviewWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      undefined,
      queue
    )
    const result = await handler({
      sample_id: sampleId,
      evidence_scope: 'latest',
      semantic_scope: 'latest',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('queued')
    expect(data.tool).toBe('workflow.module_reconstruction_review')
    expect(data.sample_id).toBe(sampleId)
    expect(data.job_id).toBeTruthy()
    expect(queue.getStatus(data.job_id)?.status).toBe('queued')
  })

  test('should orchestrate module review and reconstruct export refresh', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)
    await setupSample(sampleId, 'b')

    const moduleReviewHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          review_status: 'sampled_and_applied',
          prompt_name: 'reverse.module_reconstruction_review',
          client: {
            name: 'generic-mcp-client',
            version: '1.0.0',
            sampling_available: true,
          },
          prepare: {
            prepared_count: 3,
            artifact_id: 'artifact-prepare',
          },
          sampling: {
            attempted: true,
            model: 'gpt-5',
            stop_reason: 'endTurn',
            parsed_review_count: 1,
          },
          apply: {
            attempted: true,
            accepted_count: 1,
            rejected_count: 0,
            artifact_id: 'artifact-apply',
          },
          confidence_policy: {
            calibrated: false,
            review_scores_are_heuristic: true,
            meaning: 'heuristic only',
          },
          next_steps: ['rerun export'],
        },
      })

    const reconstructWorkflowHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          selected_path: 'native',
          preflight: {
            binary_profile: null,
            rust_profile: null,
            function_index_recovery: null,
          },
          provenance: {
            runtime: {
              scope: 'all',
              session_selector: null,
              artifact_count: 0,
              artifact_ids: [],
              session_tags: [],
              earliest_artifact_at: null,
              latest_artifact_at: null,
              scope_note: 'none',
            },
          },
          selection_diffs: null,
          export: {
            tool: 'code.reconstruct.export',
            export_root: 'reports/reconstruct/demo',
            manifest_path: 'reports/reconstruct/demo/manifest.json',
            build_validation_status: 'skipped',
            harness_validation_status: 'skipped',
          },
          notes: ['export refreshed'],
        },
      })

    const handler = createModuleReconstructionReviewWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        moduleReviewHandler,
        reconstructWorkflowHandler,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      session_tag: 'module-review-session',
      rerun_export: true,
      semantic_scope: 'latest',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.review.review_status).toBe('sampled_and_applied')
    expect(data.export.status).toBe('completed')
    expect(data.export.selected_path).toBe('native')
    expect(data.export.export_tool).toBe('code.reconstruct.export')
    expect(data.next_steps).toContain('export refreshed')

    expect(reconstructWorkflowHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: sampleId,
        semantic_scope: 'latest',
        semantic_session_tag: 'module-review-session',
      })
    )
  })
})
