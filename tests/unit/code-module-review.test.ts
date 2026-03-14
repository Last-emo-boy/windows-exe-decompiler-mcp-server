import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createCodeModuleReviewHandler } from '../../src/tools/code-module-review.js'
import type { WorkerResult, ToolArgs } from '../../src/types.js'

describe('code.module.review tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-module-review')
    testDbPath = path.join(process.cwd(), 'test-module-review.db')
    testCachePath = path.join(process.cwd(), 'test-cache-module-review')

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

  test('falls back to prompt contract when the connected MCP client does not advertise sampling', async () => {
    const prepareHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          prepared_count: 2,
          prompt_name: 'reverse.module_reconstruction_review',
          prompt_arguments: {
            analysis_goal: 'Review Akasha modules.',
            prepared_bundle_json: '{"modules":[{"module_name":"process_ops"}]}',
          },
          task_prompt: 'Return strict JSON only.',
          artifact: {
            id: 'artifact-prepare',
          },
        },
      })

    const handler = createCodeModuleReviewHandler(workspaceManager, database, cacheManager, undefined, {
      prepareHandler,
      clientCapabilitiesProvider: () => ({}),
      clientVersionProvider: () => ({
        name: 'generic-mcp-client',
        version: '1.0.0',
      }),
    })

    const result = await handler({
      sample_id: 'sha256:' + 'a'.repeat(64),
      analysis_goal: 'Review Akasha modules.',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.review_status).toBe('prompt_contract_only')
    expect(data.client.sampling_available).toBe(false)
    expect(data.prepare.prepared_count).toBe(2)
    expect(data.prompt_name).toBe('reverse.module_reconstruction_review')
    expect(data.confidence_policy.review_scores_are_heuristic).toBe(true)
  })

  test('samples and applies module review results', async () => {
    const prepareHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          prepared_count: 1,
          prompt_name: 'reverse.module_reconstruction_review',
          prompt_arguments: {
            analysis_goal: 'Review Akasha modules.',
            prepared_bundle_json: '{"modules":[{"module_name":"process_ops"}]}',
          },
          task_prompt: 'Return strict JSON only.',
          artifact: {
            id: 'artifact-prepare',
          },
        },
      })
    const applyHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          accepted_count: 1,
          rejected_count: 0,
          artifact: {
            id: 'artifact-apply',
          },
        },
      })

    const handler = createCodeModuleReviewHandler(workspaceManager, database, cacheManager, undefined, {
      prepareHandler,
      applyHandler,
      samplingRequester: async () => ({
        role: 'assistant',
        model: 'generic-tool-calling-llm',
        stopReason: 'endTurn',
        content: {
          type: 'text',
          text: [
            '```json',
            '{"reviews":[{"module_name":"process_ops","refined_name":"remote_process_operations","summary":"Groups runtime wrappers and remote process access helpers.","role_hint":"Remote process operations and execution transfer.","confidence":0.86,"assumptions":["The grouped helpers share a dispatcher."],"evidence_used":["runtime:prepare_remote_process_access","api:WriteProcessMemory"],"rewrite_guidance":["Split handle acquisition from execution transfer."],"focus_areas":["process_ops"],"priority_functions":["FUN_140081090"]}]}',
            '```',
          ].join('\n'),
        },
      }),
      clientCapabilitiesProvider: () => ({
        sampling: {},
      }),
      clientVersionProvider: () => ({
        name: 'claude-desktop',
        version: '1.2.3',
      }),
    })

    const result = await handler({
      sample_id: 'sha256:' + 'b'.repeat(64),
      analysis_goal: 'Review Akasha modules.',
      session_tag: 'akasha-module-review',
      evidence_scope: 'session',
      evidence_session_tag: 'runtime-alpha',
      semantic_scope: 'session',
      semantic_session_tag: 'semantic-alpha',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.review_status).toBe('sampled_and_applied')
    expect(data.sampling.parsed_review_count).toBe(1)
    expect(data.apply.accepted_count).toBe(1)
    expect(data.confidence_policy.calibrated).toBe(false)

    expect(applyHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: 'sha256:' + 'b'.repeat(64),
        client_name: 'claude-desktop',
        model_name: 'generic-tool-calling-llm',
        prepare_artifact_id: 'artifact-prepare',
        session_tag: 'akasha-module-review',
        reviews: [
          expect.objectContaining({
            module_name: 'process_ops',
            refined_name: 'remote_process_operations',
          }),
        ],
      })
    )
    expect(prepareHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: 'sha256:' + 'b'.repeat(64),
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
        semantic_scope: 'session',
        semantic_session_tag: 'semantic-alpha',
      })
    )
  })
})
