import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createCodeFunctionExplainReviewHandler } from '../../src/tools/code-function-explain-review.js'
import type { WorkerResult, ToolArgs } from '../../src/types.js'

describe('code.function.explain.review tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-explain-review')
    testDbPath = path.join(process.cwd(), 'test-explain-review.db')
    testCachePath = path.join(process.cwd(), 'test-cache-explain-review')

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
          prepared_count: 1,
          prompt_name: 'reverse.function_explanation_review',
          prompt_arguments: {
            analysis_goal: 'Explain Akasha.',
            prepared_bundle_json: '{"functions":[{"function":"FUN_unresolved"}]}',
          },
          task_prompt: 'Return strict JSON only.',
          artifact: {
            id: 'artifact-prepare',
          },
        },
      })

    const handler = createCodeFunctionExplainReviewHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        prepareHandler,
        clientCapabilitiesProvider: () => ({}),
        clientVersionProvider: () => ({
          name: 'generic-mcp-client',
          version: '1.0.0',
        }),
      }
    )

    const result = await handler({
      sample_id: 'sha256:' + 'a'.repeat(64),
      analysis_goal: 'Explain Akasha.',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.review_status).toBe('prompt_contract_only')
    expect(data.client.sampling_available).toBe(false)
    expect(data.prepare.prepared_count).toBe(1)
    expect(data.prompt_name).toBe('reverse.function_explanation_review')
    expect(data.confidence_policy.explanation_scores_are_heuristic).toBe(true)
  })

  test('samples and applies explanation results', async () => {
    const prepareHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          prepared_count: 1,
          prompt_name: 'reverse.function_explanation_review',
          prompt_arguments: {
            analysis_goal: 'Explain Akasha.',
            prepared_bundle_json: '{"functions":[{"function":"FUN_14008d790"}]}',
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
    const samplingRequester = jest.fn(async (): Promise<any> => ({
      role: 'assistant',
      model: 'generic-tool-calling-llm',
      stopReason: 'endTurn',
      content: {
        type: 'text',
        text: [
          '```json',
          '{"explanations":[{"address_or_function":"0x14008d790","summary":"Resolves dynamic imports and sets up remote-process operations.","behavior":"resolve_dynamic_imports","confidence":0.83,"assumptions":["The helper table is consumed by later process operations."],"evidence_used":["xref:GetProcAddress","runtime:resolve_dynamic_apis"],"rewrite_guidance":["Promote resolved imports into a table.","Split import resolution from staging logic."]}]}',
          '```',
        ].join('\n'),
      },
    }))

    const handler = createCodeFunctionExplainReviewHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        prepareHandler,
        applyHandler,
        samplingRequester: samplingRequester as any,
        clientCapabilitiesProvider: () => ({
          sampling: {},
        }),
        clientVersionProvider: () => ({
          name: 'claude-desktop',
          version: '1.2.3',
        }),
      }
    )

    const result = await handler({
      sample_id: 'sha256:' + 'b'.repeat(64),
      analysis_goal: 'Explain Akasha.',
      session_tag: 'akasha-explain',
      evidence_scope: 'session',
      evidence_session_tag: 'runtime-alpha',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.review_status).toBe('sampled_and_applied')
    expect(data.sampling.parsed_explanation_count).toBe(1)
    expect(data.apply.accepted_count).toBe(1)
    expect(data.confidence_policy.calibrated).toBe(false)

    expect(applyHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: 'sha256:' + 'b'.repeat(64),
        client_name: 'claude-desktop',
        model_name: 'generic-tool-calling-llm',
        prepare_artifact_id: 'artifact-prepare',
        session_tag: 'akasha-explain',
        explanations: [
          expect.objectContaining({
            address_or_function: '0x14008d790',
            behavior: 'resolve_dynamic_imports',
          }),
        ],
      })
    )
    expect(prepareHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: 'sha256:' + 'b'.repeat(64),
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
      })
    )
    expect(samplingRequester).toHaveBeenCalledTimes(1)
    const samplingParams = (samplingRequester.mock.calls as any[][])[0]?.[0] as any
    expect(samplingParams.systemPrompt).toContain('Do not wrap the response in markdown')
    expect(samplingParams.systemPrompt).toContain('Do not call tools')
    expect(samplingParams.systemPrompt).toContain('Preserve uncertainty explicitly')
  })
})
