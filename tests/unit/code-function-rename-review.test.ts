import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createCodeFunctionRenameReviewHandler } from '../../src/tools/code-function-rename-review.js'
import type { WorkerResult, ToolArgs } from '../../src/types.js'

describe('code.function.rename.review tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-rename-review')
    testDbPath = path.join(process.cwd(), 'test-rename-review.db')
    testCachePath = path.join(process.cwd(), 'test-cache-rename-review')

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
          unresolved_count: 1,
          prompt_name: 'reverse.semantic_name_review',
          prompt_arguments: {
            analysis_goal: 'Review Akasha.',
            prepared_bundle_json: '{"functions":[{"function":"FUN_unresolved"}]}',
          },
          task_prompt: 'Return strict JSON only.',
          artifact: {
            id: 'artifact-prepare',
          },
        },
      })

    const handler = createCodeFunctionRenameReviewHandler(
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
      analysis_goal: 'Review Akasha.',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.review_status).toBe('prompt_contract_only')
    expect(data.client.sampling_available).toBe(false)
    expect(data.prepare.prepared_count).toBe(1)
    expect(data.prompt_name).toBe('reverse.semantic_name_review')
    expect(data.confidence_policy.calibrated).toBe(false)
    expect(data.confidence_policy.rule_priority_over_llm).toBe(true)
    expect(data.confidence_policy.llm_acceptance_threshold).toBe(0.62)
    expect(data.next_steps[0]).toContain('prompts/get')
  })

  test('should require semantic_session_tag when semantic_scope=session', async () => {
    const handler = createCodeFunctionRenameReviewHandler(
      workspaceManager,
      database,
      cacheManager
    )

    const result = await handler({
      sample_id: 'sha256:' + '0'.repeat(64),
      semantic_scope: 'session',
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('semantic_session_tag')
  })

  test('samples, applies, and reruns reconstruct with llm validated names', async () => {
    const prepareHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          prepared_count: 1,
          unresolved_count: 1,
          prompt_name: 'reverse.semantic_name_review',
          prompt_arguments: {
            analysis_goal: 'Review Akasha.',
            prepared_bundle_json: '{"functions":[{"function":"FUN_1400d0580"}]}',
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
    const reconstructHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          reconstructed_count: 1,
          functions: [
            {
              function: 'FUN_1400d0580',
              address: '0x1400d0580',
              name_resolution: {
                validated_name: 'scan_packer_layout_and_signatures',
                resolution_source: 'llm',
              },
            },
          ],
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
          '{"suggestions":[{"address_or_function":"0x1400d0580","candidate_name":"scan_packer_layout_and_signatures","confidence":0.82,"why":"Uses packer strings and scan-oriented evidence.","required_assumptions":["The string cluster belongs to the same control path."],"evidence_used":["strings:Packer/Protector Detection","xref:GetProcAddress"]}]}',
          '```',
        ].join('\n'),
      },
    }))

    const handler = createCodeFunctionRenameReviewHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        prepareHandler,
        applyHandler,
        reconstructHandler,
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
      analysis_goal: 'Review Akasha.',
      session_tag: 'akasha-review',
      evidence_scope: 'session',
      evidence_session_tag: 'runtime-alpha',
      semantic_scope: 'session',
      semantic_session_tag: 'semantic-reference',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.review_status).toBe('sampled_and_applied')
    expect(data.sampling.parsed_suggestion_count).toBe(1)
    expect(data.apply.accepted_count).toBe(1)
    expect(data.reconstruct.llm_or_hybrid_count).toBe(1)
    expect(data.confidence_policy.llm_acceptance_threshold).toBe(0.62)

    expect(applyHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: 'sha256:' + 'b'.repeat(64),
        client_name: 'claude-desktop',
        model_name: 'generic-tool-calling-llm',
        prepare_artifact_id: 'artifact-prepare',
        session_tag: 'akasha-review',
        suggestions: [
          expect.objectContaining({
            address: '0x1400d0580',
            candidate_name: 'scan_packer_layout_and_signatures',
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
        semantic_session_tag: 'semantic-reference',
      })
    )
    expect(reconstructHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: 'sha256:' + 'b'.repeat(64),
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
        semantic_scope: 'session',
        semantic_session_tag: 'semantic-reference',
      })
    )
    expect(samplingRequester).toHaveBeenCalledTimes(1)
    const samplingParams = (samplingRequester.mock.calls as any[][])[0]?.[0] as any
    expect(samplingParams.systemPrompt).toContain('Do not wrap the response in markdown')
    expect(samplingParams.systemPrompt).toContain('Do not call tools')
    expect(samplingParams.systemPrompt).toContain('Preserve uncertainty explicitly')
  })

  test('rerun reconstruct should default to the current naming session when semantic scope is not explicitly narrowed', async () => {
    const prepareHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          prepared_count: 1,
          unresolved_count: 1,
          prompt_name: 'reverse.semantic_name_review',
          prompt_arguments: {
            analysis_goal: 'Review.',
            prepared_bundle_json: '{"functions":[{"function":"FUN_1"}]}',
          },
          task_prompt: 'Return strict JSON only.',
          artifact: { id: 'artifact-prepare' },
        },
      })
    const applyHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          accepted_count: 1,
          rejected_count: 0,
          artifact: { id: 'artifact-apply' },
        },
      })
    const reconstructHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: { reconstructed_count: 0, functions: [] },
      })

    const handler = createCodeFunctionRenameReviewHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        prepareHandler,
        applyHandler,
        reconstructHandler,
        samplingRequester: async () => ({
          role: 'assistant',
          model: 'generic-tool-calling-llm',
          stopReason: 'endTurn',
          content: {
            type: 'text',
            text: '{"suggestions":[{"address_or_function":"0x1400d0580","candidate_name":"scan_layout","confidence":0.8,"why":"ok","required_assumptions":[],"evidence_used":[]}]}',
          },
        }),
        clientCapabilitiesProvider: () => ({ sampling: {} }),
        clientVersionProvider: () => ({ name: 'client', version: '1.0.0' }),
      }
    )

    const result = await handler({
      sample_id: 'sha256:' + 'e'.repeat(64),
      session_tag: 'new-semantic-session',
    })

    expect(result.ok).toBe(true)
    expect(reconstructHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        semantic_scope: 'session',
        semantic_session_tag: 'new-semantic-session',
      })
    )
  })

  test('retries in include_resolved audit mode when unresolved selection is empty', async () => {
    const prepareHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValueOnce({
        ok: true,
        data: {
          prepared_count: 0,
          unresolved_count: 0,
          prompt_name: 'reverse.semantic_name_review',
          prompt_arguments: {
            analysis_goal: 'Audit Akasha.',
            prepared_bundle_json: '{"functions":[]}',
          },
          task_prompt: 'Return strict JSON only.',
        },
      })
      .mockResolvedValueOnce({
        ok: true,
        data: {
          prepared_count: 1,
          unresolved_count: 0,
          prompt_name: 'reverse.semantic_name_review',
          prompt_arguments: {
            analysis_goal: 'Audit Akasha.',
            prepared_bundle_json: '{"functions":[{"function":"FUN_resolved"}]}',
          },
          task_prompt: 'Return strict JSON only.',
          artifact: {
            id: 'artifact-prepare-resolved',
          },
        },
      })

    const handler = createCodeFunctionRenameReviewHandler(
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
      sample_id: 'sha256:' + 'c'.repeat(64),
      analysis_goal: 'Audit Akasha.',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.review_status).toBe('prompt_contract_only')
    expect(data.prepare.include_resolved).toBe(true)
    expect(prepareHandler).toHaveBeenCalledTimes(2)
    expect(result.warnings).toContain(
      'Initial unresolved-only review set was empty; automatically retried in audit mode with include_resolved=true.'
    )
  })
})
