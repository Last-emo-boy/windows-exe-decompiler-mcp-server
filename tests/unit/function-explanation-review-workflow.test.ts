import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { JobQueue } from '../../src/job-queue.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import {
  createFunctionExplanationReviewWorkflowHandler,
  functionExplanationReviewWorkflowInputSchema,
} from '../../src/workflows/function-explanation-review.js'

describe('workflow.function_explanation_review tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-function-explanation-review-workflow')
    testDbPath = path.join(process.cwd(), 'test-function-explanation-review-workflow.db')
    testCachePath = path.join(process.cwd(), 'test-cache-function-explanation-review-workflow')

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
    const parsed = functionExplanationReviewWorkflowInputSchema.parse({
      sample_id: 'sha256:' + 'a'.repeat(64),
    })

    expect(parsed.topk).toBe(6)
    expect(parsed.max_functions).toBe(6)
    expect(parsed.include_resolved).toBe(true)
    expect(parsed.evidence_scope).toBe('all')
    expect(parsed.rerun_export).toBe(true)
    expect(parsed.export_path).toBe('auto')
    expect(parsed.include_preflight).toBe(true)
    expect(parsed.auto_recover_function_index).toBe(true)
  })

  test('should require evidence_session_tag when evidence_scope=session', () => {
    expect(() =>
      functionExplanationReviewWorkflowInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        evidence_scope: 'session',
      })
    ).toThrow('evidence_session_tag')
  })

  test('should require compare_evidence_session_tag when compare_evidence_scope=session', () => {
    expect(() =>
      functionExplanationReviewWorkflowInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        compare_evidence_scope: 'session',
      })
    ).toThrow('compare_evidence_session_tag')
  })

  test('should require compare_semantic_session_tag when compare_semantic_scope=session', () => {
    expect(() =>
      functionExplanationReviewWorkflowInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        compare_semantic_scope: 'session',
      })
    ).toThrow('compare_semantic_session_tag')
  })

  test('should enqueue function explanation review workflow as async job when queue is provided', async () => {
    const sampleId = 'sha256:' + '8'.repeat(64)
    await setupSample(sampleId, '8')

    const queue = new JobQueue()
    const handler = createFunctionExplanationReviewWorkflowHandler(
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
    expect(data.tool).toBe('workflow.function_explanation_review')
    expect(data.sample_id).toBe(sampleId)
    expect(data.job_id).toBeTruthy()
    expect(queue.getStatus(data.job_id)?.status).toBe('queued')
  })

  test('should orchestrate explanation review and reconstruct export refresh', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)
    await setupSample(sampleId, 'b')

    const explainReviewHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          review_status: 'sampled_and_applied',
          prompt_name: 'reverse.function_explanation_review',
          client: {
            name: 'generic-mcp-client',
            version: '1.0.0',
            sampling_available: true,
          },
          prepare: {
            prepared_count: 2,
            artifact_id: 'artifact-prepare',
          },
          sampling: {
            attempted: true,
            model: 'gpt-5',
            stop_reason: 'endTurn',
            parsed_explanation_count: 1,
          },
          apply: {
            attempted: true,
            accepted_count: 1,
            rejected_count: 0,
            artifact_id: 'artifact-apply',
          },
          confidence_policy: {
            calibrated: false,
            explanation_scores_are_heuristic: true,
            meaning: 'Explanation confidence ranks evidence support only.',
          },
          next_steps: ['rerun code.reconstruct.export to propagate explanation summaries into rewrite output'],
        },
      })

    const reconstructWorkflowHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          selected_path: 'native',
          preflight: {
            binary_profile: {
              sample_id: sampleId,
              original_filename: 'explained.exe',
              binary_role: 'executable',
              role_confidence: 0.8,
              runtime_hint: {
                is_dotnet: false,
                dotnet_version: null,
                target_framework: null,
                primary_runtime: 'rust',
              },
              export_surface: {
                total_exports: 0,
                total_forwarders: 0,
                notable_exports: [],
                com_related_exports: [],
                service_related_exports: [],
                plugin_related_exports: [],
                forwarded_exports: [],
              },
              import_surface: {
                dll_count: 2,
                notable_dlls: ['kernel32.dll'],
                com_related_imports: [],
                service_related_imports: [],
                network_related_imports: [],
                process_related_imports: ['WriteProcessMemory'],
              },
              packed: false,
              packing_confidence: 0.04,
              indicators: {
                com_server: { likely: false, confidence: 0.05, evidence: [] },
                service_binary: { likely: false, confidence: 0.05, evidence: [] },
                plugin_binary: { likely: false, confidence: 0.05, evidence: [] },
                driver_binary: { likely: false, confidence: 0.01, evidence: [] },
              },
              export_dispatch_profile: {
                command_like_exports: [],
                callback_like_exports: [],
                registration_exports: [],
                ordinal_only_exports: 0,
                likely_dispatch_model: 'none',
                confidence: 0.1,
              },
              com_profile: {
                clsid_strings: [],
                progid_strings: [],
                interface_hints: [],
                registration_strings: [],
                class_factory_exports: [],
                confidence: 0.02,
              },
              host_interaction_profile: {
                likely_hosted: false,
                host_hints: [],
                callback_exports: [],
                callback_strings: [],
                service_hooks: [],
                confidence: 0.08,
              },
              analysis_priorities: ['review_process_manipulation_and_dynamic_resolution_paths'],
              strings_considered: 80,
            },
            rust_profile: {
              suspected_rust: true,
              confidence: 0.92,
              primary_runtime: 'rust',
              runtime_hints: ['panic_unwind'],
              crate_hints: ['tokio'],
              cargo_paths: ['cargo\\registry\\src\\...\\tokio-1.0'],
              recovered_function_count: 80,
              recovered_symbol_count: 60,
              importable_with_code_functions_define: true,
              analysis_priorities: ['recover_function_index_from_pdata'],
            },
            function_index_recovery: {
              applied: true,
              define_from: 'symbols_recover',
              recovered_function_count: 80,
              recovered_symbol_count: 60,
              imported_count: 80,
              function_index_status: 'ready',
              decompile_status: 'missing',
              cfg_status: 'missing',
              recovery_strategy: ['pdata_runtime_functions'],
              next_steps: ['Use code.functions.rank'],
            },
          },
          provenance: {
            runtime: {
              scope: 'session',
              session_selector: 'runtime-alpha',
              artifact_count: 1,
              artifact_ids: ['runtime-1'],
              session_tags: ['runtime-alpha'],
              earliest_artifact_at: '2026-03-11T00:00:00.000Z',
              latest_artifact_at: '2026-03-11T00:00:00.000Z',
              scope_note: 'runtime current',
            },
            semantic_names: {
              scope: 'session',
              session_selector: 'explain-session',
              artifact_count: 0,
              artifact_ids: [],
              session_tags: [],
              earliest_artifact_at: null,
              latest_artifact_at: null,
              scope_note: 'semantic names current',
            },
            semantic_explanations: {
              scope: 'session',
              session_selector: 'explain-session',
              artifact_count: 1,
              artifact_ids: ['semantic-expl-1'],
              session_tags: ['explain-session'],
              earliest_artifact_at: '2026-03-11T00:00:00.000Z',
              latest_artifact_at: '2026-03-11T00:00:00.000Z',
              scope_note: 'semantic explanations current',
            },
          },
          selection_diffs: {
            runtime: {
              label: 'runtime',
              current: {
                scope: 'session',
                session_selector: 'runtime-alpha',
                artifact_count: 1,
                artifact_ids: ['runtime-1'],
                session_tags: ['runtime-alpha'],
                earliest_artifact_at: '2026-03-11T00:00:00.000Z',
                latest_artifact_at: '2026-03-11T00:00:00.000Z',
                scope_note: 'runtime current',
              },
              baseline: {
                scope: 'all',
                session_selector: null,
                artifact_count: 2,
                artifact_ids: ['runtime-1', 'runtime-2'],
                session_tags: ['runtime-alpha', 'runtime-beta'],
                earliest_artifact_at: '2026-03-10T00:00:00.000Z',
                latest_artifact_at: '2026-03-11T00:00:00.000Z',
                scope_note: 'runtime baseline',
              },
              added_artifact_ids: [],
              removed_artifact_ids: ['runtime-2'],
              added_session_tags: [],
              removed_session_tags: ['runtime-beta'],
              artifact_count_delta: -1,
              summary: 'runtime diff',
            },
          },
          export: {
            tool: 'code.reconstruct.export',
            export_root: 'reports/reconstruct/explained',
            manifest_path: 'reports/reconstruct/explained/manifest.json',
            build_validation_status: 'passed',
            harness_validation_status: 'passed',
          },
          notes: ['Native build validation: passed'],
        },
      })

    const handler = createFunctionExplanationReviewWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        explainReviewHandler,
        reconstructWorkflowHandler,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      analysis_goal: 'Explain the highest-value functions in plain language.',
      evidence_scope: 'session',
      evidence_session_tag: 'runtime-alpha',
      compare_evidence_scope: 'all',
      compare_semantic_scope: 'all',
      export_name: 'explained',
      export_path: 'native',
      validate_build: true,
      run_harness: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.review.review_status).toBe('sampled_and_applied')
    expect(data.review.apply.accepted_count).toBe(1)
    expect(data.review.confidence_policy.explanation_scores_are_heuristic).toBe(true)
    expect(data.export.attempted).toBe(true)
    expect(data.export.status).toBe('completed')
    expect(data.export.selected_path).toBe('native')
    expect(data.export.export_tool).toBe('code.reconstruct.export')
    expect(data.export.manifest_path).toContain('manifest.json')
    expect(data.export.preflight.function_index_recovery.imported_count).toBe(80)
    expect(data.export.provenance.runtime.session_selector).toBe('runtime-alpha')
    expect(data.export.selection_diffs.runtime.summary).toBe('runtime diff')
    expect(data.next_steps.join(' ')).toContain('Native build validation: passed')

    expect(explainReviewHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: sampleId,
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
      })
    )
    expect(reconstructWorkflowHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: sampleId,
        path: 'native',
        export_name: 'explained',
        validate_build: true,
        run_harness: true,
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
        compare_evidence_scope: 'all',
        compare_semantic_scope: 'all',
        include_preflight: true,
        auto_recover_function_index: true,
      })
    )
  })
})
