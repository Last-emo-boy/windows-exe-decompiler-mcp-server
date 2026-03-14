/**
 * workflow.function_explanation_review
 * High-level orchestration for function explanation review plus optional reconstruct export refresh.
 */

import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { JobQueue } from '../job-queue.js'
import type { MCPServer } from '../server.js'
import { createCodeFunctionExplainReviewHandler } from '../tools/code-function-explain-review.js'
import { createReconstructWorkflowHandler } from './reconstruct.js'
import { AnalysisProvenanceSchema } from '../analysis-provenance.js'
import { AnalysisSelectionDiffSchema } from '../selection-diff.js'
import { BinaryRoleProfileDataSchema } from '../tools/binary-role-profile.js'
import { GhidraExecutionSummarySchema } from '../ghidra-execution-summary.js'
import {
  RequiredUserInputSchema,
  SetupActionSchema,
  collectSetupGuidanceFromWorkerResult,
  mergeRequiredUserInputs,
  mergeSetupActions,
} from '../setup-guidance.js'
import { PollingGuidanceSchema, buildPollingGuidance } from '../polling-guidance.js'

const TOOL_NAME = 'workflow.function_explanation_review'

export const functionExplanationReviewWorkflowInputSchema = z
  .object({
    sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
    address: z.string().optional().describe('Optional specific function address'),
    symbol: z.string().optional().describe('Optional specific function symbol'),
    topk: z
      .number()
      .int()
      .min(1)
      .max(20)
      .default(6)
      .describe('When address/symbol not provided, review up to top-K functions'),
    max_functions: z
      .number()
      .int()
      .min(1)
      .max(20)
      .default(6)
      .describe('Maximum number of functions included in the explanation review bundle'),
    include_resolved: z
      .boolean()
      .default(true)
      .describe('Include already resolved functions so the external LLM can explain stable and unresolved ones together'),
    analysis_goal: z
      .string()
      .min(1)
      .max(400)
      .default(
        'Explain the prepared functions in plain language and propose evidence-grounded rewrite guidance.'
      )
      .describe('Human-readable analysis goal injected into the MCP prompt and sampling request'),
    session_tag: z
      .string()
      .optional()
      .describe('Optional semantic explanation session tag used for artifact grouping'),
    evidence_scope: z
      .enum(['all', 'latest', 'session'])
      .default('all')
      .describe('Runtime evidence scope forwarded to review and optional reconstruct/export refresh'),
    evidence_session_tag: z
      .string()
      .optional()
      .describe('Optional runtime evidence session selector used when evidence_scope=session or to narrow all/latest results'),
    semantic_scope: z
      .enum(['all', 'latest', 'session'])
      .default('all')
      .describe('Semantic artifact scope used when refreshing reconstruct/export output after apply'),
    semantic_session_tag: z
      .string()
      .optional()
      .describe('Optional semantic review session selector used when semantic_scope=session or to narrow all/latest results'),
    compare_evidence_scope: z
      .enum(['all', 'latest', 'session'])
      .optional()
      .describe('Optional baseline runtime evidence scope used when refreshing export for comparison-aware workflow output'),
    compare_evidence_session_tag: z
      .string()
      .optional()
      .describe('Optional baseline runtime evidence session selector used when compare_evidence_scope=session'),
    compare_semantic_scope: z
      .enum(['all', 'latest', 'session'])
      .optional()
      .describe('Optional baseline semantic artifact scope used when refreshing export for comparison-aware workflow output'),
    compare_semantic_session_tag: z
      .string()
      .optional()
      .describe('Optional baseline semantic artifact session selector used when compare_semantic_scope=session'),
    persist_artifact: z
      .boolean()
      .default(true)
      .describe('Persist the prepare bundle artifact before requesting external explanation review'),
    auto_apply: z
      .boolean()
      .default(true)
      .describe('Persist accepted explanations automatically via code.function.explain.apply'),
    temperature: z
      .number()
      .min(0)
      .max(1)
      .default(0.2)
      .describe('Sampling temperature passed to the connected MCP client'),
    max_tokens: z
      .number()
      .int()
      .min(200)
      .max(8000)
      .default(2200)
      .describe('Maximum sampling tokens requested from the connected MCP client'),
    include_context: z
      .enum(['none', 'thisServer', 'allServers'])
      .default('none')
      .describe('Requested MCP sampling context scope; clients may ignore this preference'),
    model_hint: z
      .string()
      .min(1)
      .max(120)
      .optional()
      .describe('Optional advisory model-family hint for client-mediated MCP sampling'),
    cost_priority: z
      .number()
      .min(0)
      .max(1)
      .default(0.1)
      .describe('Advisory model selection preference for sampling cost'),
    speed_priority: z
      .number()
      .min(0)
      .max(1)
      .default(0.2)
      .describe('Advisory model selection preference for sampling latency'),
    intelligence_priority: z
      .number()
      .min(0)
      .max(1)
      .default(0.95)
      .describe('Advisory model selection preference for reasoning quality'),
    system_prompt: z
      .string()
      .min(1)
      .max(800)
      .optional()
      .describe('Optional extra system prompt for the client-mediated explanation review'),
    rerun_export: z
      .boolean()
      .default(true)
      .describe('After successful apply, rerun workflow.reconstruct to refresh rewrite/export output'),
    export_path: z
      .enum(['auto', 'native', 'dotnet'])
      .default('auto')
      .describe('Routing strategy used when rerun_export=true'),
    export_topk: z
      .number()
      .int()
      .min(1)
      .max(40)
      .default(12)
      .describe('Top-K high-value functions used for optional reconstruct/export refresh'),
    export_name: z
      .string()
      .min(1)
      .max(64)
      .optional()
      .describe('Optional export folder name used for the refresh run'),
    include_preflight: z
      .boolean()
      .default(true)
      .describe('Run binary role and language-specific preflight profiling before refresh export'),
    auto_recover_function_index: z
      .boolean()
      .default(true)
      .describe('When native function-index coverage is missing, automatically recover it before refresh export'),
    include_plan: z
      .boolean()
      .default(false)
      .describe('Include code.reconstruct.plan when rerun_export=true'),
    include_obfuscation_fallback: z
      .boolean()
      .default(true)
      .describe('When routing to .NET path, generate IL fallback notes when needed'),
    fallback_on_error: z
      .boolean()
      .default(true)
      .describe('When primary export path fails, automatically try the alternative path'),
    allow_partial: z
      .boolean()
      .default(true)
      .describe('When all export paths fail, still return runtime/plan as partial output'),
    validate_build: z
      .boolean()
      .default(false)
      .describe('Compile the refreshed native reconstruction when rerun_export=true'),
    run_harness: z
      .boolean()
      .default(false)
      .describe('Execute reconstruct_harness after a successful refreshed native build'),
    compiler_path: z
      .string()
      .min(1)
      .max(260)
      .optional()
      .describe('Optional explicit clang compiler path for the refresh run'),
    build_timeout_ms: z
      .number()
      .int()
      .min(5000)
      .max(300000)
      .default(60000)
      .describe('Timeout for native clang build validation in milliseconds'),
    run_timeout_ms: z
      .number()
      .int()
      .min(5000)
      .max(300000)
      .default(30000)
      .describe('Timeout for reconstruct_harness execution in milliseconds'),
    reuse_cached: z
      .boolean()
      .default(true)
      .describe('Reuse cached reconstruct workflow results for the optional refresh run'),
  })
  .refine((value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()), {
    message: 'evidence_session_tag is required when evidence_scope=session',
    path: ['evidence_session_tag'],
  })
  .refine((value) => value.semantic_scope !== 'session' || Boolean(value.semantic_session_tag?.trim()), {
    message: 'semantic_session_tag is required when semantic_scope=session',
    path: ['semantic_session_tag'],
  })
  .refine(
    (value) =>
      value.compare_evidence_scope !== 'session' || Boolean(value.compare_evidence_session_tag?.trim()),
    {
      message: 'compare_evidence_session_tag is required when compare_evidence_scope=session',
      path: ['compare_evidence_session_tag'],
    }
  )
  .refine(
    (value) =>
      value.compare_semantic_scope !== 'session' || Boolean(value.compare_semantic_session_tag?.trim()),
    {
      message: 'compare_semantic_session_tag is required when compare_semantic_scope=session',
      path: ['compare_semantic_session_tag'],
    }
  )

export const functionExplanationReviewWorkflowOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .union([
      z.object({
        job_id: z.string(),
        status: z.literal('queued'),
        tool: z.literal(TOOL_NAME),
        sample_id: z.string(),
        progress: z.number().int().min(0).max(100),
        polling_guidance: PollingGuidanceSchema.nullable(),
      }),
      z.object({
      sample_id: z.string(),
      review: z.object({
        review_status: z.string(),
        prompt_name: z.string(),
        client: z.object({
          name: z.string().nullable(),
          version: z.string().nullable(),
          sampling_available: z.boolean(),
        }),
        prepare: z.object({
          prepared_count: z.number().int().nonnegative(),
          artifact_id: z.string().nullable(),
        }),
        sampling: z.object({
          attempted: z.boolean(),
          model: z.string().nullable(),
          stop_reason: z.string().nullable(),
          parsed_explanation_count: z.number().int().nonnegative(),
        }),
        apply: z.object({
          attempted: z.boolean(),
          accepted_count: z.number().int().nonnegative(),
          rejected_count: z.number().int().nonnegative(),
          artifact_id: z.string().nullable(),
        }),
        confidence_policy: z.object({
          calibrated: z.boolean(),
          explanation_scores_are_heuristic: z.boolean(),
          meaning: z.string(),
        }),
      }),
      export: z.object({
        attempted: z.boolean(),
        status: z.enum(['completed', 'failed', 'skipped']),
        selected_path: z.enum(['native', 'dotnet']).nullable(),
        export_tool: z.string().nullable(),
        export_root: z.string().nullable(),
        manifest_path: z.string().nullable(),
        build_validation_status: z.string().nullable(),
        harness_validation_status: z.string().nullable(),
        preflight: z
          .object({
            binary_profile: BinaryRoleProfileDataSchema.nullable(),
            rust_profile: z.any().nullable(),
            function_index_recovery: z.any().nullable(),
          })
          .nullable(),
        ghidra_execution: GhidraExecutionSummarySchema.nullable(),
        provenance: AnalysisProvenanceSchema.nullable(),
        selection_diffs: AnalysisSelectionDiffSchema.nullable(),
        notes: z.array(z.string()),
      }),
      next_steps: z.array(z.string()),
      }),
    ])
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  setup_actions: z.array(SetupActionSchema).optional(),
  required_user_inputs: z.array(RequiredUserInputSchema).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const functionExplanationReviewWorkflowToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Run function explanation review end-to-end for any MCP-capable LLM client, then optionally refresh reconstruct/export output with the applied explanations.',
  inputSchema: functionExplanationReviewWorkflowInputSchema,
  outputSchema: functionExplanationReviewWorkflowOutputSchema,
}

interface FunctionExplanationReviewWorkflowDependencies {
  explainReviewHandler?: (args: ToolArgs) => Promise<WorkerResult>
  reconstructWorkflowHandler?: (args: ToolArgs) => Promise<WorkerResult>
}

export function createFunctionExplanationReviewWorkflowHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  mcpServer?: MCPServer,
  dependencies?: FunctionExplanationReviewWorkflowDependencies,
  jobQueue?: JobQueue
) {
  const explainReviewHandler =
    dependencies?.explainReviewHandler ||
    createCodeFunctionExplainReviewHandler(
      workspaceManager,
      database,
      cacheManager,
      mcpServer
    )
  const reconstructWorkflowHandler =
    dependencies?.reconstructWorkflowHandler ||
    createReconstructWorkflowHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const warnings: string[] = []
    const errors: string[] = []
    const artifacts: any[] = []
    let setupActions = [] as z.infer<typeof SetupActionSchema>[]
    let requiredUserInputs = [] as z.infer<typeof RequiredUserInputSchema>[]

    try {
      const input = functionExplanationReviewWorkflowInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      if (jobQueue) {
        const jobTimeoutMs = Math.max(
          input.build_timeout_ms + input.run_timeout_ms + 45 * 60 * 1000,
          60 * 60 * 1000
        )
        const jobId = jobQueue.enqueue({
          type: 'static',
          tool: TOOL_NAME,
          sampleId: input.sample_id,
          args: input,
          priority: 5,
          timeout: jobTimeoutMs,
          retryPolicy: {
            maxRetries: 1,
            backoffMs: 5000,
            retryableErrors: ['E_TIMEOUT', 'E_RESOURCE_EXHAUSTED'],
          },
        })

        return {
          ok: true,
          data: {
            job_id: jobId,
            status: 'queued',
            tool: TOOL_NAME,
            sample_id: input.sample_id,
            progress: 0,
            polling_guidance: buildPollingGuidance({
              tool: TOOL_NAME,
              status: 'queued',
              progress: 0,
              timeout_ms: jobTimeoutMs,
            }),
          },
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const reviewResult = await explainReviewHandler({
        sample_id: input.sample_id,
        address: input.address,
        symbol: input.symbol,
        topk: input.topk,
        max_functions: input.max_functions,
        include_resolved: input.include_resolved,
        analysis_goal: input.analysis_goal,
        session_tag: input.session_tag,
        evidence_scope: input.evidence_scope,
        evidence_session_tag: input.evidence_session_tag,
        persist_artifact: input.persist_artifact,
        auto_apply: input.auto_apply,
        temperature: input.temperature,
        max_tokens: input.max_tokens,
        include_context: input.include_context,
        model_hint: input.model_hint,
        cost_priority: input.cost_priority,
        speed_priority: input.speed_priority,
        intelligence_priority: input.intelligence_priority,
        system_prompt: input.system_prompt,
      })

      warnings.push(...(reviewResult.warnings || []))
      artifacts.push(...(reviewResult.artifacts || []))
      {
        const setupGuidance = collectSetupGuidanceFromWorkerResult(reviewResult)
        setupActions = mergeSetupActions(setupActions, setupGuidance.setupActions)
        requiredUserInputs = mergeRequiredUserInputs(
          requiredUserInputs,
          setupGuidance.requiredUserInputs
        )
      }

      if (!reviewResult.ok) {
        return {
          ok: false,
          errors: reviewResult.errors || ['code.function.explain.review failed'],
          warnings: warnings.length > 0 ? warnings : undefined,
          setup_actions: setupActions.length > 0 ? setupActions : undefined,
          required_user_inputs: requiredUserInputs.length > 0 ? requiredUserInputs : undefined,
          artifacts: artifacts.length > 0 ? artifacts : undefined,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const reviewData = (reviewResult.data || {}) as any
      const acceptedCount = Number(reviewData?.apply?.accepted_count || 0)
      const canRefreshExport =
        input.rerun_export &&
        reviewData.review_status === 'sampled_and_applied' &&
        acceptedCount > 0

      let exportSummary: {
        attempted: boolean
        status: 'completed' | 'failed' | 'skipped'
        selected_path: 'native' | 'dotnet' | null
        export_tool: string | null
        export_root: string | null
        manifest_path: string | null
        build_validation_status: string | null
        harness_validation_status: string | null
        preflight: {
          binary_profile: z.infer<typeof BinaryRoleProfileDataSchema> | null
          rust_profile: unknown | null
          function_index_recovery: unknown | null
        } | null
        ghidra_execution: z.infer<typeof GhidraExecutionSummarySchema> | null
        provenance: z.infer<typeof AnalysisProvenanceSchema> | null
        selection_diffs: z.infer<typeof AnalysisSelectionDiffSchema> | null
        notes: string[]
      } = {
        attempted: false,
        status: 'skipped',
        selected_path: null,
        export_tool: null,
        export_root: null,
        manifest_path: null,
        build_validation_status: null,
        harness_validation_status: null,
        preflight: null,
        ghidra_execution: null,
        provenance: null,
        selection_diffs: null,
        notes: [],
      }

      if (canRefreshExport) {
        const exportResult = await reconstructWorkflowHandler({
          sample_id: input.sample_id,
          path: input.export_path,
          topk: input.export_topk,
          export_name: input.export_name,
          validate_build: input.validate_build,
          run_harness: input.run_harness,
          compiler_path: input.compiler_path,
          build_timeout_ms: input.build_timeout_ms,
          run_timeout_ms: input.run_timeout_ms,
          evidence_scope: input.evidence_scope,
          evidence_session_tag: input.evidence_session_tag,
          compare_evidence_scope: input.compare_evidence_scope,
          compare_evidence_session_tag: input.compare_evidence_session_tag,
          semantic_scope:
            input.semantic_scope === 'all' && input.session_tag ? 'session' : input.semantic_scope,
          semantic_session_tag: input.semantic_session_tag || input.session_tag,
          compare_semantic_scope: input.compare_semantic_scope,
          compare_semantic_session_tag: input.compare_semantic_session_tag,
          include_preflight: input.include_preflight,
          auto_recover_function_index: input.auto_recover_function_index,
          include_plan: input.include_plan,
          include_obfuscation_fallback: input.include_obfuscation_fallback,
          fallback_on_error: input.fallback_on_error,
          allow_partial: input.allow_partial,
          reuse_cached: input.reuse_cached,
        })

        warnings.push(...(exportResult.warnings || []))
        artifacts.push(...(exportResult.artifacts || []))
        {
          const setupGuidance = collectSetupGuidanceFromWorkerResult(exportResult)
          setupActions = mergeSetupActions(setupActions, setupGuidance.setupActions)
          requiredUserInputs = mergeRequiredUserInputs(
            requiredUserInputs,
            setupGuidance.requiredUserInputs
          )
        }

        if (!exportResult.ok) {
          errors.push(...(exportResult.errors || ['workflow.reconstruct failed during export refresh']))
          exportSummary = {
            attempted: true,
            status: 'failed',
            selected_path: null,
            export_tool: null,
            export_root: null,
            manifest_path: null,
            build_validation_status: null,
            harness_validation_status: null,
            preflight: null,
            ghidra_execution: null,
            provenance: null,
            selection_diffs: null,
            notes: ['Refresh export failed after function explanation apply.'],
          }
        } else {
          const exportData = (exportResult.data || {}) as any
          exportSummary = {
            attempted: true,
            status: 'completed',
            selected_path: exportData.selected_path || null,
            export_tool: exportData.export?.tool || null,
            export_root: exportData.export?.export_root || null,
            manifest_path: exportData.export?.manifest_path || null,
            build_validation_status: exportData.export?.build_validation_status || null,
            harness_validation_status: exportData.export?.harness_validation_status || null,
            preflight: exportData.preflight || null,
            ghidra_execution: exportData.ghidra_execution || null,
            provenance: exportData.provenance || null,
            selection_diffs: exportData.selection_diffs || null,
            notes: Array.isArray(exportData.notes) ? exportData.notes : [],
          }
        }
      } else if (input.rerun_export) {
        exportSummary.notes.push(
          reviewData.review_status === 'prompt_contract_only'
            ? 'Refresh export skipped because no sampled explanations were applied yet.'
            : 'Refresh export skipped because no explanation artifacts were applied.'
        )
      }

      const nextSteps = [
        ...(Array.isArray(reviewData.next_steps) ? reviewData.next_steps : []),
        ...exportSummary.notes,
      ]

      return {
        ok: errors.length === 0,
        data: {
          sample_id: input.sample_id,
          review: {
            review_status: reviewData.review_status || 'unknown',
            prompt_name: reviewData.prompt_name || 'reverse.function_explanation_review',
            client: {
              name: reviewData.client?.name || null,
              version: reviewData.client?.version || null,
              sampling_available: Boolean(reviewData.client?.sampling_available),
            },
            prepare: {
              prepared_count: Number(reviewData.prepare?.prepared_count || 0),
              artifact_id: reviewData.prepare?.artifact_id || null,
            },
            sampling: {
              attempted: Boolean(reviewData.sampling?.attempted),
              model: reviewData.sampling?.model || null,
              stop_reason: reviewData.sampling?.stop_reason || null,
              parsed_explanation_count: Number(reviewData.sampling?.parsed_explanation_count || 0),
            },
            apply: {
              attempted: Boolean(reviewData.apply?.attempted),
              accepted_count: acceptedCount,
              rejected_count: Number(reviewData.apply?.rejected_count || 0),
              artifact_id: reviewData.apply?.artifact_id || null,
            },
            confidence_policy: {
              calibrated: Boolean(reviewData.confidence_policy?.calibrated),
              explanation_scores_are_heuristic:
                reviewData.confidence_policy?.explanation_scores_are_heuristic !== false,
              meaning: String(
                reviewData.confidence_policy?.meaning ||
                  'Explanation confidence remains heuristic and should be read as evidence support strength, not proof of source-equivalent recovery.'
              ),
            },
          },
          export: exportSummary,
          next_steps: nextSteps,
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        errors: errors.length > 0 ? errors : undefined,
        setup_actions: setupActions.length > 0 ? setupActions : undefined,
        required_user_inputs: requiredUserInputs.length > 0 ? requiredUserInputs : undefined,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        setup_actions: setupActions.length > 0 ? setupActions : undefined,
        required_user_inputs: requiredUserInputs.length > 0 ? requiredUserInputs : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
