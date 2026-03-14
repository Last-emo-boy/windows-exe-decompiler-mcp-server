/**
 * workflow.module_reconstruction_review
 * High-level orchestration for module reconstruction review plus optional export refresh.
 */

import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { JobQueue } from '../job-queue.js'
import type { MCPServer } from '../server.js'
import { createCodeModuleReviewHandler } from '../tools/code-module-review.js'
import { createReconstructWorkflowHandler } from './reconstruct.js'
import { AnalysisProvenanceSchema } from '../analysis-provenance.js'
import { AnalysisSelectionDiffSchema } from '../selection-diff.js'
import { BinaryRoleProfileDataSchema } from '../tools/binary-role-profile.js'
import {
  RequiredUserInputSchema,
  SetupActionSchema,
  collectSetupGuidanceFromWorkerResult,
  mergeRequiredUserInputs,
  mergeSetupActions,
} from '../setup-guidance.js'

const TOOL_NAME = 'workflow.module_reconstruction_review'

export const moduleReconstructionReviewWorkflowInputSchema = z
  .object({
    sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
    topk: z.number().int().min(1).max(40).default(12),
    module_limit: z.number().int().min(1).max(12).default(6),
    min_module_size: z.number().int().min(1).max(20).default(2),
    include_imports: z.boolean().default(true),
    include_strings: z.boolean().default(true),
    analysis_goal: z
      .string()
      .min(1)
      .max(400)
      .default(
        'Review reconstructed modules, refine their role labels, and propose evidence-grounded rewrite guidance.'
      ),
    session_tag: z.string().optional(),
    evidence_scope: z.enum(['all', 'latest', 'session']).default('all'),
    evidence_session_tag: z.string().optional(),
    semantic_scope: z.enum(['all', 'latest', 'session']).default('all'),
    semantic_session_tag: z.string().optional(),
    compare_evidence_scope: z.enum(['all', 'latest', 'session']).optional(),
    compare_evidence_session_tag: z.string().optional(),
    compare_semantic_scope: z.enum(['all', 'latest', 'session']).optional(),
    compare_semantic_session_tag: z.string().optional(),
    role_target: z.string().min(1).max(64).optional(),
    role_focus_areas: z.array(z.string().min(1).max(96)).max(16).default([]),
    role_priority_order: z.array(z.string().min(1).max(96)).max(24).default([]),
    persist_artifact: z.boolean().default(true),
    auto_apply: z.boolean().default(true),
    temperature: z.number().min(0).max(1).default(0.2),
    max_tokens: z.number().int().min(200).max(8000).default(2400),
    include_context: z.enum(['none', 'thisServer', 'allServers']).default('none'),
    model_hint: z.string().min(1).max(120).optional(),
    cost_priority: z.number().min(0).max(1).default(0.1),
    speed_priority: z.number().min(0).max(1).default(0.2),
    intelligence_priority: z.number().min(0).max(1).default(0.95),
    system_prompt: z.string().min(1).max(800).optional(),
    rerun_export: z.boolean().default(true),
    export_path: z.enum(['auto', 'native', 'dotnet']).default('auto'),
    export_topk: z.number().int().min(1).max(40).default(12),
    export_name: z.string().min(1).max(64).optional(),
    include_preflight: z.boolean().default(true),
    auto_recover_function_index: z.boolean().default(true),
    include_plan: z.boolean().default(false),
    include_obfuscation_fallback: z.boolean().default(true),
    fallback_on_error: z.boolean().default(true),
    allow_partial: z.boolean().default(true),
    validate_build: z.boolean().default(false),
    run_harness: z.boolean().default(false),
    compiler_path: z.string().min(1).max(260).optional(),
    build_timeout_ms: z.number().int().min(5000).max(300000).default(60000),
    run_timeout_ms: z.number().int().min(5000).max(300000).default(30000),
    reuse_cached: z.boolean().default(true),
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

export const moduleReconstructionReviewWorkflowOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .union([
      z.object({
        job_id: z.string(),
        status: z.literal('queued'),
        tool: z.literal(TOOL_NAME),
        sample_id: z.string(),
        progress: z.number().int().min(0).max(100),
      }),
      z.object({
        sample_id: z.string(),
        review: z.any(),
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
              rust_profile: z.unknown().nullable(),
              function_index_recovery: z.unknown().nullable(),
            })
            .nullable(),
          provenance: AnalysisProvenanceSchema.nullable(),
          selection_diffs: AnalysisSelectionDiffSchema.nullable(),
          notes: z.array(z.string()),
        }),
        setup_actions: z.array(SetupActionSchema).optional(),
        required_user_inputs: z.array(RequiredUserInputSchema).optional(),
        next_steps: z.array(z.string()),
      }),
    ])
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  setup_actions: z.array(SetupActionSchema).optional(),
  required_user_inputs: z.array(RequiredUserInputSchema).optional(),
  metrics: z.object({
    elapsed_ms: z.number(),
    tool: z.string(),
  }).optional(),
})

export const moduleReconstructionReviewWorkflowToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Run module-level reconstruction review end-to-end for any MCP-capable LLM client, then optionally refresh reconstruct/export output with the applied module reviews.',
  inputSchema: moduleReconstructionReviewWorkflowInputSchema,
  outputSchema: moduleReconstructionReviewWorkflowOutputSchema,
}

interface ModuleReconstructionReviewWorkflowDependencies {
  moduleReviewHandler?: (args: ToolArgs) => Promise<WorkerResult>
  reconstructWorkflowHandler?: (args: ToolArgs) => Promise<WorkerResult>
}

export function createModuleReconstructionReviewWorkflowHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  mcpServer?: MCPServer,
  dependencies?: ModuleReconstructionReviewWorkflowDependencies,
  jobQueue?: JobQueue
) {
  const moduleReviewHandler =
    dependencies?.moduleReviewHandler ||
    createCodeModuleReviewHandler(workspaceManager, database, cacheManager, mcpServer)
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
      const input = moduleReconstructionReviewWorkflowInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
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
          },
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const reviewResult = await moduleReviewHandler({
        sample_id: input.sample_id,
        topk: input.topk,
        module_limit: input.module_limit,
        min_module_size: input.min_module_size,
        include_imports: input.include_imports,
        include_strings: input.include_strings,
        analysis_goal: input.analysis_goal,
        session_tag: input.session_tag,
        evidence_scope: input.evidence_scope,
        evidence_session_tag: input.evidence_session_tag,
        semantic_scope: input.semantic_scope,
        semantic_session_tag: input.semantic_session_tag,
        role_target: input.role_target,
        role_focus_areas: input.role_focus_areas,
        role_priority_order: input.role_priority_order,
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
        requiredUserInputs = mergeRequiredUserInputs(requiredUserInputs, setupGuidance.requiredUserInputs)
      }

      if (!reviewResult.ok) {
        return {
          ok: false,
          errors: reviewResult.errors || ['code.module.review failed'],
          warnings: warnings.length > 0 ? warnings : undefined,
          setup_actions: setupActions.length > 0 ? setupActions : undefined,
          required_user_inputs: requiredUserInputs.length > 0 ? requiredUserInputs : undefined,
          artifacts: artifacts.length > 0 ? artifacts : undefined,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
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
          requiredUserInputs = mergeRequiredUserInputs(requiredUserInputs, setupGuidance.requiredUserInputs)
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
            provenance: null,
            selection_diffs: null,
            notes: ['Refresh export failed after module review apply.'],
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
            provenance: exportData.provenance || null,
            selection_diffs: exportData.selection_diffs || null,
            notes: Array.isArray(exportData.notes) ? exportData.notes : [],
          }
        }
      } else if (input.rerun_export) {
        exportSummary.notes.push(
          reviewData.review_status === 'prompt_contract_only'
            ? 'Refresh export skipped because no sampled module reviews were applied yet.'
            : 'Refresh export skipped because no module review artifacts were applied.'
        )
      }

      return {
        ok: errors.length === 0,
        data: {
          sample_id: input.sample_id,
          review: reviewData,
          export: exportSummary,
          setup_actions: setupActions.length > 0 ? setupActions : undefined,
          required_user_inputs: requiredUserInputs.length > 0 ? requiredUserInputs : undefined,
          next_steps: [
            ...(Array.isArray(reviewData.next_steps) ? reviewData.next_steps : []),
            ...exportSummary.notes,
          ],
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        errors: errors.length > 0 ? errors : undefined,
        setup_actions: setupActions.length > 0 ? setupActions : undefined,
        required_user_inputs: requiredUserInputs.length > 0 ? requiredUserInputs : undefined,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
