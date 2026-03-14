import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { createCodeReconstructExportHandler } from './code-reconstruct-export.js'
import {
  persistSemanticModuleReviewPrepareBundleArtifact,
  SEMANTIC_MODULE_REVIEW_PREPARE_BUNDLE_ARTIFACT_TYPE,
} from '../semantic-name-suggestion-artifacts.js'
import { buildModuleReconstructionReviewPromptText } from '../prompts/module-reconstruction-review.js'

const TOOL_NAME = 'code.module.review.prepare'

const PreparedModuleFunctionSchema = z.object({
  function: z.string(),
  address: z.string(),
  confidence: z.number().min(0).max(1),
  validated_name: z.string().nullable().optional(),
  resolution_source: z.string().nullable().optional(),
  explanation_summary: z.string().nullable().optional(),
  explanation_behavior: z.string().nullable().optional(),
  explanation_confidence: z.number().min(0).max(1).nullable().optional(),
})

const PreparedModuleSchema = z.object({
  module_name: z.string(),
  role_hint: z.string().nullable().optional(),
  focus_matches: z.array(z.string()).optional(),
  confidence: z.number().min(0).max(1),
  function_count: z.number().int().nonnegative(),
  import_hints: z.array(z.string()),
  string_hints: z.array(z.string()),
  runtime_apis: z.array(z.string()),
  runtime_stages: z.array(z.string()),
  functions: z.array(PreparedModuleFunctionSchema),
  rewrite_path: z.string(),
  pseudocode_path: z.string(),
  interface_path: z.string(),
})

const PreparedModuleReviewBundleSchema = z.object({
  schema_version: z.literal(1),
  sample_id: z.string(),
  analysis_goal: z.string(),
  generated_at: z.string(),
  selection: z.object({
    topk: z.number().int().positive(),
    module_limit: z.number().int().positive(),
    min_module_size: z.number().int().positive(),
    include_imports: z.boolean(),
    include_strings: z.boolean(),
    evidence_scope: z.enum(['all', 'latest', 'session']),
    evidence_session_tag: z.string().nullable(),
    semantic_scope: z.enum(['all', 'latest', 'session']),
    semantic_session_tag: z.string().nullable(),
    role_target: z.string().nullable(),
    role_focus_areas: z.array(z.string()),
    role_priority_order: z.array(z.string()),
  }),
  output_contract: z.object({
    output_root: z.literal('reviews'),
    required_fields: z.array(z.string()),
  }),
  binary_profile: z.any().nullable(),
  runtime_evidence: z.any().nullable(),
  provenance: z.any().optional(),
  modules: z.array(PreparedModuleSchema),
})

export const codeModuleReviewPrepareInputSchema = z
  .object({
    sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
    topk: z
      .number()
      .int()
      .min(1)
      .max(40)
      .default(12)
      .describe('Top-K high-value functions forwarded to code.reconstruct.export'),
    module_limit: z
      .number()
      .int()
      .min(1)
      .max(12)
      .default(6)
      .describe('Maximum module count in the prepared reconstruction bundle'),
    min_module_size: z
      .number()
      .int()
      .min(1)
      .max(20)
      .default(2)
      .describe('Modules with fewer functions than this threshold are merged into core'),
    include_imports: z
      .boolean()
      .default(true)
      .describe('Use import features for module hints'),
    include_strings: z
      .boolean()
      .default(true)
      .describe('Use high-value string clusters for module hints'),
    analysis_goal: z
      .string()
      .min(1)
      .max(400)
      .default(
        'Review reconstructed modules, refine their role labels, and propose evidence-grounded rewrite guidance.'
      )
      .describe('Human-readable analysis goal injected into the prompt contract for any external LLM'),
    persist_artifact: z
      .boolean()
      .default(true)
      .describe('Persist the prepared module review bundle as a JSON artifact for later review and provenance'),
    session_tag: z
      .string()
      .optional()
      .describe('Optional semantic module review session tag used for artifact grouping'),
    evidence_scope: z
      .enum(['all', 'latest', 'session'])
      .default('all')
      .describe('Runtime evidence scope forwarded to code.reconstruct.export for module review preparation'),
    evidence_session_tag: z
      .string()
      .optional()
      .describe('Optional runtime evidence session selector used when evidence_scope=session or to narrow all/latest results'),
    semantic_scope: z
      .enum(['all', 'latest', 'session'])
      .default('all')
      .describe('Semantic artifact scope forwarded to code.reconstruct.export for module review preparation'),
    semantic_session_tag: z
      .string()
      .optional()
      .describe('Optional semantic artifact session selector used when semantic_scope=session or to narrow all/latest results'),
    role_target: z
      .string()
      .min(1)
      .max(64)
      .optional()
      .describe('Optional high-level binary role hint such as native_rust_executable, dll_library, or com_server'),
    role_focus_areas: z
      .array(z.string().min(1).max(96))
      .max(16)
      .default([])
      .describe('Optional role-aware focus areas forwarded to code.reconstruct.export'),
    role_priority_order: z
      .array(z.string().min(1).max(96))
      .max(24)
      .default([])
      .describe('Optional role-aware priority-order hints forwarded to code.reconstruct.export'),
  })
  .refine((value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()), {
    message: 'evidence_session_tag is required when evidence_scope=session',
    path: ['evidence_session_tag'],
  })
  .refine((value) => value.semantic_scope !== 'session' || Boolean(value.semantic_session_tag?.trim()), {
    message: 'semantic_session_tag is required when semantic_scope=session',
    path: ['semantic_session_tag'],
  })

export const codeModuleReviewPrepareOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      analysis_goal: z.string(),
      prepared_count: z.number().int().nonnegative(),
      prompt_name: z.literal('reverse.module_reconstruction_review'),
      prompt_arguments: z.object({
        analysis_goal: z.string(),
        prepared_bundle_json: z.string(),
      }),
      task_prompt: z.string(),
      prepared_bundle: PreparedModuleReviewBundleSchema,
      export: z.object({
        export_root: z.string(),
        manifest_path: z.string(),
        module_count: z.number().int().nonnegative(),
      }),
      artifact: z
        .object({
          id: z.string(),
          type: z.literal(SEMANTIC_MODULE_REVIEW_PREPARE_BUNDLE_ARTIFACT_TYPE),
          path: z.string(),
          sha256: z.string(),
          mime: z.string().optional(),
        })
        .optional(),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const codeModuleReviewPrepareToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Prepare a structured module-level reconstruction bundle and MCP prompt contract so any tool-calling LLM can review grouped modules and refine rewrite guidance.',
  inputSchema: codeModuleReviewPrepareInputSchema,
  outputSchema: codeModuleReviewPrepareOutputSchema,
}

interface CodeModuleReviewPrepareDependencies {
  exportHandler?: (args: ToolArgs) => Promise<WorkerResult>
}

export function createCodeModuleReviewPrepareHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies?: CodeModuleReviewPrepareDependencies
) {
  const exportHandler =
    dependencies?.exportHandler ||
    createCodeReconstructExportHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = codeModuleReviewPrepareInputSchema.parse(args)
      const exportResult = await exportHandler({
        sample_id: input.sample_id,
        topk: input.topk,
        module_limit: input.module_limit,
        min_module_size: input.min_module_size,
        include_imports: input.include_imports,
        include_strings: input.include_strings,
        validate_build: false,
        run_harness: false,
        evidence_scope: input.evidence_scope,
        evidence_session_tag: input.evidence_session_tag,
        semantic_scope: input.semantic_scope,
        semantic_session_tag: input.semantic_session_tag,
        role_target: input.role_target,
        role_focus_areas: input.role_focus_areas,
        role_priority_order: input.role_priority_order,
        reuse_cached: true,
      })

      if (!exportResult.ok) {
        return {
          ok: false,
          errors: exportResult.errors || ['code.reconstruct.export failed'],
          warnings: exportResult.warnings,
          artifacts: exportResult.artifacts,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const exportData = (exportResult.data || {}) as any
      const preparedBundle = {
        schema_version: 1 as const,
        sample_id: input.sample_id,
        analysis_goal: input.analysis_goal,
        generated_at: new Date().toISOString(),
        selection: {
          topk: input.topk,
          module_limit: input.module_limit,
          min_module_size: input.min_module_size,
          include_imports: input.include_imports,
          include_strings: input.include_strings,
          evidence_scope: input.evidence_scope,
          evidence_session_tag: input.evidence_session_tag || null,
          semantic_scope: input.semantic_scope,
          semantic_session_tag: input.semantic_session_tag || null,
          role_target: input.role_target || null,
          role_focus_areas: input.role_focus_areas,
          role_priority_order: input.role_priority_order,
        },
        output_contract: {
          output_root: 'reviews' as const,
          required_fields: [
            'module_name',
            'summary',
            'role_hint',
            'confidence',
            'assumptions',
            'evidence_used',
            'rewrite_guidance',
          ],
        },
        binary_profile: exportData.binary_profile || null,
        runtime_evidence: exportData.runtime_evidence || null,
        provenance: exportData.provenance || null,
        modules: Array.isArray(exportData.modules)
          ? exportData.modules.map((module: any) => ({
              module_name: module.name,
              role_hint: module.role_hint || null,
              focus_matches: Array.isArray(module.focus_matches) ? module.focus_matches : [],
              confidence: Number(module.confidence || 0),
              function_count: Number(module.function_count || 0),
              import_hints: Array.isArray(module.import_hints) ? module.import_hints : [],
              string_hints: Array.isArray(module.string_hints) ? module.string_hints : [],
              runtime_apis: Array.isArray(module.runtime_apis) ? module.runtime_apis : [],
              runtime_stages: Array.isArray(module.runtime_stages) ? module.runtime_stages : [],
              functions: Array.isArray(module.functions)
                ? module.functions.map((func: any) => ({
                    function: func.function,
                    address: func.address,
                    confidence: Number(func.confidence || 0),
                    validated_name: func.validated_name || null,
                    resolution_source: func.name_resolution_source || null,
                    explanation_summary: func.explanation_summary || null,
                    explanation_behavior: func.explanation_behavior || null,
                    explanation_confidence:
                      typeof func.explanation_confidence === 'number'
                        ? func.explanation_confidence
                        : null,
                  }))
                : [],
              rewrite_path: module.rewrite_path,
              pseudocode_path: module.pseudocode_path,
              interface_path: module.interface_path,
            }))
          : [],
      }

      const promptArguments = {
        analysis_goal: input.analysis_goal,
        prepared_bundle_json: JSON.stringify(preparedBundle, null, 2),
      }
      const taskPrompt = buildModuleReconstructionReviewPromptText(
        promptArguments.prepared_bundle_json,
        input.analysis_goal
      )

      let artifact: ArtifactRef | undefined
      const artifacts = [...(exportResult.artifacts || [])]
      if (input.persist_artifact) {
        artifact = await persistSemanticModuleReviewPrepareBundleArtifact(
          workspaceManager,
          database,
          input.sample_id,
          preparedBundle,
          input.session_tag || null
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          analysis_goal: input.analysis_goal,
          prepared_count: preparedBundle.modules.length,
          prompt_name: 'reverse.module_reconstruction_review',
          prompt_arguments: promptArguments,
          task_prompt: taskPrompt,
          prepared_bundle: preparedBundle,
          export: {
            export_root: exportData.export_root,
            manifest_path: exportData.manifest_path,
            module_count: preparedBundle.modules.length,
          },
          artifact,
        },
        warnings: exportResult.warnings,
        artifacts,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
