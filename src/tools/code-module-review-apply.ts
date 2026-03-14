import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import {
  persistSemanticModuleReviewsArtifact,
  type SemanticModuleReviewArtifactPayload,
  SEMANTIC_MODULE_REVIEWS_ARTIFACT_TYPE,
} from '../semantic-name-suggestion-artifacts.js'

const TOOL_NAME = 'code.module.review.apply'

const ModuleReviewInputSchema = z.object({
  module_name: z.string().min(1).max(120).describe('Module name as returned by code.reconstruct.export'),
  refined_name: z
    .string()
    .min(1)
    .max(120)
    .optional()
    .describe('Optional refined human-readable module display name'),
  summary: z.string().min(1).max(1600).describe('Evidence-grounded plain-language explanation of the module'),
  role_hint: z
    .string()
    .min(1)
    .max(240)
    .optional()
    .describe('Optional refined module role hint, such as export dispatch or COM activation'),
  confidence: z.number().min(0).max(1).describe('Heuristic support score for the module review'),
  assumptions: z.array(z.string()).optional().default([]).describe('Assumptions that must hold for the review to remain valid'),
  evidence_used: z.array(z.string()).optional().default([]).describe('Evidence sources used by the external LLM'),
  rewrite_guidance: z
    .union([z.string().min(1), z.array(z.string().min(1))])
    .optional()
    .describe('One or more rewrite-oriented guidance items derived from the evidence'),
  focus_areas: z
    .array(z.string().min(1))
    .optional()
    .default([])
    .describe('Optional high-value focus areas inside the module'),
  priority_functions: z
    .array(z.string().min(1))
    .optional()
    .default([])
    .describe('Optional function names or addresses that should be prioritized inside the module'),
})

function normalizeStringArray(input: string | string[] | undefined, limit = 12): string[] {
  if (!input) {
    return []
  }
  const values = Array.isArray(input) ? input : [input]
  return values.map((item) => item.trim()).filter((item) => item.length > 0).slice(0, limit)
}

export const codeModuleReviewApplyInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  reviews: z
    .array(ModuleReviewInputSchema)
    .min(1)
    .describe('Structured module review outputs returned by an external MCP client / LLM'),
  client_name: z
    .string()
    .optional()
    .describe('Optional client identifier, such as claude-desktop or codex-cli'),
  model_name: z
    .string()
    .optional()
    .describe('Optional model identifier for provenance only'),
  prepare_artifact_id: z
    .string()
    .optional()
    .describe('Optional semantic_module_review_prepare_bundle artifact ID that produced this review task'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional semantic module review session tag used for artifact grouping'),
})

export const codeModuleReviewApplyOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      accepted_count: z.number().int().nonnegative(),
      rejected_count: z.number().int().nonnegative(),
      accepted_reviews: z.array(
        z.object({
          module_name: z.string(),
          refined_name: z.string().nullable(),
          confidence: z.number().min(0).max(1),
          rewrite_guidance_count: z.number().int().nonnegative(),
        })
      ),
      artifact: z.object({
        id: z.string(),
        type: z.literal(SEMANTIC_MODULE_REVIEWS_ARTIFACT_TYPE),
        path: z.string(),
        sha256: z.string(),
        mime: z.string().optional(),
      }),
      next_steps: z.array(z.string()),
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

export const codeModuleReviewApplyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Persist structured module review outputs returned by any external MCP client / LLM so export and workflow layers can consume them.',
  inputSchema: codeModuleReviewApplyInputSchema,
  outputSchema: codeModuleReviewApplyOutputSchema,
}

export function createCodeModuleReviewApplyHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = codeModuleReviewApplyInputSchema.parse(args)
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

      const acceptedReviews: SemanticModuleReviewArtifactPayload['reviews'] = []
      const acceptedSummary: Array<{
        module_name: string
        refined_name: string | null
        confidence: number
        rewrite_guidance_count: number
      }> = []
      const warnings: string[] = []

      for (const review of input.reviews) {
        const moduleName = review.module_name.trim()
        const summary = review.summary.trim()
        if (moduleName.length === 0 || summary.length === 0) {
          warnings.push('Rejected module review because module_name or summary was empty after normalization.')
          continue
        }

        const rewriteGuidance = normalizeStringArray(review.rewrite_guidance, 10)
        const focusAreas = normalizeStringArray(review.focus_areas, 10)
        const priorityFunctions = normalizeStringArray(review.priority_functions, 16)

        acceptedReviews.push({
          module_name: moduleName,
          refined_name: review.refined_name?.trim() || null,
          summary,
          role_hint: review.role_hint?.trim() || null,
          confidence: review.confidence,
          assumptions: review.assumptions || [],
          evidence_used: review.evidence_used || [],
          rewrite_guidance: rewriteGuidance,
          focus_areas: focusAreas,
          priority_functions: priorityFunctions,
        })
        acceptedSummary.push({
          module_name: moduleName,
          refined_name: review.refined_name?.trim() || null,
          confidence: review.confidence,
          rewrite_guidance_count: rewriteGuidance.length,
        })
      }

      if (acceptedReviews.length === 0) {
        return {
          ok: false,
          errors: ['No module reviews were accepted after normalization.'],
          warnings: warnings.length > 0 ? warnings : undefined,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const payload: SemanticModuleReviewArtifactPayload = {
        schema_version: 1,
        sample_id: input.sample_id,
        created_at: new Date().toISOString(),
        session_tag: input.session_tag || null,
        client_name: input.client_name || null,
        model_name: input.model_name || null,
        prepare_artifact_id: input.prepare_artifact_id || null,
        reviews: acceptedReviews,
      }

      const artifact = await persistSemanticModuleReviewsArtifact(workspaceManager, database, payload)

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          accepted_count: acceptedReviews.length,
          rejected_count: input.reviews.length - acceptedReviews.length,
          accepted_reviews: acceptedSummary,
          artifact,
          next_steps: [
            'rerun code.reconstruct.export to propagate module review summaries and rewrite guidance into rewrite output',
            'rerun workflow.reconstruct if you want refreshed role-aware export output',
          ],
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts: [artifact],
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
