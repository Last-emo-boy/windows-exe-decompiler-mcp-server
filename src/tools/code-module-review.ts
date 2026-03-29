import { z } from 'zod'
import type {
  ClientCapabilities,
  CreateMessageRequest,
  CreateMessageResult,
  CreateMessageResultWithTools,
  Implementation,
  TextContent,
} from '@modelcontextprotocol/sdk/types.js'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { MCPServer } from '../server.js'
import { createCodeModuleReviewPrepareHandler } from './code-module-review-prepare.js'
import { createCodeModuleReviewApplyHandler } from './code-module-review-apply.js'

const TOOL_NAME = 'code.module.review'

/**
 * @deprecated Use `llm.analyze` with task='review' instead.
 * This tool will be removed in a future version.
 * Migration guide: docs/MIGRATION.md
 */

const ReviewModuleSchema = z.object({
  module_name: z.string().min(1).max(120),
  refined_name: z.string().min(1).max(120).optional(),
  summary: z.string().min(1).max(1600),
  role_hint: z.string().min(1).max(240),
  confidence: z.number().min(0).max(1),
  assumptions: z.array(z.string()).optional().default([]),
  evidence_used: z.array(z.string()).optional().default([]),
  rewrite_guidance: z.union([z.string().min(1), z.array(z.string().min(1))]).optional(),
  focus_areas: z.array(z.string().min(1)).optional().default([]),
  priority_functions: z.array(z.string().min(1)).optional().default([]),
})

const ReviewModulePayloadSchema = z.object({
  reviews: z.array(ReviewModuleSchema).min(1),
})

export const codeModuleReviewInputSchema = z
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
    include_imports: z.boolean().default(true).describe('Use import features for module hints'),
    include_strings: z.boolean().default(true).describe('Use high-value string clusters for module hints'),
    analysis_goal: z
      .string()
      .min(1)
      .max(400)
      .default(
        'Review reconstructed modules, refine their role labels, and propose evidence-grounded rewrite guidance.'
      )
      .describe('Human-readable analysis goal injected into the MCP prompt and sampling request'),
    session_tag: z
      .string()
      .optional()
      .describe('Optional semantic module review session tag used for artifact grouping'),
    evidence_scope: z
      .enum(['all', 'latest', 'session'])
      .default('all')
      .describe('Runtime evidence scope forwarded to prepare and optional export refresh'),
    evidence_session_tag: z
      .string()
      .optional()
      .describe('Optional runtime evidence session selector used when evidence_scope=session or to narrow all/latest results'),
    semantic_scope: z
      .enum(['all', 'latest', 'session'])
      .default('all')
      .describe('Semantic artifact scope forwarded to prepare and optional export refresh'),
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
      .describe('Optional role-aware focus areas forwarded to module preparation'),
    role_priority_order: z
      .array(z.string().min(1).max(96))
      .max(24)
      .default([])
      .describe('Optional role-aware priority-order hints forwarded to module preparation'),
    persist_artifact: z
      .boolean()
      .default(true)
      .describe('Persist the prepared bundle artifact before requesting external module review'),
    auto_apply: z
      .boolean()
      .default(true)
      .describe('Persist accepted module reviews automatically via code.module.review.apply'),
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
      .default(2400)
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
    cost_priority: z.number().min(0).max(1).default(0.1),
    speed_priority: z.number().min(0).max(1).default(0.2),
    intelligence_priority: z.number().min(0).max(1).default(0.95),
    system_prompt: z
      .string()
      .min(1)
      .max(800)
      .optional()
      .describe('Optional extra system prompt for the client-mediated module review'),
  })
  .refine((value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()), {
    message: 'evidence_session_tag is required when evidence_scope=session',
    path: ['evidence_session_tag'],
  })
  .refine((value) => value.semantic_scope !== 'session' || Boolean(value.semantic_session_tag?.trim()), {
    message: 'semantic_session_tag is required when semantic_scope=session',
    path: ['semantic_session_tag'],
  })

export const codeModuleReviewOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      review_status: z.enum([
        'sampled_and_applied',
        'sampled_only',
        'prompt_contract_only',
        'no_targets',
        'sampling_parse_failed',
      ]),
      prompt_name: z.literal('reverse.module_reconstruction_review'),
      prompt_arguments: z.object({
        analysis_goal: z.string(),
        prepared_bundle_json: z.string(),
      }),
      task_prompt: z.string(),
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
        response_text: z.string().nullable(),
        parsed_review_count: z.number().int().nonnegative(),
      }),
      apply: z.object({
        attempted: z.boolean(),
        accepted_count: z.number().int().nonnegative(),
        rejected_count: z.number().int().nonnegative(),
        artifact_id: z.string().nullable(),
      }),
      confidence_policy: z.object({
        calibrated: z.boolean(),
        review_scores_are_heuristic: z.boolean(),
        meaning: z.string(),
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

export const codeModuleReviewToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Use MCP client-mediated sampling to request an external LLM review of reconstructed modules, then optionally persist module-level summaries and rewrite guidance.',
  inputSchema: codeModuleReviewInputSchema,
  outputSchema: codeModuleReviewOutputSchema,
}

type SamplingResult = CreateMessageResult | CreateMessageResultWithTools

interface CodeModuleReviewDependencies {
  prepareHandler?: (args: ToolArgs) => Promise<WorkerResult>
  applyHandler?: (args: ToolArgs) => Promise<WorkerResult>
  samplingRequester?: (params: CreateMessageRequest['params']) => Promise<SamplingResult>
  clientCapabilitiesProvider?: () => ClientCapabilities | undefined
  clientVersionProvider?: () => Implementation | undefined
}

function extractTextBlocks(result: SamplingResult): string {
  const blocks = Array.isArray(result.content) ? result.content : [result.content]
  return blocks
    .filter((block): block is TextContent => block?.type === 'text')
    .map((block) => block.text || '')
    .join('\n')
    .trim()
}

function extractJsonCandidates(rawText: string): string[] {
  const trimmed = rawText.trim()
  const candidates = new Set<string>()
  if (trimmed.length > 0) {
    candidates.add(trimmed)
  }
  const fencedMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i)
  if (fencedMatch?.[1]) {
    candidates.add(fencedMatch[1].trim())
  }
  const firstBrace = trimmed.indexOf('{')
  const lastBrace = trimmed.lastIndexOf('}')
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    candidates.add(trimmed.slice(firstBrace, lastBrace + 1))
  }
  const firstBracket = trimmed.indexOf('[')
  const lastBracket = trimmed.lastIndexOf(']')
  if (firstBracket >= 0 && lastBracket > firstBracket) {
    candidates.add(trimmed.slice(firstBracket, lastBracket + 1))
  }
  return Array.from(candidates)
}

function parseSamplingReviews(rawText: string): z.infer<typeof ReviewModuleSchema>[] {
  for (const candidate of extractJsonCandidates(rawText)) {
    try {
      const parsed = JSON.parse(candidate)
      if (Array.isArray(parsed)) {
        return ReviewModulePayloadSchema.parse({ reviews: parsed }).reviews
      }
      return ReviewModulePayloadSchema.parse(parsed).reviews
    } catch {
      continue
    }
  }
  throw new Error(
    'Sampling response could not be parsed as strict JSON module reviews. Return {"reviews":[...]} only.'
  )
}

function buildSamplingRequest(
  input: z.infer<typeof codeModuleReviewInputSchema>,
  taskPrompt: string
): CreateMessageRequest['params'] {
  const invariantSystemPrompt = [
    'You are an evidence-grounded reverse-engineering assistant.',
    'Return strict JSON only.',
    'Do not wrap the response in markdown, code fences, or commentary.',
    'Do not call tools.',
    'Use only the supplied evidence bundle.',
    'Preserve uncertainty explicitly.',
    'Prefer empty results or conservative review guidance over hallucinated precision.',
  ].join(' ')

  return {
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text: taskPrompt,
        },
      },
    ],
    systemPrompt: input.system_prompt
      ? `${invariantSystemPrompt}\n\nAdditional task constraints:\n${input.system_prompt}`
      : invariantSystemPrompt,
    includeContext: input.include_context,
    maxTokens: input.max_tokens,
    temperature: input.temperature,
    modelPreferences: {
      hints: input.model_hint ? [{ name: input.model_hint }] : undefined,
      costPriority: input.cost_priority,
      speedPriority: input.speed_priority,
      intelligencePriority: input.intelligence_priority,
    },
  }
}

function buildModuleReviewConfidencePolicy() {
  return {
    calibrated: false,
    review_scores_are_heuristic: true,
    meaning:
      'Module review confidence values rank evidence support strength only. They do not prove semantic equivalence or recover original source-level intent with calibrated probability.',
  }
}

export function createCodeModuleReviewHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  mcpServer?: MCPServer,
  dependencies?: CodeModuleReviewDependencies
) {
  const prepareHandler =
    dependencies?.prepareHandler ||
    createCodeModuleReviewPrepareHandler(workspaceManager, database, cacheManager)
  const applyHandler =
    dependencies?.applyHandler || createCodeModuleReviewApplyHandler(workspaceManager, database)
  const samplingRequester =
    dependencies?.samplingRequester ||
    (mcpServer ? (params: CreateMessageRequest['params']) => mcpServer.createMessage(params) : undefined)
  const clientCapabilitiesProvider =
    dependencies?.clientCapabilitiesProvider ||
    (mcpServer ? () => mcpServer.getClientCapabilities() : undefined)
  const clientVersionProvider =
    dependencies?.clientVersionProvider ||
    (mcpServer ? () => mcpServer.getClientVersion() : undefined)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const warnings: string[] = []
    const artifacts: any[] = []
    try {
      const input = codeModuleReviewInputSchema.parse(args)
      const prepareResult = await prepareHandler({
        sample_id: input.sample_id,
        topk: input.topk,
        module_limit: input.module_limit,
        min_module_size: input.min_module_size,
        include_imports: input.include_imports,
        include_strings: input.include_strings,
        analysis_goal: input.analysis_goal,
        persist_artifact: input.persist_artifact,
        session_tag: input.session_tag,
        evidence_scope: input.evidence_scope,
        evidence_session_tag: input.evidence_session_tag,
        semantic_scope: input.semantic_scope,
        semantic_session_tag: input.semantic_session_tag,
        role_target: input.role_target,
        role_focus_areas: input.role_focus_areas,
        role_priority_order: input.role_priority_order,
      })

      warnings.push(...(prepareResult.warnings || []))
      artifacts.push(...(prepareResult.artifacts || []))

      if (!prepareResult.ok) {
        return {
          ok: false,
          errors: prepareResult.errors || ['code.module.review.prepare failed'],
          warnings: warnings.length > 0 ? warnings : undefined,
          artifacts: artifacts.length > 0 ? artifacts : undefined,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const prepareData = (prepareResult.data || {}) as any
      const preparedCount = Number(prepareData.prepared_count || 0)
      const prepareArtifactId = prepareData.artifact?.id || null
      const promptArguments = prepareData.prompt_arguments
      const taskPrompt = prepareData.task_prompt
      const clientCapabilities = clientCapabilitiesProvider?.()
      const samplingAvailable = Boolean(clientCapabilities?.sampling && samplingRequester)
      const clientVersion = clientVersionProvider?.()

      if (preparedCount === 0) {
        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            review_status: 'no_targets',
            prompt_name: 'reverse.module_reconstruction_review',
            prompt_arguments: promptArguments,
            task_prompt: taskPrompt,
            client: {
              name: clientVersion?.name || null,
              version: clientVersion?.version || null,
              sampling_available: samplingAvailable,
            },
            prepare: {
              prepared_count: 0,
              artifact_id: prepareArtifactId,
            },
            sampling: {
              attempted: false,
              model: null,
              stop_reason: null,
              response_text: null,
              parsed_review_count: 0,
            },
            apply: {
              attempted: false,
              accepted_count: 0,
              rejected_count: 0,
              artifact_id: null,
            },
            confidence_policy: buildModuleReviewConfidencePolicy(),
            next_steps: ['increase topk or module_limit', 'rerun code.reconstruct.export to produce module output'],
          },
          warnings: warnings.length > 0 ? warnings : undefined,
          artifacts: artifacts.length > 0 ? artifacts : undefined,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      if (!samplingAvailable) {
        warnings.push(
          'Connected MCP client did not advertise sampling support; returning prompt contract only.'
        )
        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            review_status: 'prompt_contract_only',
            prompt_name: 'reverse.module_reconstruction_review',
            prompt_arguments: promptArguments,
            task_prompt: taskPrompt,
            client: {
              name: clientVersion?.name || null,
              version: clientVersion?.version || null,
              sampling_available: false,
            },
            prepare: {
              prepared_count: preparedCount,
              artifact_id: prepareArtifactId,
            },
            sampling: {
              attempted: false,
              model: null,
              stop_reason: null,
              response_text: null,
              parsed_review_count: 0,
            },
            apply: {
              attempted: false,
              accepted_count: 0,
              rejected_count: 0,
              artifact_id: null,
            },
            confidence_policy: buildModuleReviewConfidencePolicy(),
            next_steps: [
              'call prompts/get for reverse.module_reconstruction_review with the returned prompt arguments',
              'send the prompt to any MCP-capable tool-calling LLM client that supports sampling or manual prompt execution',
              'pass the JSON result to code.module.review.apply',
            ],
          },
          warnings: warnings.length > 0 ? warnings : undefined,
          artifacts: artifacts.length > 0 ? artifacts : undefined,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const samplingResult = await samplingRequester!(buildSamplingRequest(input, taskPrompt))
      const responseText = extractTextBlocks(samplingResult)
      let parsedReviews: z.infer<typeof ReviewModuleSchema>[]
      try {
        parsedReviews = parseSamplingReviews(responseText)
      } catch (error) {
        warnings.push(error instanceof Error ? error.message : String(error))
        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            review_status: 'sampling_parse_failed',
            prompt_name: 'reverse.module_reconstruction_review',
            prompt_arguments: promptArguments,
            task_prompt: taskPrompt,
            client: {
              name: clientVersion?.name || null,
              version: clientVersion?.version || null,
              sampling_available: true,
            },
            prepare: {
              prepared_count: preparedCount,
              artifact_id: prepareArtifactId,
            },
            sampling: {
              attempted: true,
              model: samplingResult.model || null,
              stop_reason: samplingResult.stopReason || null,
              response_text: responseText || null,
              parsed_review_count: 0,
            },
            apply: {
              attempted: false,
              accepted_count: 0,
              rejected_count: 0,
              artifact_id: null,
            },
            confidence_policy: buildModuleReviewConfidencePolicy(),
            next_steps: [
              'inspect the sampling response and ensure it returns strict JSON with the shape {"reviews":[...]}',
              'rerun code.module.review with a stricter system_prompt if needed',
            ],
          },
          warnings: warnings.length > 0 ? warnings : undefined,
          artifacts: artifacts.length > 0 ? artifacts : undefined,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      let applyAttempted = false
      let applyAcceptedCount = 0
      let applyRejectedCount = 0
      let applyArtifactId: string | null = null

      if (input.auto_apply) {
        applyAttempted = true
        const applyResult = await applyHandler({
          sample_id: input.sample_id,
          client_name: clientVersion?.name || null,
          model_name: samplingResult.model || null,
          prepare_artifact_id: prepareArtifactId || undefined,
          session_tag: input.session_tag,
          reviews: parsedReviews,
        })
        warnings.push(...(applyResult.warnings || []))
        artifacts.push(...(applyResult.artifacts || []))
        if (!applyResult.ok) {
          return {
            ok: false,
            errors: applyResult.errors || ['code.module.review.apply failed'],
            warnings: warnings.length > 0 ? warnings : undefined,
            artifacts: artifacts.length > 0 ? artifacts : undefined,
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
            },
          }
        }
        applyAcceptedCount = Number((applyResult.data as any)?.accepted_count || 0)
        applyRejectedCount = Number((applyResult.data as any)?.rejected_count || 0)
        applyArtifactId = ((applyResult.data as any)?.artifact?.id as string | undefined) || null
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          review_status: input.auto_apply ? 'sampled_and_applied' : 'sampled_only',
          prompt_name: 'reverse.module_reconstruction_review',
          prompt_arguments: promptArguments,
          task_prompt: taskPrompt,
          client: {
            name: clientVersion?.name || null,
            version: clientVersion?.version || null,
            sampling_available: true,
          },
          prepare: {
            prepared_count: preparedCount,
            artifact_id: prepareArtifactId,
          },
          sampling: {
            attempted: true,
            model: samplingResult.model || null,
            stop_reason: samplingResult.stopReason || null,
            response_text: responseText || null,
            parsed_review_count: parsedReviews.length,
          },
          apply: {
            attempted: applyAttempted,
            accepted_count: applyAcceptedCount,
            rejected_count: applyRejectedCount,
            artifact_id: applyArtifactId,
          },
          confidence_policy: buildModuleReviewConfidencePolicy(),
          next_steps: input.auto_apply
            ? [
                'rerun code.reconstruct.export or workflow.reconstruct to propagate module review summaries into rewrite output',
                'inspect reverse_notes.md and module rewrite headers for updated module-level guidance',
              ]
            : ['pass the parsed JSON result to code.module.review.apply'],
        },
        warnings: warnings.length > 0 ? warnings : undefined,
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
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
