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
import { createCodeFunctionExplainPrepareHandler } from './code-function-explain-prepare.js'
import { createCodeFunctionExplainApplyHandler } from './code-function-explain-apply.js'

const TOOL_NAME = 'code.function.explain.review'

/**
 * @deprecated Use `llm.analyze` with task='explain' instead.
 * This tool will be removed in a future version.
 * Migration guide: docs/MIGRATION.md
 */

const ReviewExplanationSchema = z
  .object({
    address_or_function: z.string().optional(),
    address: z.string().optional(),
    function: z.string().optional(),
    summary: z.string().min(1).max(1200),
    behavior: z.string().min(1).max(160),
    confidence: z.number().min(0).max(1),
    assumptions: z.array(z.string()).optional().default([]),
    evidence_used: z.array(z.string()).optional().default([]),
    rewrite_guidance: z.union([z.string().min(1), z.array(z.string().min(1))]).optional(),
  })
  .refine(
    (value) =>
      Boolean(value.address_or_function?.trim()) ||
      Boolean(value.address?.trim()) ||
      Boolean(value.function?.trim()),
    {
      message: 'Each explanation must provide address_or_function, address, or function.',
    }
  )

const ReviewExplanationPayloadSchema = z.object({
  explanations: z.array(ReviewExplanationSchema).min(1),
})

export const codeFunctionExplainReviewInputSchema = z
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
      .describe('When address/symbol not provided, review up to top-K reconstructed functions'),
    max_functions: z
      .number()
      .int()
      .min(1)
      .max(20)
      .default(6)
      .describe('Maximum number of functions included in the explanation bundle'),
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
      .describe('Runtime evidence scope forwarded to prepare'),
    evidence_session_tag: z
      .string()
      .optional()
      .describe('Optional runtime evidence session selector used when evidence_scope=session or to narrow all/latest results'),
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
  })
  .refine((value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()), {
    message: 'evidence_session_tag is required when evidence_scope=session',
    path: ['evidence_session_tag'],
  })

export const codeFunctionExplainReviewOutputSchema = z.object({
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
      prompt_name: z.literal('reverse.function_explanation_review'),
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

export const codeFunctionExplainReviewToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Use MCP client-mediated sampling to request an external LLM explanation review, then optionally persist the resulting function explanations.',
  inputSchema: codeFunctionExplainReviewInputSchema,
  outputSchema: codeFunctionExplainReviewOutputSchema,
}

type SamplingResult = CreateMessageResult | CreateMessageResultWithTools

interface CodeFunctionExplainReviewDependencies {
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
  const candidates: string[] = []
  const trimmed = rawText.trim()
  if (trimmed.length > 0) {
    candidates.push(trimmed)
  }

  const fencedMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i)
  if (fencedMatch?.[1]) {
    candidates.push(fencedMatch[1].trim())
  }

  const firstBrace = trimmed.indexOf('{')
  const lastBrace = trimmed.lastIndexOf('}')
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    candidates.push(trimmed.slice(firstBrace, lastBrace + 1))
  }

  const firstBracket = trimmed.indexOf('[')
  const lastBracket = trimmed.lastIndexOf(']')
  if (firstBracket >= 0 && lastBracket > firstBracket) {
    candidates.push(trimmed.slice(firstBracket, lastBracket + 1))
  }

  return Array.from(new Set(candidates.filter((item) => item.length > 0)))
}

function parseSamplingExplanations(rawText: string): z.infer<typeof ReviewExplanationSchema>[] {
  const candidates = extractJsonCandidates(rawText)

  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate)
      if (Array.isArray(parsed)) {
        return ReviewExplanationPayloadSchema.parse({ explanations: parsed }).explanations
      }
      return ReviewExplanationPayloadSchema.parse(parsed).explanations
    } catch {
      continue
    }
  }

  throw new Error(
    'Sampling response could not be parsed as strict JSON explanations. Return {"explanations":[...]} only.'
  )
}

function buildSamplingRequest(
  input: z.infer<typeof codeFunctionExplainReviewInputSchema>,
  taskPrompt: string
): CreateMessageRequest['params'] {
  const invariantSystemPrompt = [
    'You are an evidence-grounded reverse-engineering assistant.',
    'Return strict JSON only.',
    'Do not wrap the response in markdown, code fences, or commentary.',
    'Do not call tools.',
    'Use only the supplied evidence bundle.',
    'Preserve uncertainty explicitly.',
    'Prefer empty results or conservative explanations over hallucinated precision.',
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

function buildExplanationConfidencePolicy() {
  return {
    calibrated: false,
    explanation_scores_are_heuristic: true,
    meaning:
      'Explanation confidence values rank evidence support strength only. They do not prove semantic equivalence or recover original source-level intent with calibrated probability.',
  }
}

export function createCodeFunctionExplainReviewHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  mcpServer?: MCPServer,
  dependencies?: CodeFunctionExplainReviewDependencies
) {
  const prepareHandler =
    dependencies?.prepareHandler ||
    createCodeFunctionExplainPrepareHandler(workspaceManager, database, cacheManager)
  const applyHandler =
    dependencies?.applyHandler ||
    createCodeFunctionExplainApplyHandler(workspaceManager, database)
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
      const input = codeFunctionExplainReviewInputSchema.parse(args)
      const prepareResult = await prepareHandler({
        sample_id: input.sample_id,
        address: input.address,
        symbol: input.symbol,
        topk: input.topk,
        max_functions: input.max_functions,
        include_resolved: input.include_resolved,
        analysis_goal: input.analysis_goal,
        persist_artifact: input.persist_artifact,
        session_tag: input.session_tag,
        evidence_scope: input.evidence_scope,
        evidence_session_tag: input.evidence_session_tag,
      })

      warnings.push(...(prepareResult.warnings || []))
      artifacts.push(...(prepareResult.artifacts || []))

      if (!prepareResult.ok) {
        return {
          ok: false,
          errors: prepareResult.errors || ['code.function.explain.prepare failed'],
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
            prompt_name: 'reverse.function_explanation_review',
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
              parsed_explanation_count: 0,
            },
            apply: {
              attempted: false,
              accepted_count: 0,
              rejected_count: 0,
              artifact_id: null,
            },
            confidence_policy: buildExplanationConfidencePolicy(),
            next_steps: [
              'increase topk or max_functions',
              'target a specific address or symbol for explanation review',
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

      if (!samplingAvailable) {
        warnings.push(
          'Connected MCP client did not advertise sampling support; returning prompt contract only.'
        )

        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            review_status: 'prompt_contract_only',
            prompt_name: 'reverse.function_explanation_review',
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
              parsed_explanation_count: 0,
            },
            apply: {
              attempted: false,
              accepted_count: 0,
              rejected_count: 0,
              artifact_id: null,
            },
            confidence_policy: buildExplanationConfidencePolicy(),
            next_steps: [
              'call prompts/get for reverse.function_explanation_review with the returned prompt arguments',
              'send the prompt to any MCP-capable tool-calling LLM client that supports sampling or manual prompt execution',
              'pass the JSON result to code.function.explain.apply',
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
      const samplingModel = (samplingResult as any)?.model || null
      const stopReason = (samplingResult as any)?.stopReason || null

      let parsedExplanations: z.infer<typeof ReviewExplanationSchema>[] = []
      try {
        parsedExplanations = parseSamplingExplanations(responseText)
      } catch (error) {
        warnings.push(error instanceof Error ? error.message : String(error))
        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            review_status: 'sampling_parse_failed',
            prompt_name: 'reverse.function_explanation_review',
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
              model: samplingModel,
              stop_reason: stopReason,
              response_text: responseText || null,
              parsed_explanation_count: 0,
            },
            apply: {
              attempted: false,
              accepted_count: 0,
              rejected_count: 0,
              artifact_id: null,
            },
            confidence_policy: buildExplanationConfidencePolicy(),
            next_steps: [
              'inspect the sampling response text and ensure the client returned strict JSON',
              'rerun code.function.explain.review or use code.function.explain.apply manually with corrected JSON',
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

      if (!input.auto_apply) {
        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            review_status: 'sampled_only',
            prompt_name: 'reverse.function_explanation_review',
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
              model: samplingModel,
              stop_reason: stopReason,
              response_text: responseText || null,
              parsed_explanation_count: parsedExplanations.length,
            },
            apply: {
              attempted: false,
              accepted_count: 0,
              rejected_count: 0,
              artifact_id: null,
            },
            confidence_policy: buildExplanationConfidencePolicy(),
            next_steps: [
              'pass the parsed JSON payload to code.function.explain.apply',
              'rerun code.reconstruct.export after apply to propagate explanation summaries into rewrite output',
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

      const applyResult = await applyHandler({
        sample_id: input.sample_id,
        explanations: parsedExplanations,
        client_name: clientVersion?.name,
        model_name: samplingModel || undefined,
        prepare_artifact_id: prepareArtifactId || undefined,
        session_tag: input.session_tag,
      })

      if (!applyResult.ok) {
        return {
          ok: false,
          errors: applyResult.errors || ['code.function.explain.apply failed'],
          warnings: [...warnings, ...(applyResult.warnings || [])],
          artifacts: [...artifacts, ...(applyResult.artifacts || [])],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      warnings.push(...(applyResult.warnings || []))
      artifacts.push(...(applyResult.artifacts || []))
      const applyData = (applyResult.data || {}) as any

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          review_status: 'sampled_and_applied',
          prompt_name: 'reverse.function_explanation_review',
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
            model: samplingModel,
            stop_reason: stopReason,
            response_text: responseText || null,
            parsed_explanation_count: parsedExplanations.length,
          },
          apply: {
            attempted: true,
            accepted_count: Number(applyData.accepted_count || 0),
            rejected_count: Number(applyData.rejected_count || 0),
            artifact_id: applyData.artifact?.id || null,
          },
          confidence_policy: buildExplanationConfidencePolicy(),
          next_steps: [
            'rerun code.reconstruct.export to propagate explanation summaries into rewrite output',
            'rerun report.generate or report.summarize if you want explanation artifacts reflected in analyst-facing output',
          ],
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
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
