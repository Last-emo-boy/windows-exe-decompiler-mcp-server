import { z } from 'zod'
import type {
  ClientCapabilities,
  CreateMessageRequest,
  CreateMessageResult,
  CreateMessageResultWithTools,
  Implementation,
  TextContent,
} from '@modelcontextprotocol/sdk/types.js'
import type { ToolArgs, ToolDefinition, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { MCPServer } from '../server.js'
import { createCodeFunctionRenamePrepareHandler } from './code-function-rename-prepare.js'
import { createCodeFunctionRenameApplyHandler } from './code-function-rename-apply.js'
import { createCodeFunctionsReconstructHandler } from './code-functions-reconstruct.js'

const TOOL_NAME = 'code.function.rename.review'

/**
 * @deprecated Use `llm.analyze` with task='review' instead.
 * This tool will be removed in a future version.
 * Migration guide: docs/MIGRATION.md
 */

const ReviewSuggestionSchema = z
  .object({
    address_or_function: z.string().optional(),
    address: z.string().optional(),
    function: z.string().optional(),
    candidate_name: z.string().min(1).max(160),
    confidence: z.number().min(0).max(1),
    why: z.string().min(1).max(1000),
    required_assumptions: z.array(z.string()).optional().default([]),
    evidence_used: z.array(z.string()).optional().default([]),
  })
  .refine(
    (value) =>
      Boolean(value.address_or_function?.trim()) ||
      Boolean(value.address?.trim()) ||
      Boolean(value.function?.trim()),
    {
      message: 'Each suggestion must provide address_or_function, address, or function.',
    }
  )

const ReviewSuggestionPayloadSchema = z.object({
  suggestions: z.array(ReviewSuggestionSchema).min(1),
})

export const codeFunctionRenameReviewInputSchema = z.object({
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
    .describe('Maximum number of functions included in the review bundle'),
  include_resolved: z
    .boolean()
    .default(false)
    .describe('Include functions that already have validated names in the initial review request'),
  auto_include_resolved_on_empty: z
    .boolean()
    .default(true)
    .describe('When unresolved selection is empty, automatically retry in audit mode with include_resolved=true'),
  analysis_goal: z
    .string()
    .min(1)
    .max(400)
    .default(
      'Reverse-engineer the prepared functions and propose precise human-readable semantic names.'
    )
    .describe('Human-readable analysis goal injected into the MCP prompt and sampling request'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional semantic naming session tag used for artifact grouping'),
  evidence_scope: z
    .enum(['all', 'latest', 'session'])
    .default('all')
    .describe('Runtime evidence scope forwarded to prepare and reconstruct passes'),
  evidence_session_tag: z
    .string()
    .optional()
    .describe('Optional runtime evidence session selector used when evidence_scope=session or to narrow all/latest results'),
  semantic_scope: z
    .enum(['all', 'latest', 'session'])
    .default('all')
    .describe('Semantic naming artifact scope used for prepare and rerun reconstruct passes'),
  semantic_session_tag: z
    .string()
    .optional()
    .describe('Optional semantic naming session selector used when semantic_scope=session or to narrow all/latest results'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist the prepare bundle artifact before requesting external semantic review'),
  auto_apply: z
    .boolean()
    .default(true)
    .describe('Persist accepted suggestions automatically via code.function.rename.apply'),
  rerun_reconstruct: z
    .boolean()
    .default(true)
    .describe('Rerun code.functions.reconstruct after apply to materialize llm/hybrid validated names'),
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
    .default(1800)
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
    .describe('Optional extra system prompt for the client-mediated semantic naming review'),
})
  .refine((value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()), {
    message: 'evidence_session_tag is required when evidence_scope=session',
    path: ['evidence_session_tag'],
  })
  .refine((value) => value.semantic_scope !== 'session' || Boolean(value.semantic_session_tag?.trim()), {
    message: 'semantic_session_tag is required when semantic_scope=session',
    path: ['semantic_session_tag'],
  })

export const codeFunctionRenameReviewOutputSchema = z.object({
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
      prompt_name: z.literal('reverse.semantic_name_review'),
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
        unresolved_count: z.number().int().nonnegative(),
        include_resolved: z.boolean(),
        artifact_id: z.string().nullable(),
      }),
      sampling: z.object({
        attempted: z.boolean(),
        model: z.string().nullable(),
        stop_reason: z.string().nullable(),
        response_text: z.string().nullable(),
        parsed_suggestion_count: z.number().int().nonnegative(),
      }),
      apply: z.object({
        attempted: z.boolean(),
        accepted_count: z.number().int().nonnegative(),
        rejected_count: z.number().int().nonnegative(),
        artifact_id: z.string().nullable(),
      }),
      reconstruct: z.object({
        attempted: z.boolean(),
        reconstructed_count: z.number().int().nonnegative(),
        llm_or_hybrid_count: z.number().int().nonnegative(),
        functions: z.array(
          z.object({
            function: z.string(),
            address: z.string(),
            validated_name: z.string().nullable(),
            resolution_source: z.string().nullable(),
          })
        ),
      }),
      confidence_policy: z.object({
        calibrated: z.boolean(),
        rule_priority_over_llm: z.boolean(),
        llm_acceptance_threshold: z.number().min(0).max(1),
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

export const codeFunctionRenameReviewToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Use MCP client-mediated sampling to request an external LLM semantic naming review, then optionally persist and materialize the resulting suggestions.',
  inputSchema: codeFunctionRenameReviewInputSchema,
  outputSchema: codeFunctionRenameReviewOutputSchema,
}

type SamplingResult = CreateMessageResult | CreateMessageResultWithTools

interface CodeFunctionRenameReviewDependencies {
  prepareHandler?: (args: ToolArgs) => Promise<WorkerResult>
  applyHandler?: (args: ToolArgs) => Promise<WorkerResult>
  reconstructHandler?: (args: ToolArgs) => Promise<WorkerResult>
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

function normalizeSuggestionIdentifier(
  suggestion: z.infer<typeof ReviewSuggestionSchema>
): {
  address?: string
  function?: string
} {
  const normalizedAddress = suggestion.address?.trim()
  const normalizedFunction = suggestion.function?.trim()

  if (normalizedAddress || normalizedFunction) {
    return {
      address: normalizedAddress || undefined,
      function: normalizedFunction || undefined,
    }
  }

  const identifier = suggestion.address_or_function?.trim()
  if (!identifier) {
    return {}
  }

  if (/^(0x)?[0-9a-f]+$/i.test(identifier)) {
    return { address: identifier }
  }

  return { function: identifier }
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

function parseSamplingSuggestions(rawText: string): z.infer<typeof ReviewSuggestionSchema>[] {
  const candidates = extractJsonCandidates(rawText)

  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate)
      if (Array.isArray(parsed)) {
        return ReviewSuggestionPayloadSchema.parse({ suggestions: parsed }).suggestions
      }
      return ReviewSuggestionPayloadSchema.parse(parsed).suggestions
    } catch {
      continue
    }
  }

  throw new Error(
    'Sampling response could not be parsed as strict JSON suggestions. Return {"suggestions":[...]} only.'
  )
}

async function runPrepare(
  prepareHandler: (args: ToolArgs) => Promise<WorkerResult>,
  input: z.infer<typeof codeFunctionRenameReviewInputSchema>,
  includeResolved: boolean
) {
  return prepareHandler({
    sample_id: input.sample_id,
    address: input.address,
    symbol: input.symbol,
    topk: input.topk,
    max_functions: input.max_functions,
    include_resolved: includeResolved,
    analysis_goal: input.analysis_goal,
    persist_artifact: input.persist_artifact,
    session_tag: input.session_tag,
    evidence_scope: input.evidence_scope,
    evidence_session_tag: input.evidence_session_tag,
    semantic_scope: input.semantic_scope,
    semantic_session_tag: input.semantic_session_tag,
  })
}

function buildSamplingRequest(
  input: z.infer<typeof codeFunctionRenameReviewInputSchema>,
  taskPrompt: string
): CreateMessageRequest['params'] {
  const invariantSystemPrompt = [
    'You are an evidence-grounded reverse-engineering assistant.',
    'Return strict JSON only.',
    'Do not wrap the response in markdown, code fences, or commentary.',
    'Do not call tools.',
    'Use only the supplied evidence bundle.',
    'Preserve uncertainty explicitly.',
    'Prefer empty results or low-confidence candidates over hallucinated precision.',
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

function buildNamingConfidencePolicy() {
  return {
    calibrated: false,
    rule_priority_over_llm: true,
    llm_acceptance_threshold: 0.62,
    meaning:
      'Naming confidence values are heuristic support scores. Rule-based names take priority, and pure LLM suggestions are promoted only when llm_confidence >= 0.62.',
  }
}

export function createCodeFunctionRenameReviewHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  mcpServer?: MCPServer,
  dependencies?: CodeFunctionRenameReviewDependencies
) {
  const prepareHandler =
    dependencies?.prepareHandler ||
    createCodeFunctionRenamePrepareHandler(workspaceManager, database, cacheManager)
  const applyHandler =
    dependencies?.applyHandler ||
    createCodeFunctionRenameApplyHandler(workspaceManager, database)
  const reconstructHandler =
    dependencies?.reconstructHandler ||
    createCodeFunctionsReconstructHandler(workspaceManager, database, cacheManager)
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
    const artifacts: ArtifactRef[] = []

    try {
      const input = codeFunctionRenameReviewInputSchema.parse(args)
      let usedIncludeResolved = input.include_resolved
      let prepareResult = await runPrepare(prepareHandler, input, usedIncludeResolved)

      if (
        prepareResult.ok &&
        ((prepareResult.data as any)?.prepared_count || 0) === 0 &&
        !usedIncludeResolved &&
        input.auto_include_resolved_on_empty
      ) {
        warnings.push(
          'Initial unresolved-only review set was empty; automatically retried in audit mode with include_resolved=true.'
        )
        usedIncludeResolved = true
        prepareResult = await runPrepare(prepareHandler, input, usedIncludeResolved)
      }

      if (!prepareResult.ok) {
        return {
          ok: false,
          errors: prepareResult.errors || ['code.function.rename.prepare failed'],
          warnings: prepareResult.warnings,
          artifacts: prepareResult.artifacts,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      warnings.push(...(prepareResult.warnings || []))
      artifacts.push(...(prepareResult.artifacts || []))
      const prepareData = (prepareResult.data || {}) as any
      const preparedCount = Number(prepareData.prepared_count || 0)
      const unresolvedCount = Number(prepareData.unresolved_count || 0)
      const taskPrompt = String(prepareData.task_prompt || '')
      const promptArguments = prepareData.prompt_arguments || {
        analysis_goal: input.analysis_goal,
        prepared_bundle_json: '',
      }
      const prepareArtifactId =
        prepareData.artifact?.id || (prepareResult.artifacts || [])[0]?.id || null

      const clientVersion = clientVersionProvider?.()
      const clientCapabilities = clientCapabilitiesProvider?.()
      const samplingAvailable = Boolean(clientCapabilities?.sampling && samplingRequester)

      if (preparedCount === 0) {
        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            review_status: 'no_targets',
            prompt_name: 'reverse.semantic_name_review',
            prompt_arguments: promptArguments,
            task_prompt: taskPrompt,
            client: {
              name: clientVersion?.name || null,
              version: clientVersion?.version || null,
              sampling_available: samplingAvailable,
            },
            prepare: {
              prepared_count: preparedCount,
              unresolved_count: unresolvedCount,
              include_resolved: usedIncludeResolved,
              artifact_id: prepareArtifactId,
            },
            sampling: {
              attempted: false,
              model: null,
              stop_reason: null,
              response_text: null,
              parsed_suggestion_count: 0,
            },
            apply: {
              attempted: false,
              accepted_count: 0,
              rejected_count: 0,
              artifact_id: null,
            },
            reconstruct: {
              attempted: false,
              reconstructed_count: 0,
              llm_or_hybrid_count: 0,
              functions: [],
            },
            confidence_policy: buildNamingConfidencePolicy(),
            next_steps: [
              'increase topk or max_functions',
              'set include_resolved=true to audit existing rule-based names',
              'target a specific address or symbol for review',
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
            prompt_name: 'reverse.semantic_name_review',
            prompt_arguments: promptArguments,
            task_prompt: taskPrompt,
            client: {
              name: clientVersion?.name || null,
              version: clientVersion?.version || null,
              sampling_available: false,
            },
            prepare: {
              prepared_count: preparedCount,
              unresolved_count: unresolvedCount,
              include_resolved: usedIncludeResolved,
              artifact_id: prepareArtifactId,
            },
            sampling: {
              attempted: false,
              model: null,
              stop_reason: null,
              response_text: null,
              parsed_suggestion_count: 0,
            },
            apply: {
              attempted: false,
              accepted_count: 0,
              rejected_count: 0,
              artifact_id: null,
            },
            reconstruct: {
              attempted: false,
              reconstructed_count: 0,
              llm_or_hybrid_count: 0,
              functions: [],
            },
            confidence_policy: buildNamingConfidencePolicy(),
            next_steps: [
              'call prompts/get for reverse.semantic_name_review with the returned prompt arguments',
              'send the prompt to any MCP-capable tool-calling LLM client that supports sampling or manual prompt execution',
              'pass the JSON result to code.function.rename.apply',
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

      let parsedSuggestions: z.infer<typeof ReviewSuggestionSchema>[] = []
      try {
        parsedSuggestions = parseSamplingSuggestions(responseText)
      } catch (error) {
        warnings.push(error instanceof Error ? error.message : String(error))
        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            review_status: 'sampling_parse_failed',
            prompt_name: 'reverse.semantic_name_review',
            prompt_arguments: promptArguments,
            task_prompt: taskPrompt,
            client: {
              name: clientVersion?.name || null,
              version: clientVersion?.version || null,
              sampling_available: true,
            },
            prepare: {
              prepared_count: preparedCount,
              unresolved_count: unresolvedCount,
              include_resolved: usedIncludeResolved,
              artifact_id: prepareArtifactId,
            },
            sampling: {
              attempted: true,
              model: samplingModel,
              stop_reason: stopReason,
              response_text: responseText || null,
              parsed_suggestion_count: 0,
            },
            apply: {
              attempted: false,
              accepted_count: 0,
              rejected_count: 0,
              artifact_id: null,
            },
            reconstruct: {
              attempted: false,
              reconstructed_count: 0,
              llm_or_hybrid_count: 0,
              functions: [],
            },
            confidence_policy: buildNamingConfidencePolicy(),
            next_steps: [
              'inspect the sampling response text and ensure the client returned strict JSON',
              'rerun code.function.rename.review or use code.function.rename.apply manually with corrected JSON',
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
            prompt_name: 'reverse.semantic_name_review',
            prompt_arguments: promptArguments,
            task_prompt: taskPrompt,
            client: {
              name: clientVersion?.name || null,
              version: clientVersion?.version || null,
              sampling_available: true,
            },
            prepare: {
              prepared_count: preparedCount,
              unresolved_count: unresolvedCount,
              include_resolved: usedIncludeResolved,
              artifact_id: prepareArtifactId,
            },
            sampling: {
              attempted: true,
              model: samplingModel,
              stop_reason: stopReason,
              response_text: responseText || null,
              parsed_suggestion_count: parsedSuggestions.length,
            },
            apply: {
              attempted: false,
              accepted_count: 0,
              rejected_count: 0,
              artifact_id: null,
            },
            reconstruct: {
              attempted: false,
              reconstructed_count: 0,
              llm_or_hybrid_count: 0,
              functions: [],
            },
            confidence_policy: buildNamingConfidencePolicy(),
            next_steps: [
              'pass the parsed JSON payload to code.function.rename.apply',
              'rerun code.functions.reconstruct or code.reconstruct.export after apply',
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

      const applySuggestions = parsedSuggestions.map((suggestion) => ({
        ...normalizeSuggestionIdentifier(suggestion),
        candidate_name: suggestion.candidate_name,
        confidence: suggestion.confidence,
        why: suggestion.why,
        required_assumptions: suggestion.required_assumptions || [],
        evidence_used: suggestion.evidence_used || [],
      }))

      const applyResult = await applyHandler({
        sample_id: input.sample_id,
        suggestions: applySuggestions,
        client_name: clientVersion?.name,
        model_name: samplingModel || undefined,
        prepare_artifact_id: prepareArtifactId || undefined,
        session_tag: input.session_tag,
      })

      if (!applyResult.ok) {
        return {
          ok: false,
          errors: applyResult.errors || ['code.function.rename.apply failed'],
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

      let reconstructData = {
        attempted: false,
        reconstructed_count: 0,
        llm_or_hybrid_count: 0,
        functions: [] as Array<{
          function: string
          address: string
          validated_name: string | null
          resolution_source: string | null
        }>,
      }

      if (input.rerun_reconstruct) {
        const rerunSemanticScope =
          input.semantic_scope === 'all' && input.session_tag ? 'session' : input.semantic_scope
        const rerunSemanticSessionTag = input.semantic_session_tag || input.session_tag
        const reconstructResult = await reconstructHandler({
          sample_id: input.sample_id,
          address: input.address,
          symbol: input.symbol,
          topk: input.topk,
          include_xrefs: true,
          max_pseudocode_lines: 80,
          max_assembly_lines: 60,
          timeout: 45,
          evidence_scope: input.evidence_scope,
          evidence_session_tag: input.evidence_session_tag,
          semantic_scope: rerunSemanticScope,
          semantic_session_tag: rerunSemanticSessionTag,
        })

        if (!reconstructResult.ok) {
          return {
            ok: false,
            errors: reconstructResult.errors || ['code.functions.reconstruct failed after semantic name apply'],
            warnings: [...warnings, ...(reconstructResult.warnings || [])],
            artifacts: artifacts.length > 0 ? artifacts : undefined,
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
            },
          }
        }

        warnings.push(...(reconstructResult.warnings || []))
        const reconstructedFunctions = (((reconstructResult.data as any)?.functions || []) as any[]).map((item) => ({
          function: item.function,
          address: item.address,
          validated_name: item?.name_resolution?.validated_name || null,
          resolution_source: item?.name_resolution?.resolution_source || null,
        }))

        reconstructData = {
          attempted: true,
          reconstructed_count: Number((reconstructResult.data as any)?.reconstructed_count || reconstructedFunctions.length),
          llm_or_hybrid_count: reconstructedFunctions.filter((item) =>
            item.resolution_source === 'llm' || item.resolution_source === 'hybrid'
          ).length,
          functions: reconstructedFunctions,
        }
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          review_status: 'sampled_and_applied',
          prompt_name: 'reverse.semantic_name_review',
          prompt_arguments: promptArguments,
          task_prompt: taskPrompt,
          client: {
            name: clientVersion?.name || null,
            version: clientVersion?.version || null,
            sampling_available: true,
          },
          prepare: {
            prepared_count: preparedCount,
            unresolved_count: unresolvedCount,
            include_resolved: usedIncludeResolved,
            artifact_id: prepareArtifactId,
          },
          sampling: {
            attempted: true,
            model: samplingModel,
            stop_reason: stopReason,
            response_text: responseText || null,
            parsed_suggestion_count: parsedSuggestions.length,
          },
          apply: {
            attempted: true,
            accepted_count: Number(applyData.accepted_count || 0),
            rejected_count: Number(applyData.rejected_count || 0),
            artifact_id: applyData.artifact?.id || null,
          },
          reconstruct: reconstructData,
          confidence_policy: buildNamingConfidencePolicy(),
          next_steps: input.rerun_reconstruct
            ? [
                'inspect reconstructed functions for llm or hybrid validated names',
                'rerun code.reconstruct.export to propagate validated names into rewrite output',
              ]
            : [
                'rerun code.functions.reconstruct to materialize llm or hybrid validated names',
                'rerun code.reconstruct.export after reconstruct if you want updated rewrite output',
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
