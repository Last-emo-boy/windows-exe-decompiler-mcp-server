/**
 * LLM Analysis - Unified Interface
 * Provides simplified LLM-assisted analysis through MCP Client
 * Tasks: llm-assisted-analysis-enhancement 1.1
 */

import { z } from 'zod'
import { logger } from '../logger.js'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { MCPServer } from '../server.js'
import type { CreateMessageRequest } from '@modelcontextprotocol/sdk/types.js'
import { estimateTokens } from '../performance-benchmark.js'

const TOOL_NAME = 'llm.analyze'

export const LlmAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  task: z.enum(['summarize', 'explain', 'recommend', 'review']).describe('LLM task type'),
  context: z.string().describe('Analysis context to provide to LLM'),
  goal: z.string().optional().describe('Analysis goal or question'),
  max_tokens: z.number().int().min(100).max(10000).default(2000).describe('Maximum tokens in response'),
  temperature: z.number().min(0).max(1).default(0.2).describe('LLM temperature (0=focused, 1=creative)'),
})

export const LlmAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string(),
    task: z.string(),
    response: z.string().describe('LLM response'),
    token_count: z.number().optional().describe('Estimated token count'),
  }).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({
    elapsed_ms: z.number(),
    tool: z.string(),
  }).optional(),
})

export type LlmAnalyzeInput = z.infer<typeof LlmAnalyzeInputSchema>

interface LlmAnalyzeDependencies {
  mcpServer?: MCPServer
}

export function createLlmAnalyzeHandler(
  mcpServer?: MCPServer
): (args: ToolArgs) => Promise<WorkerResult> {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const warnings: string[] = []

    try {
      const input = LlmAnalyzeInputSchema.parse(args)

      // Check if MCP Server is available
      if (!mcpServer) {
        return {
          ok: false,
          errors: ['LLM analysis requires MCP Server connection'],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      // Check if client supports sampling
      const capabilities = mcpServer.getClientCapabilities()
      if (!capabilities?.sampling) {
        return {
          ok: false,
          errors: ['Connected MCP Client does not support LLM sampling'],
          warnings: ['Please use an MCP Client with LLM capabilities (e.g., Claude Desktop, Cursor)'],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      // Build prompt based on task
      const prompt = buildPrompt(input)

      // Request LLM response through MCP Client
      const result = await mcpServer.createMessage({
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: prompt,
            },
          },
        ],
        maxTokens: input.max_tokens,
        temperature: input.temperature,
        systemPrompt: buildSystemPrompt(input.task),
      })

      const responseText = extractResponseText(result)
      
      // Calculate token count (estimate from response text)
      // Note: MCP sampling doesn't return usage stats, so we estimate
      const tokenCount = estimateTokens(responseText)

      // Log LLM usage for tracking
      logLlmUsage(input.sample_id, input.task, tokenCount)

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          task: input.task,
          response: responseText,
          token_count: tokenCount,
          model: (result as any).model,  // MCP returns model info
        },
        warnings: warnings.length > 0 ? warnings : undefined,
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

function buildSystemPrompt(task: string): string {
  const prompts: Record<string, string> = {
    summarize: 'You are an expert reverse engineering analyst. Provide concise, accurate summaries of binary analysis results.',
    explain: 'You are an expert reverse engineering analyst. Explain complex binary behavior in clear, accessible language.',
    recommend: 'You are an expert reverse engineering analyst. Provide actionable recommendations for next analysis steps.',
    review: 'You are an expert reverse engineering analyst. Review and critique analysis results, identifying gaps and suggesting improvements.',
  }
  return prompts[task] || 'You are an expert reverse engineering analyst.'
}

function buildPrompt(input: LlmAnalyzeInput): string {
  let prompt = `Context:\n${input.context}\n\n`
  
  switch (input.task) {
    case 'summarize':
      prompt += `Please summarize the analysis results for this sample.`
      break
    case 'explain':
      prompt += `Please explain the following aspect of the analysis.`
      break
    case 'recommend':
      prompt += `Please recommend next steps for this analysis.`
      break
    case 'review':
      prompt += `Please review the analysis and identify any gaps or issues.`
      break
  }
  
  if (input.goal) {
    prompt += `\n\nGoal: ${input.goal}`
  }
  
  return prompt
}

function extractResponseText(result: any): string {
  if (typeof result.content === 'string') {
    return result.content
  }
  
  if (Array.isArray(result.content)) {
    return result.content
      .filter((item: any) => item.type === 'text')
      .map((item: any) => item.text)
      .join('\n')
  }
  
  return String(result.content || '')
}

/**
 * Log LLM usage for token tracking
 */
function logLlmUsage(sampleId: string, task: string, tokenCount: number): void {
  logger.info({ sampleId, task, tokenCount }, 'LLM usage')
}

export const llmAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Unified LLM analysis interface. Automatically handles prepare/review/apply flow through MCP Client. ' +
    'Supports four task types: summarize (concise summaries), explain (clear explanations), ' +
    'recommend (actionable recommendations), and review (critical review). ' +
    'Requires MCP Client with LLM capabilities (e.g., Claude Desktop, Cursor).',
  inputSchema: LlmAnalyzeInputSchema,
  outputSchema: LlmAnalyzeOutputSchema,
}
