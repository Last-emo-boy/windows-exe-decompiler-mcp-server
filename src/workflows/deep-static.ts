/**
 * Deep Static Analysis Workflow
 * 
 * Requirements: 16.1, 16.2, 16.3, 16.4, 16.5
 * 
 * Performs comprehensive static analysis including:
 * - Quick triage
 * - Ghidra analysis
 * - Function ranking
 * - Top function decompilation
 * - Report generation
 */

import { z } from 'zod';
import type { ToolDefinition, ToolHandler, ToolResult } from '../types.js';
import type { DatabaseManager } from '../database.js';
import type { WorkspaceManager } from '../workspace-manager.js';
import type { CacheManager } from '../cache-manager.js';
import type { JobQueue } from '../job-queue.js';
import { DecompilerWorker } from '../decompiler-worker.js';
import { logger } from '../logger.js';
import { triageWorkflow } from './triage.js';
import { buildPollingGuidance } from '../polling-guidance.js';
import {
  CoverageEnvelopeSchema,
  buildCoverageEnvelope,
  classifySampleSizeTier,
  deriveAnalysisBudgetProfile,
  mergeCoverageEnvelope,
} from '../analysis-coverage.js'

/**
 * Input schema for deep static workflow
 */
export const deepStaticWorkflowInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  options: z.object({
    top_functions: z.number().optional().describe('Number of top functions to decompile (default: 10)'),
    ghidra_timeout: z.number().optional().describe('Ghidra analysis timeout in seconds (default: 600)'),
    include_cfg: z.boolean().optional().describe('Include CFG for top functions (default: false)')
  }).optional()
});

export type DeepStaticWorkflowInput = z.infer<typeof deepStaticWorkflowInputSchema>;

const DeepStaticTopFunctionSchema = z.object({
  address: z.string(),
  name: z.string(),
  score: z.number(),
  reasons: z.array(z.string()),
  pseudocode: z.any().optional(),
  cfg: z.any().optional(),
})

export const deepStaticWorkflowOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      triage_summary: z.any().optional(),
      analysis_id: z.string().optional(),
      job_id: z.string().optional(),
      function_count: z.number().int().nonnegative().optional(),
      top_functions: z.array(DeepStaticTopFunctionSchema).optional(),
      report_path: z.string().optional(),
      elapsed_ms: z.number().optional(),
      status: z.string().optional(),
      tool: z.literal('workflow.deep_static').optional(),
      sample_id: z.string().optional(),
      progress: z.number().int().min(0).max(100).optional(),
      polling_guidance: z.any().nullable().optional(),
      result_mode: z.enum(['queued', 'completed']).optional(),
      recommended_next_tools: z.array(z.string()).optional(),
      next_actions: z.array(z.string()).optional(),
    })
    .extend(CoverageEnvelopeSchema.shape)
    .optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
})

/**
 * Deep static workflow result
 */
export interface DeepStaticWorkflowResult {
  ok: boolean;
  data?: {
    triage_summary: any;
    analysis_id: string;
    function_count: number;
    top_functions: Array<{
      address: string;
      name: string;
      score: number;
      reasons: string[];
      pseudocode?: string;
      cfg?: any;
    }>;
    report_path?: string;
    elapsed_ms: number;
    result_mode?: 'queued' | 'completed';
    recommended_next_tools?: string[];
    next_actions?: string[];
  };
  errors?: string[];
  warnings?: string[];
}

export interface DeepStaticWorkflowProgressCallbacks {
  onProgress?: (progress: number, stage: string) => void
}

function buildDeepStaticCoverage(params: {
  sampleSize: number
  topFunctions: number
  queued: boolean
  functionCount?: number
  completedTopFunctions?: Array<{ pseudocode?: unknown | null }>
}): z.infer<typeof CoverageEnvelopeSchema> {
  const sampleSizeTier = classifySampleSizeTier(params.sampleSize)
  const requestedDepth = params.topFunctions >= 8 ? 'deep' : 'balanced'
  const analysisBudgetProfile = deriveAnalysisBudgetProfile(requestedDepth, sampleSizeTier)
  const decompiledCount =
    params.completedTopFunctions?.filter((item) => Boolean(item.pseudocode)).length || 0

  return buildCoverageEnvelope({
    coverageLevel: analysisBudgetProfile === 'deep' ? 'deep_static' : 'static_core',
    completionState: params.queued
      ? 'queued'
      : analysisBudgetProfile === 'deep'
        ? 'completed'
        : 'bounded',
    sampleSizeTier,
    analysisBudgetProfile,
    downgradeReasons:
      analysisBudgetProfile === 'deep'
        ? []
        : [
            `Deep static analysis stayed bounded because sample size tier ${sampleSizeTier} or top-function budget ${params.topFunctions} did not justify a full deep pass.`,
          ],
    coverageGaps: [
      params.queued
        ? {
            domain: 'decompilation',
            status: 'queued',
            reason: 'Top-function decompilation is still queued.',
          }
        : null,
      !params.queued && analysisBudgetProfile !== 'deep'
        ? {
            domain: 'decompilation',
            status: 'skipped',
            reason: 'Only a bounded set of top functions was decompiled.',
          }
        : null,
      {
        domain: 'reconstruction_export',
        status: 'missing',
        reason: 'workflow.deep_static stops before source-like reconstruction export.',
      },
      {
        domain: 'dynamic_behavior',
        status: 'missing',
        reason: 'No runtime execution or trace verification was performed.',
      },
    ],
    confidenceByDomain: {
      function_index: params.queued ? 0.2 : params.functionCount ? 0.7 : 0.35,
      decompilation: params.queued ? 0.1 : decompiledCount > 0 ? 0.7 : 0.3,
      graph_context: params.queued ? 0.05 : 0.4,
    },
    knownFindings: [
      params.functionCount !== undefined ? `Recovered ${params.functionCount} functions during deep static analysis.` : null,
      !params.queued && decompiledCount > 0 ? `Decompiled ${decompiledCount} high-value function(s).` : null,
    ],
    suspectedFindings: [
      !params.queued && decompiledCount < params.topFunctions
        ? 'Some top-ranked functions remain without pseudocode and may need a deeper pass.'
        : null,
    ],
    unverifiedAreas: [
      'Source-like reconstruction and validation remain unverified.',
      'Dynamic behavior remains unverified.',
    ],
    upgradePaths: [
      {
        tool: params.queued ? 'task.status' : 'workflow.reconstruct',
        purpose: params.queued
          ? 'Wait for queued deep static completion.'
          : 'Continue from deep static context into reconstruction.',
        closes_gaps: params.queued ? ['decompilation'] : ['reconstruction_export'],
        expected_coverage_gain: params.queued
          ? 'Returns completed deep static output when the queued job finishes.'
          : 'Adds source-like export and validation artifacts beyond deep static output.',
        cost_tier: params.queued ? 'low' : 'high',
      },
      !params.queued
        ? {
            tool: 'code.function.decompile',
            purpose: 'Inspect additional functions outside the bounded shortlist.',
            closes_gaps: ['decompilation'],
            expected_coverage_gain: 'Extends decompilation coverage to functions not included in the initial top-function batch.',
            cost_tier: 'medium',
          }
        : null,
    ],
  })
}

/**
 * Tool definition for deep static workflow
 */
export const deepStaticWorkflowToolDefinition: ToolDefinition = {
  name: 'workflow.deep_static',
  description:
    'Run a long-running deep static workflow that chains quick triage, Ghidra analysis, function ranking, and top-function decompilation. ' +
    'If the user has not picked a workflow yet, prefer workflow.analyze.auto so the server can route by intent first. ' +
    'Use this when you want one queued entrypoint for deeper static reverse engineering rather than calling each stage manually. ' +
    'Do not use this for quick profiling only; workflow.triage is cheaper and faster. ' +
    'Read coverage_level, completion_state, coverage_gaps, and upgrade_paths to understand whether the result is queued, bounded, or fully completed.' +
    '\n\nDecision guide:\n' +
    '- Use when: you want a single deep static analysis job with queue-aware polling.\n' +
    '- Do not use when: you only need a fast first-pass triage or a single leaf analysis tool.\n' +
    '- Typical next step: if queued, poll task.status(job_id); if completed, inspect top_functions or continue with workflow.reconstruct/report tools.\n' +
    '- Common mistake: treating this as an immediate-response tool despite its long runtime.',
  inputSchema: deepStaticWorkflowInputSchema,
  outputSchema: deepStaticWorkflowOutputSchema,
};

/**
 * Execute deep static analysis workflow
 * 
 * Requirements: 16.1, 16.2, 16.3, 16.4, 16.5
 * 
 * @param sampleId - Sample identifier
 * @param workspaceManager - Workspace manager
 * @param database - Database manager
 * @param cacheManager - Cache manager
 * @param options - Workflow options
 * @returns Deep static workflow result
 */
export async function deepStaticWorkflow(
  sampleId: string,
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  options?: {
    top_functions?: number;
    ghidra_timeout?: number;
    include_cfg?: boolean;
  },
  callbacks?: DeepStaticWorkflowProgressCallbacks
): Promise<DeepStaticWorkflowResult> {
  const startTime = Date.now();
  const reportProgress = (progress: number, stage: string) => {
    callbacks?.onProgress?.(progress, stage)
  }

  try {
    logger.info({
      sample_id: sampleId,
      options
    }, 'Starting deep static workflow');
    reportProgress(5, 'triage')

    // Step 1: Execute quick triage workflow (Requirement 16.1)
    logger.info({ sample_id: sampleId }, 'Step 1: Executing quick triage');
    const triageResult = await triageWorkflow(
      sampleId,
      workspaceManager,
      database,
      cacheManager
    );

    if (!triageResult.ok) {
      return {
        ok: false,
        errors: triageResult.errors || ['Triage workflow failed']
      };
    }
    reportProgress(25, 'ghidra_analyze')

    // Step 2: Start Ghidra analysis (Requirement 16.2)
    logger.info({ sample_id: sampleId }, 'Step 2: Starting Ghidra analysis');
    const decompilerWorker = new DecompilerWorker(database, workspaceManager);

    const ghidraTimeout = (options?.ghidra_timeout || 600) * 1000; // Convert to ms
    const analysisResult = await decompilerWorker.analyze(sampleId, {
      timeout: ghidraTimeout,
      maxCpu: '4'
    });

    logger.info({
      analysis_id: analysisResult.analysisId,
      function_count: analysisResult.functionCount
    }, 'Ghidra analysis completed');
    reportProgress(55, 'rank_functions')

    // Step 3: Execute function ranking (Requirement 16.3)
    logger.info({ sample_id: sampleId }, 'Step 3: Ranking functions');
    const topK = options?.top_functions || 10;
    const rankedFunctions = await decompilerWorker.rankFunctions(sampleId, topK);

    logger.info({
      sample_id: sampleId,
      top_k: topK,
      top_score: rankedFunctions[0]?.score || 0
    }, 'Functions ranked');
    reportProgress(75, 'decompile_top_functions')

    // Step 4: Decompile top functions (Requirement 16.4)
    logger.info({
      sample_id: sampleId,
      count: rankedFunctions.length
    }, 'Step 4: Decompiling top functions');

    const decompiledFunctions = [];
    for (const func of rankedFunctions) {
      try {
        logger.debug({
          address: func.address,
          name: func.name
        }, 'Decompiling function');

        const decompiled = await decompilerWorker.decompileFunction(
          sampleId,
          func.address,
          false, // Don't include xrefs for performance
          30000 // 30 second timeout per function
        );

        const funcResult: any = {
          address: func.address,
          name: func.name,
          score: func.score,
          reasons: func.reasons,
          pseudocode: decompiled.pseudocode
        };

        // Optionally include CFG
        if (options?.include_cfg) {
          try {
            const cfg = await decompilerWorker.getFunctionCFG(
              sampleId,
              func.address,
              30000
            );
            funcResult.cfg = cfg;
          } catch (error) {
            logger.warn({
              address: func.address,
              error: error instanceof Error ? error.message : String(error)
            }, 'Failed to extract CFG');
          }
        }

        decompiledFunctions.push(funcResult);

      } catch (error) {
        logger.warn({
          address: func.address,
          name: func.name,
          error: error instanceof Error ? error.message : String(error)
        }, 'Failed to decompile function');

        // Add function without pseudocode
        decompiledFunctions.push({
          address: func.address,
          name: func.name,
          score: func.score,
          reasons: func.reasons,
          pseudocode: null,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }

    // Step 5: Generate report (Requirement 16.5)
    logger.info({ sample_id: sampleId }, 'Step 5: Generating report');
    reportProgress(92, 'generate_report')
    // Report generation would be implemented here
    // For now, we'll just return the data

    const elapsedMs = Date.now() - startTime;

    logger.info({
      sample_id: sampleId,
      elapsed_ms: elapsedMs,
      function_count: analysisResult.functionCount,
      decompiled_count: decompiledFunctions.length
    }, 'Deep static workflow completed');
    reportProgress(100, 'completed')

    return {
      ok: true,
      data: {
        triage_summary: triageResult.data,
        analysis_id: analysisResult.analysisId,
        function_count: analysisResult.functionCount,
        top_functions: decompiledFunctions,
        elapsed_ms: elapsedMs,
        result_mode: 'completed',
        recommended_next_tools: [
          'workflow.reconstruct',
          'report.generate',
          'code.function.decompile',
        ],
        next_actions: [
          'Inspect top_functions for the most suspicious or relevant routines.',
          'Use workflow.reconstruct if you want source-like export after deep static analysis.',
        ],
      }
    };

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const elapsedMs = Date.now() - startTime;

    logger.error({
      sample_id: sampleId,
      error: errorMessage,
      elapsed_ms: elapsedMs
    }, 'Deep static workflow failed');

    return {
      ok: false,
      errors: [errorMessage]
    };
  }
}

/**
 * Create handler for deep static workflow tool
 */
export function createDeepStaticWorkflowHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  jobQueue?: JobQueue
): ToolHandler {
  const buildJsonResult = (payload: Record<string, unknown>, isError = false): ToolResult => ({
    content: [{
      type: 'text',
      text: JSON.stringify(payload, null, 2)
    }],
    structuredContent: payload,
    isError: isError || undefined,
  })

  return async (args: unknown): Promise<ToolResult> => {
    try {
      const input = deepStaticWorkflowInputSchema.parse(args);

      logger.info({
        sample_id: input.sample_id,
        options: input.options
      }, 'workflow.deep_static tool called');

      // Check if sample exists
      const sample = database.findSample(input.sample_id);
      if (!sample) {
        return buildJsonResult({
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`]
        }, true);
      }

      if (jobQueue) {
        const requestedTimeoutSec = input.options?.ghidra_timeout || 600
        const jobTimeoutMs = Math.max((requestedTimeoutSec + 1200) * 1000, 30 * 60 * 1000)
        const jobId = jobQueue.enqueue({
          type: 'static',
          tool: 'workflow.deep_static',
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
          ...buildJsonResult({
            ok: true,
            data: mergeCoverageEnvelope(
              {
                job_id: jobId,
                status: 'queued',
                tool: 'workflow.deep_static',
                sample_id: input.sample_id,
                progress: 0,
                polling_guidance: buildPollingGuidance({
                  tool: 'workflow.deep_static',
                  status: 'queued',
                  progress: 0,
                  timeout_ms: jobTimeoutMs,
                }),
                result_mode: 'queued',
                recommended_next_tools: ['task.status'],
                next_actions: [
                  'Wait for approximately the recommended polling interval before checking task.status again.',
                  'Call task.status with the returned job_id until the workflow completes or fails.',
                ],
              },
              buildDeepStaticCoverage({
                sampleSize: sample.size || 0,
                topFunctions: input.options?.top_functions || 10,
                queued: true,
              })
            ),
          }),
        }
      }

      const result = await deepStaticWorkflow(
        input.sample_id,
        workspaceManager,
        database,
        cacheManager,
        input.options
      );

      if (!result.ok) {
        return buildJsonResult(result as unknown as Record<string, unknown>, true);
      }

      const resultData =
        result.data && typeof result.data === 'object'
          ? (result.data as Record<string, unknown>)
          : {}

      return buildJsonResult({
        ...result,
        data: mergeCoverageEnvelope(
          resultData,
          buildDeepStaticCoverage({
            sampleSize: sample.size || 0,
            topFunctions: input.options?.top_functions || 10,
            queued: false,
            functionCount: typeof resultData.function_count === 'number' ? (resultData.function_count as number) : undefined,
            completedTopFunctions: Array.isArray(resultData.top_functions)
              ? (resultData.top_functions as Array<{ pseudocode?: unknown | null }>)
              : undefined,
          })
        ),
      });

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error({
        error: errorMessage
      }, 'workflow.deep_static tool failed');

      return buildJsonResult({
        ok: false,
        errors: [errorMessage]
      }, true);
    }
  };
}
