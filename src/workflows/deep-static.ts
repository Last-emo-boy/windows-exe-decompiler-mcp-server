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
  };
  errors?: string[];
  warnings?: string[];
}

export interface DeepStaticWorkflowProgressCallbacks {
  onProgress?: (progress: number, stage: string) => void
}

/**
 * Tool definition for deep static workflow
 */
export const deepStaticWorkflowToolDefinition: ToolDefinition = {
  name: 'workflow.deep_static',
  description: 'Perform comprehensive static analysis including triage, Ghidra analysis, function ranking, and decompilation of top functions. This is a long-running operation (30-60 minutes).',
  inputSchema: deepStaticWorkflowInputSchema
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
        elapsed_ms: elapsedMs
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
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ok: false,
              errors: [`Sample not found: ${input.sample_id}`]
            }, null, 2)
          }],
          isError: true
        };
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
          content: [{
            type: 'text',
            text: JSON.stringify({
              ok: true,
              data: {
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
              }
            }, null, 2)
          }]
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
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }],
          isError: true
        };
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error({
        error: errorMessage
      }, 'workflow.deep_static tool failed');

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ok: false,
            errors: [errorMessage]
          }, null, 2)
        }],
        isError: true
      };
    }
  };
}
