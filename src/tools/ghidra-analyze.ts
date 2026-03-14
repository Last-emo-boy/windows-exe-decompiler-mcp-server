/**
 * ghidra.analyze MCP Tool
 * 
 * Requirements: 8.1, 8.2, 8.3
 * 
 * Analyzes a binary sample with Ghidra Headless and extracts function list
 */

import { z } from 'zod';
import type { ToolDefinition, ToolHandler, ToolResult } from '../types.js';
import type { DatabaseManager } from '../database.js';
import type { WorkspaceManager } from '../workspace-manager.js';
import type { JobQueue } from '../job-queue.js';
import { DecompilerWorker, getGhidraDiagnostics, normalizeGhidraError } from '../decompiler-worker.js';
import {
  findBestGhidraAnalysis,
  getGhidraReadiness,
  parseGhidraAnalysisMetadata,
} from '../ghidra-analysis-status.js';
import { logger } from '../logger.js';
import { PollingGuidanceSchema, buildPollingGuidance } from '../polling-guidance.js';

/**
 * Input schema for ghidra.analyze tool
 * Requirements: 8.1
 */
export const ghidraAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  options: z.object({
    timeout: z.number().optional().describe('Analysis timeout in seconds (default: 300)'),
    max_cpu: z.string().optional().describe('Maximum CPU cores to use (default: "4")'),
    project_key: z.string().optional().describe('Optional project key for reusing existing project'),
    processor: z.string().optional().describe('Optional processor or language override passed to analyzeHeadless -processor'),
    language_id: z.string().optional().describe('Optional Ghidra language ID override for Rust/Go/C++ binaries'),
    cspec: z.string().optional().describe('Optional compiler specification passed to analyzeHeadless -cspec'),
    script_paths: z.array(z.string()).optional().describe('Additional Ghidra script directories appended to the default script path'),
  }).optional().describe('Ghidra analysis options')
});

export type GhidraAnalyzeInput = z.infer<typeof ghidraAnalyzeInputSchema>;

/**
 * Output schema for ghidra.analyze tool
 * Requirements: 8.2, 8.3
 */
export interface GhidraAnalyzeOutput {
  ok: boolean;
  data?: {
    analysis_id: string;
    job_id?: string;
    backend: string;
    function_count: number;
    project_path: string;
    status: string;
    polling_guidance?: z.infer<typeof PollingGuidanceSchema> | null;
    capabilities?: {
      function_index: unknown;
      decompile: unknown;
      cfg: unknown;
    };
  };
  diagnostics?: unknown;
  normalized_error?: unknown;
  errors?: string[];
  warnings?: string[];
}

/**
 * Tool definition for ghidra.analyze
 * Requirements: 8.1, 8.2, 8.3
 */
export const ghidraAnalyzeToolDefinition: ToolDefinition = {
  name: 'ghidra.analyze',
  description: 'Analyze a binary sample with Ghidra Headless and extract function list. This is a long-running operation that may take several minutes depending on sample size.',
  inputSchema: ghidraAnalyzeInputSchema
};

/**
 * Create handler for ghidra.analyze tool
 * 
 * Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6
 * 
 * @param workspaceManager - Workspace manager instance
 * @param database - Database manager instance
 * @param jobQueue - Job queue instance (optional, for async execution)
 * @returns Tool handler function
 */
export function createGhidraAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  jobQueue?: JobQueue
): ToolHandler {
  return async (args: unknown): Promise<ToolResult> => {
    try {
      // Validate input
      const input = ghidraAnalyzeInputSchema.parse(args);

      logger.info({
        sample_id: input.sample_id,
        options: input.options
      }, 'ghidra.analyze tool called');

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

      // Create decompiler worker
      const decompilerWorker = new DecompilerWorker(database, workspaceManager);

      const analyses = database.findAnalysesBySample(input.sample_id)
      const reusableAnalysis = (() => {
        if (input.options?.project_key) {
          return analyses.find((analysis) => {
            if (analysis.backend !== 'ghidra') {
              return false
            }
            const metadata = parseGhidraAnalysisMetadata(analysis.output_json)
            return (
              metadata.project_key === input.options?.project_key &&
              getGhidraReadiness(analysis).function_index.status === 'ready'
            )
          })
        }
        return findBestGhidraAnalysis(analyses, 'function_index')
      })()

      if (reusableAnalysis) {
        const metadata = parseGhidraAnalysisMetadata(reusableAnalysis.output_json)
        const reusedOutput: GhidraAnalyzeOutput = {
          ok: true,
          data: {
            analysis_id: reusableAnalysis.id,
            backend: reusableAnalysis.backend,
            function_count:
              typeof metadata.function_count === 'number' ? metadata.function_count : 0,
            project_path:
              typeof metadata.project_path === 'string' ? metadata.project_path : '',
            status: 'reused',
            capabilities: getGhidraReadiness(reusableAnalysis),
          },
          warnings: [
            input.options?.project_key
              ? `Reused existing completed Ghidra analysis for project_key=${input.options.project_key}.`
              : 'Reused existing completed Ghidra analysis for this sample.',
          ],
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(reusedOutput, null, 2),
            },
          ],
        }
      }

      // Convert timeout from seconds to milliseconds
      const timeoutMs = (input.options?.timeout || 300) * 1000;

      // Prepare Ghidra options
      const ghidraOptions = {
        timeout: timeoutMs,
        maxCpu: input.options?.max_cpu || '4',
        projectKey: input.options?.project_key,
        processor: input.options?.processor,
        languageId: input.options?.language_id,
        cspec: input.options?.cspec,
        scriptPaths: input.options?.script_paths,
      };

      // If job queue is available, enqueue the analysis
      if (jobQueue) {
        const jobId = await jobQueue.enqueue({
          type: 'decompile',
          tool: 'ghidra.analyze',
          sampleId: input.sample_id,
          args: input,
          priority: 5,
          timeout: timeoutMs,
          retryPolicy: {
            maxRetries: 2,
            backoffMs: 5000,
            retryableErrors: ['E_TIMEOUT', 'E_RESOURCE_EXHAUSTED']
          }
        });

        logger.info({
          job_id: jobId,
          sample_id: input.sample_id
        }, 'Ghidra analysis job enqueued');

        const output: GhidraAnalyzeOutput = {
          ok: true,
          data: {
            analysis_id: jobId,
            job_id: jobId,
            backend: 'ghidra',
            function_count: 0,
            project_path: '',
            status: 'queued',
            polling_guidance: buildPollingGuidance({
              tool: 'ghidra.analyze',
              status: 'queued',
              progress: 0,
              timeout_ms: timeoutMs,
            }),
          }
        };

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(output, null, 2)
            }
          ]
        };
      }

      // Otherwise, execute synchronously
      const result = await decompilerWorker.analyze(input.sample_id, ghidraOptions);

      logger.info({
        analysis_id: result.analysisId,
        function_count: result.functionCount
      }, 'Ghidra analysis completed');

      const output: GhidraAnalyzeOutput = {
        ok: true,
        data: {
          analysis_id: result.analysisId,
          backend: result.backend,
          function_count: result.functionCount,
          project_path: result.projectPath,
          status: result.status === 'partial_success' ? 'partial_success' : 'completed',
          capabilities: result.readiness,
        },
        warnings: result.warnings,
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(output, null, 2)
          }
        ]
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const diagnostics = getGhidraDiagnostics(error);
      const normalizedError = normalizeGhidraError(error, 'ghidra.analyze');
      logger.error({
        error: errorMessage,
        ghidra_diagnostics: diagnostics,
        normalized_error: normalizedError,
      }, 'ghidra.analyze tool failed');

      const output: GhidraAnalyzeOutput = {
        ok: false,
        diagnostics,
        normalized_error: normalizedError,
        errors: [errorMessage]
      };

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(output, null, 2)
        }],
        isError: true
      };
    }
  };
}
