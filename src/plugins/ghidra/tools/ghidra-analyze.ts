/**
 * ghidra.analyze MCP Tool
 * 
 * Requirements: 8.1, 8.2, 8.3
 * 
 * Analyzes a binary sample with Ghidra Headless and extracts function list
 */

import { z } from 'zod';
import type { ToolDefinition, ToolResult, PluginToolDeps } from '../../sdk.js';

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

const GhidraAnalyzeDataSchema = z.object({
  analysis_id: z.string(),
  job_id: z.string().optional(),
  backend: z.string(),
  function_count: z.number().int().nonnegative(),
  project_path: z.string(),
  status: z.string(),
  polling_guidance: z.any().nullable().optional(),
  capabilities: z
    .object({
      function_index: z.any(),
      decompile: z.any(),
      cfg: z.any(),
    })
    .optional(),
  result_mode: z.enum(['queued', 'reused', 'completed', 'partial_success']),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const ghidraAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: GhidraAnalyzeDataSchema.optional(),
  diagnostics: z.any().optional(),
  normalized_error: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
})

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
    polling_guidance?: unknown | null;
    capabilities?: {
      function_index: unknown;
      decompile: unknown;
      cfg: unknown;
    };
    result_mode?: 'queued' | 'reused' | 'completed' | 'partial_success';
    recommended_next_tools?: string[];
    next_actions?: string[];
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
  description:
    'Start or reuse deep static analysis with Ghidra Headless to extract function indexes and unlock decompile/CFG workflows. ' +
    'Use this after a sample has been registered and you need code-level reverse engineering, not just quick profiling. ' +
    'Do not use this as the first host-file ingest step or as a health check. ' +
    '\n\nDecision guide:\n' +
    '- Use when: you need function-level reverse engineering, decompilation, or reconstruction prerequisites.\n' +
    '- Do not use when: the sample is not ingested yet or you only need a fast triage profile.\n' +
    '- Typical next step: if status=queued, poll task.status(job_id); if completed/reused, continue with workflow.reconstruct, code.functions.list, or code.function.decompile.\n' +
    '- Common mistake: assuming this tool is always synchronous and skipping task.status when a queue-backed client is active.',
  inputSchema: ghidraAnalyzeInputSchema,
  outputSchema: ghidraAnalyzeOutputSchema,
};

/**
 * Create handler for ghidra.analyze tool
 * 
 * Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6
 * 
 * @param deps - Plugin dependencies injected by the server
 * @returns Tool handler function
 */
export function createGhidraAnalyzeHandler(
  deps: PluginToolDeps
) {
  const {
    workspaceManager,
    database,
    jobQueue,
    logger,
    DecompilerWorker,
    getGhidraDiagnostics,
    normalizeGhidraError,
    findBestGhidraAnalysis,
    getGhidraReadiness,
    parseGhidraAnalysisMetadata,
    buildPollingGuidance,
  } = deps;

  const buildJsonResult = (
    payload: GhidraAnalyzeOutput,
    isError = false
  ): ToolResult => ({
    content: [
      {
        type: 'text',
        text: JSON.stringify(payload, null, 2),
      },
    ],
    structuredContent: payload as unknown as Record<string, unknown>,
    isError,
  })

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
        return buildJsonResult(
          {
            ok: false,
            errors: [`Sample not found: ${input.sample_id}`],
          },
          true
        );
      }

      // Create decompiler worker
      const decompilerWorker = new DecompilerWorker(database, workspaceManager);

      const analyses = database.findAnalysesBySample(input.sample_id)
      const reusableAnalysis = (() => {
        if (input.options?.project_key) {
          return analyses.find((analysis: any) => {
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
            result_mode: 'reused',
            recommended_next_tools: [
              'workflow.reconstruct',
              'code.functions.list',
              'code.function.decompile',
            ],
            next_actions: [
              'Use workflow.reconstruct for source-like reconstruction over the completed Ghidra analysis.',
              'Use code.functions.list or code.function.decompile when you need direct function-level inspection.',
            ],
          },
          warnings: [
            input.options?.project_key
              ? `Reused existing completed Ghidra analysis for project_key=${input.options.project_key}.`
              : 'Reused existing completed Ghidra analysis for this sample.',
          ],
        }

        return buildJsonResult(reusedOutput)
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
            result_mode: 'queued',
            recommended_next_tools: ['task.status'],
            next_actions: [
              'Wait for approximately the recommended polling interval before querying task.status.',
              'Call task.status with the returned job_id until the analysis completes, fails, or is cancelled.',
            ],
          }
        };

        return buildJsonResult(output);
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
          result_mode: result.status === 'partial_success' ? 'partial_success' : 'completed',
          recommended_next_tools: [
            'workflow.reconstruct',
            'code.functions.list',
            'code.function.decompile',
          ],
          next_actions: [
            'Use workflow.reconstruct for source-like reconstruction over the completed Ghidra analysis.',
            'Use code.functions.list or code.function.decompile when you need direct function-level inspection.',
          ],
        },
        warnings: result.warnings,
      };

      return buildJsonResult(output);

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

      return buildJsonResult(output, true);
    }
  };
}
