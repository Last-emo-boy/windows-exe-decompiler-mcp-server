import { z } from 'zod'
import type { ToolArgs, ToolDefinition, ToolResult, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { JobQueue } from '../job-queue.js'
import {
  AnalysisIntentDepthSchema,
  AnalysisIntentGoalSchema,
  BackendPolicySchema,
  BackendRoutingMetadataSchema,
  buildIntentBackendPlan,
  mergeRoutingMetadata,
} from '../intent-routing.js'
import {
  CoverageEnvelopeSchema,
  buildBudgetDowngradeReasons,
  buildCoverageEnvelope,
  classifySampleSizeTier,
  deriveAnalysisBudgetProfile,
  mergeCoverageEnvelope,
} from '../analysis-coverage.js'
import { resolveAnalysisBackends } from '../static-backend-discovery.js'
import { createDynamicDependenciesHandler } from '../tools/dynamic-dependencies.js'
import { createSandboxExecuteHandler } from '../tools/sandbox-execute.js'
import { createQilingInspectHandler, createPandaInspectHandler } from '../tools/docker-backend-tools.js'
import { createTriageWorkflowHandler } from './triage.js'
import { createDeepStaticWorkflowHandler } from './deep-static.js'
import { createReconstructWorkflowHandler } from './reconstruct.js'
import { createWorkflowSummarizeHandler } from './summarize.js'
import {
  createAnalyzeWorkflowPromoteHandler,
  createAnalyzeWorkflowStartHandler,
} from './analyze-pipeline.js'
import type { PolicyGuard } from '../policy-guard.js'
import type { MCPServer } from '../server.js'

const TOOL_NAME = 'workflow.analyze.auto'

export const analyzeAutoWorkflowInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  goal: AnalysisIntentGoalSchema
    .default('triage')
    .describe('Analyst intent. The server routes to an appropriate workflow or safe dynamic path.'),
  depth: AnalysisIntentDepthSchema
    .default('balanced')
    .describe('Controls how aggressively the server selects safe corroborating backends. Prefer safe/balanced first for medium or larger samples; reserve deep for smaller or already-triaged samples.'),
  backend_policy: BackendPolicySchema
    .default('auto')
    .describe('Controls whether newer installed backends are preferred, suppressed, or only used when needed.'),
  allow_transformations: z
    .boolean()
    .default(false)
    .describe('Keep false for routine analysis. True only permits later explicit transform-capable follow-ups; it does not auto-run them.'),
  allow_live_execution: z
    .boolean()
    .default(false)
    .describe('Dynamic routing still defaults to readiness and safe simulation first. Wine/live execution stays manual-only even when this flag is true.'),
  force_refresh: z
    .boolean()
    .default(false)
    .describe('Bypass cache in delegated workflows when supported.'),
  raw_result_mode: z
    .enum(['compact', 'full'])
    .default('compact')
    .describe('Forwarded to workflow.triage when goal=triage. Keep compact for normal and large-sample use; full is mainly for targeted debugging on smaller samples.'),
  include_cfg: z
    .boolean()
    .default(false)
    .describe('Forwarded to workflow.deep_static when goal=static.'),
})

export const analyzeAutoWorkflowOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      goal: AnalysisIntentGoalSchema,
      depth: AnalysisIntentDepthSchema,
      backend_policy: BackendPolicySchema,
      routed_tool: z.string(),
      status: z.string().optional(),
      job_id: z.string().optional(),
      polling_guidance: z.any().optional(),
      routed_result: z.any().optional(),
      dynamic_preflight: z.any().optional(),
      sandbox: z.any().optional(),
      backend_enrichments: z
        .object({
          qiling: z.any().optional(),
          panda: z.any().optional(),
        })
        .optional(),
      result_mode: z.enum(['delegated', 'queued', 'completed']),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .extend(CoverageEnvelopeSchema.shape)
    .extend(BackendRoutingMetadataSchema.shape)
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const analyzeAutoWorkflowToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Intent-routed analysis entrypoint. Prefer this when the user asks for analysis, reverse engineering, dynamic checks, or reporting without naming a specific workflow or backend. ' +
    'The server chooses an existing workflow layer and only selects safe corroborating backends automatically. ' +
    'Read coverage_level, completion_state, coverage_gaps, and upgrade_paths on the result before assuming a deeper stage was reached. ' +
    '\n\nDecision guide:\n' +
    '- Use when: the user says analyze / triage / reverse / dynamic / summarize without specifying an exact backend.\n' +
    '- Small-sample default: goal=triage with depth=balanced is usually the best first call; inspect recommended_next_tools before escalating.\n' +
    '- Large-sample default: expect a persisted run with bounded output first; prefer workflow.analyze.status and workflow.analyze.promote over direct heavyweight tools.\n' +
    '- Do not use when: the user explicitly names a backend wrapper such as rizin.analyze or retdec.decompile.\n' +
    '- Typical next step: inspect routed_tool and routing metadata, then continue with task.status, artifact.read, or the recommended_next_tools.\n' +
    '- Common mistake: assuming allow_live_execution automatically launches Wine; live execution remains approval-gated.',
  inputSchema: analyzeAutoWorkflowInputSchema,
  outputSchema: analyzeAutoWorkflowOutputSchema,
}

interface AnalyzeAutoWorkflowDependencies {
  analyzeStartHandler?: ReturnType<typeof createAnalyzeWorkflowStartHandler>
  analyzePromoteHandler?: ReturnType<typeof createAnalyzeWorkflowPromoteHandler>
  triageHandler?: ReturnType<typeof createTriageWorkflowHandler>
  deepStaticHandler?: ReturnType<typeof createDeepStaticWorkflowHandler>
  reconstructHandler?: ReturnType<typeof createReconstructWorkflowHandler>
  workflowSummarizeHandler?: ReturnType<typeof createWorkflowSummarizeHandler>
  dynamicDependenciesHandler?: ReturnType<typeof createDynamicDependenciesHandler>
  sandboxExecuteHandler?: ReturnType<typeof createSandboxExecuteHandler>
  qilingInspectHandler?: ReturnType<typeof createQilingInspectHandler>
  pandaInspectHandler?: ReturnType<typeof createPandaInspectHandler>
  resolveBackends?: typeof resolveAnalysisBackends
}

function normalizeToolLikeResult(result: WorkerResult | ToolResult): WorkerResult {
  if (!('content' in result)) {
    return result
  }

  const structured = result.structuredContent
  if (structured && typeof structured === 'object') {
    const payload = structured as Record<string, unknown>
    return {
      ok: Boolean(payload.ok ?? !result.isError),
      data: payload.data,
      errors: Array.isArray(payload.errors) ? (payload.errors as string[]) : undefined,
      warnings: Array.isArray(payload.warnings) ? (payload.warnings as string[]) : undefined,
      metrics:
        payload.metrics && typeof payload.metrics === 'object'
          ? (payload.metrics as Record<string, unknown>)
          : undefined,
    }
  }

  const text = result.content.find((item) => item.type === 'text')?.text
  if (text) {
    try {
      const payload = JSON.parse(text) as Record<string, unknown>
      return {
        ok: Boolean(payload.ok ?? !result.isError),
        data: payload.data,
        errors: Array.isArray(payload.errors) ? (payload.errors as string[]) : undefined,
        warnings: Array.isArray(payload.warnings) ? (payload.warnings as string[]) : undefined,
        metrics:
          payload.metrics && typeof payload.metrics === 'object'
            ? (payload.metrics as Record<string, unknown>)
            : undefined,
      }
    } catch {
      return {
        ok: !result.isError,
        data: undefined,
        errors: result.isError ? ['Delegated tool returned non-JSON output.'] : undefined,
      }
    }
  }

  return {
    ok: !result.isError,
    data: undefined,
    errors: result.isError ? ['Delegated tool returned no structured payload.'] : undefined,
  }
}

function extractRoutingMetadata(
  payload: unknown
): z.infer<typeof BackendRoutingMetadataSchema> | null {
  if (!payload || typeof payload !== 'object') {
    return null
  }

  const parsed = BackendRoutingMetadataSchema.safeParse(payload)
  return parsed.success ? parsed.data : null
}

function extractCoverageEnvelope(
  payload: unknown
): z.infer<typeof CoverageEnvelopeSchema> | null {
  if (!payload || typeof payload !== 'object') {
    return null
  }

  const parsed = CoverageEnvelopeSchema.safeParse(payload)
  return parsed.success ? parsed.data : null
}

function dedupeStrings(values: Array<string | undefined | null>) {
  return Array.from(new Set(values.filter((value): value is string => Boolean(value && value.trim().length > 0))))
}

export function createAnalyzeAutoWorkflowHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  policyGuard: PolicyGuard,
  server?: MCPServer,
  dependencies: AnalyzeAutoWorkflowDependencies = {},
  jobQueue?: JobQueue
) {
  const triageHandler =
    dependencies.triageHandler || createTriageWorkflowHandler(workspaceManager, database, cacheManager)
  const deepStaticHandler =
    dependencies.deepStaticHandler ||
    createDeepStaticWorkflowHandler(workspaceManager, database, cacheManager, jobQueue)
  const reconstructHandler =
    dependencies.reconstructHandler ||
    createReconstructWorkflowHandler(workspaceManager, database, cacheManager, undefined, jobQueue)
  const workflowSummarizeHandler =
    dependencies.workflowSummarizeHandler ||
    createWorkflowSummarizeHandler(workspaceManager, database, cacheManager, server)
  const dynamicDependenciesHandler =
    dependencies.dynamicDependenciesHandler ||
    createDynamicDependenciesHandler(workspaceManager, database)
  const sandboxExecuteHandler =
    dependencies.sandboxExecuteHandler ||
    createSandboxExecuteHandler(workspaceManager, database, policyGuard)
  const qilingInspectHandler =
    dependencies.qilingInspectHandler || createQilingInspectHandler(workspaceManager, database)
  const pandaInspectHandler =
    dependencies.pandaInspectHandler || createPandaInspectHandler(workspaceManager, database)
  const analyzeStartHandler =
    dependencies.analyzeStartHandler ||
    createAnalyzeWorkflowStartHandler(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      server,
      {},
      jobQueue
    )
  const analyzePromoteHandler =
    dependencies.analyzePromoteHandler ||
    createAnalyzeWorkflowPromoteHandler(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      server,
      {},
      jobQueue
    )

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = analyzeAutoWorkflowInputSchema.parse(args)
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

      const sampleSizeTier = classifySampleSizeTier(sample.size || 0)
      const analysisBudgetProfile = deriveAnalysisBudgetProfile(input.depth, sampleSizeTier)
      const budgetDowngradeReasons = buildBudgetDowngradeReasons({
        requestedDepth: input.depth,
        sampleSizeTier,
        analysisBudgetProfile,
      })

      const readiness = (dependencies.resolveBackends || resolveAnalysisBackends)()
      const fallbackRouting = buildIntentBackendPlan({
        goal: input.goal,
        depth: input.depth,
        backendPolicy: input.backend_policy,
        allowTransformations: input.allow_transformations,
        allowLiveExecution: input.allow_live_execution,
        readiness,
      })

      const startDelegated = await analyzeStartHandler({
        sample_id: input.sample_id,
        goal: input.goal,
        depth: input.depth,
        backend_policy: input.backend_policy,
        allow_transformations: input.allow_transformations,
        allow_live_execution: input.allow_live_execution,
        force_refresh: input.force_refresh,
      })
      if (!startDelegated.ok || !startDelegated.data) {
        return {
          ok: false,
          errors: startDelegated.errors || ['workflow.analyze.start failed'],
          warnings: startDelegated.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const startPayload =
        startDelegated.data && typeof startDelegated.data === 'object'
          ? (startDelegated.data as Record<string, unknown>)
          : {}
      const startRouting = extractRoutingMetadata(startDelegated.data) || fallbackRouting
      const startCoverage =
        extractCoverageEnvelope(startDelegated.data) ||
        buildCoverageEnvelope({
          coverageLevel: 'quick',
          completionState: 'bounded',
          sampleSizeTier,
          analysisBudgetProfile,
          downgradeReasons: budgetDowngradeReasons,
        })

      if (input.goal === 'triage') {
        return {
          ok: true,
          data: mergeRoutingMetadata(
            mergeCoverageEnvelope(
              {
                ...startPayload,
                sample_id: input.sample_id,
                goal: input.goal,
                depth: input.depth,
                backend_policy: input.backend_policy,
                routed_tool: 'workflow.analyze.start',
                routed_result: startPayload.stage_result,
                result_mode:
                  startPayload.execution_state === 'queued' ? 'queued' : 'completed',
                recommended_next_tools:
                  (startPayload.recommended_next_tools as string[]) || [
                    'workflow.analyze.promote',
                    'workflow.analyze.status',
                  ],
                next_actions:
                  (startPayload.next_actions as string[]) || [
                    'Promote the persisted run instead of repeating fast-profile analysis when you need deeper stages.',
                  ],
              },
              startCoverage
            ),
            startRouting
          ),
          warnings: startDelegated.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const throughStage =
        input.goal === 'reverse'
          ? 'reconstruct'
          : input.goal === 'report'
            ? 'summarize'
            : input.goal === 'dynamic'
              ? input.allow_live_execution
                ? 'dynamic_execute'
                : 'dynamic_plan'
              : analysisBudgetProfile === 'quick'
                ? 'enrich_static'
                : 'function_map'

      const promoteDelegated = await analyzePromoteHandler({
        run_id: String(startPayload.run_id),
        through_stage: throughStage,
        force_refresh: input.force_refresh,
      })
      if (!promoteDelegated.ok || !promoteDelegated.data) {
        return {
          ok: false,
          errors: promoteDelegated.errors || ['workflow.analyze.promote failed'],
          warnings: [...(startDelegated.warnings || []), ...(promoteDelegated.warnings || [])],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const promotePayload =
        promoteDelegated.data && typeof promoteDelegated.data === 'object'
          ? (promoteDelegated.data as Record<string, unknown>)
          : {}
      const promoteRouting = extractRoutingMetadata(promoteDelegated.data) || startRouting
      const promoteCoverage =
        extractCoverageEnvelope(promoteDelegated.data) || startCoverage

      return {
        ok: true,
        data: mergeRoutingMetadata(
          mergeCoverageEnvelope(
            {
              ...promotePayload,
              sample_id: input.sample_id,
              goal: input.goal,
              depth: input.depth,
              backend_policy: input.backend_policy,
              routed_tool: 'workflow.analyze.promote',
              routed_result: promotePayload.stage_result || promotePayload,
              result_mode:
                promotePayload.execution_state === 'queued' ? 'queued' : 'completed',
              recommended_next_tools:
                (promotePayload.recommended_next_tools as string[]) || [
                  'workflow.analyze.status',
                  'workflow.analyze.promote',
                ],
              next_actions:
                (promotePayload.next_actions as string[]) || [
                  'Use workflow.analyze.status to monitor the persisted run instead of rerunning heavyweight workflows.',
                ],
            },
            promoteCoverage
          ),
          promoteRouting
        ),
        warnings: dedupeStrings([
          ...(startDelegated.warnings || []),
          ...(promoteDelegated.warnings || []),
        ]),
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }

      if (input.goal === 'triage') {
        const triageResult = await triageHandler({
          sample_id: input.sample_id,
          force_refresh: input.force_refresh,
          raw_result_mode: input.raw_result_mode,
          depth: input.depth,
          backend_policy: input.backend_policy,
          allow_transformations: input.allow_transformations,
        })
        const routingMetadata = extractRoutingMetadata(triageResult.data) || fallbackRouting
        const coverageEnvelope =
          extractCoverageEnvelope(triageResult.data) ||
          buildCoverageEnvelope({
            coverageLevel: 'quick',
            completionState: triageResult.ok ? 'bounded' : 'partial',
            sampleSizeTier,
            analysisBudgetProfile,
            downgradeReasons: budgetDowngradeReasons,
            coverageGaps: [
              {
                domain: 'ghidra_analysis',
                status: 'missing',
                reason: 'Quick triage does not include a queued decompiler pass.',
              },
              {
                domain: 'dynamic_behavior',
                status: 'missing',
                reason: 'No runtime execution or trace verification was performed.',
              },
            ],
            knownFindings: [
              (triageResult.data as Record<string, unknown> | undefined)?.summary as string | undefined,
            ],
            unverifiedAreas: ['Function-level attribution remains unverified after quick triage.'],
            upgradePaths: [
              {
                tool: 'ghidra.analyze',
                purpose: 'Recover function-level attribution.',
                closes_gaps: ['ghidra_analysis'],
                expected_coverage_gain: 'Adds decompiler-backed function discovery and addresses-to-behavior context.',
                cost_tier: 'high',
              },
              {
                tool: 'workflow.reconstruct',
                purpose: 'Produce source-like reconstruction artifacts.',
                closes_gaps: ['reconstruction_export'],
                expected_coverage_gain: 'Adds plan plus export artifacts beyond first-pass triage.',
                cost_tier: 'high',
              },
            ],
          })

        return {
          ok: triageResult.ok,
          data: triageResult.ok
            ? mergeRoutingMetadata(
                mergeCoverageEnvelope(
                  {
                  sample_id: input.sample_id,
                  goal: input.goal,
                  depth: input.depth,
                  backend_policy: input.backend_policy,
                  routed_tool: 'workflow.triage',
                  routed_result: triageResult.data,
                  result_mode: 'completed',
                  recommended_next_tools:
                    (triageResult.data as Record<string, unknown>)?.recommended_next_tools as string[] || [
                      'ghidra.analyze',
                      'workflow.reconstruct',
                    ],
                  next_actions:
                    (triageResult.data as Record<string, unknown>)?.next_actions as string[] || [
                      'Continue with the recommended follow-up workflow.',
                    ],
                  },
                  coverageEnvelope
                ),
                routingMetadata
              )
            : undefined,
          warnings: triageResult.warnings,
          errors: triageResult.errors,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      if (input.goal === 'static') {
        const staticTopFunctions =
          analysisBudgetProfile === 'deep'
            ? 10
            : sampleSizeTier === 'oversized'
              ? 3
              : sampleSizeTier === 'large'
                ? 5
                : 6
        const delegated = normalizeToolLikeResult(
          await deepStaticHandler({
            sample_id: input.sample_id,
            options: {
              top_functions: staticTopFunctions,
              include_cfg:
                input.include_cfg || (input.depth === 'deep' && analysisBudgetProfile === 'deep'),
            },
          })
        )
        const routingMetadata = extractRoutingMetadata(delegated.data) || fallbackRouting
        const delegatedData =
          delegated.data && typeof delegated.data === 'object'
            ? (delegated.data as Record<string, unknown>)
            : {}
        const coverageEnvelope =
          extractCoverageEnvelope(delegated.data) ||
          buildCoverageEnvelope({
            coverageLevel: analysisBudgetProfile === 'deep' ? 'deep_static' : 'static_core',
            completionState:
              delegatedData.result_mode === 'queued'
                ? 'queued'
                : analysisBudgetProfile === 'deep'
                  ? 'completed'
                  : 'bounded',
            sampleSizeTier,
            analysisBudgetProfile,
            downgradeReasons: budgetDowngradeReasons,
            coverageGaps: [
              delegatedData.result_mode === 'queued'
                ? {
                    domain: 'decompilation',
                    status: 'queued',
                    reason: 'Deep static analysis is queued and has not produced decompiled output yet.',
                  }
                : null,
              analysisBudgetProfile !== 'deep'
                ? {
                    domain: 'decompilation',
                    status: 'skipped',
                    reason: 'Large-sample budget profile kept top-function decompilation bounded.',
                  }
                : null,
              {
                domain: 'reconstruction_export',
                status: 'missing',
                reason: 'Deep static analysis stops before source-like reconstruction export.',
              },
            ],
            knownFindings: [
              typeof delegatedData.function_count === 'number'
                ? `Recovered ${delegatedData.function_count} functions in deep static workflow.`
                : null,
            ],
            suspectedFindings: [
              analysisBudgetProfile !== 'deep'
                ? 'Only a bounded subset of top functions may have been decompiled.'
                : null,
            ],
            unverifiedAreas: [
              'Export validation and dynamic confirmation remain outside workflow.deep_static.',
            ],
            upgradePaths: [
              {
                tool: delegatedData.result_mode === 'queued' ? 'task.status' : 'workflow.reconstruct',
                purpose:
                  delegatedData.result_mode === 'queued'
                    ? 'Wait for queued deep static completion.'
                    : 'Continue to source-like reconstruction artifacts.',
                closes_gaps:
                  delegatedData.result_mode === 'queued'
                    ? ['decompilation']
                    : ['reconstruction_export'],
                expected_coverage_gain:
                  delegatedData.result_mode === 'queued'
                    ? 'Returns completed deep static outputs once queued work finishes.'
                    : 'Adds plan plus export artifacts beyond deep static inspection.',
                cost_tier: delegatedData.result_mode === 'queued' ? 'low' : 'high',
              },
            ],
          })

        return {
          ok: delegated.ok,
          data: delegated.ok
            ? mergeRoutingMetadata(
                mergeCoverageEnvelope(
                  {
                    sample_id: input.sample_id,
                    goal: input.goal,
                    depth: input.depth,
                    backend_policy: input.backend_policy,
                    routed_tool: 'workflow.deep_static',
                    status: typeof delegatedData.status === 'string' ? delegatedData.status : undefined,
                    job_id: typeof delegatedData.job_id === 'string' ? delegatedData.job_id : undefined,
                    polling_guidance: delegatedData.polling_guidance,
                    routed_result: delegated.data,
                    result_mode:
                      delegatedData.result_mode === 'queued' ? 'queued' : 'completed',
                    recommended_next_tools:
                      (delegatedData.recommended_next_tools as string[]) || ['task.status', 'workflow.reconstruct'],
                    next_actions:
                      (delegatedData.next_actions as string[]) || [
                        delegatedData.result_mode === 'queued'
                          ? 'Poll task.status until workflow.deep_static completes.'
                          : 'Continue with workflow.reconstruct if you need source-like export.',
                      ],
                  },
                  coverageEnvelope
                ),
                routingMetadata
              )
            : undefined,
          warnings: delegated.warnings,
          errors: delegated.errors,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      if (input.goal === 'reverse') {
        const reconstructResult = await reconstructHandler({
          sample_id: input.sample_id,
          path: 'auto',
          topk:
            analysisBudgetProfile === 'deep'
              ? input.depth === 'deep'
                ? 20
                : 16
              : sampleSizeTier === 'oversized'
                ? 8
                : 12,
          depth: input.depth,
          backend_policy: input.backend_policy,
          allow_transformations: input.allow_transformations,
          include_preflight: true,
          include_plan: analysisBudgetProfile !== 'quick',
          validate_build: analysisBudgetProfile === 'deep',
          run_harness: analysisBudgetProfile === 'deep' && sampleSizeTier !== 'large' && sampleSizeTier !== 'oversized',
          allow_partial: true,
        })
        const routingMetadata = extractRoutingMetadata(reconstructResult.data) || fallbackRouting
        const delegatedData =
          reconstructResult.data && typeof reconstructResult.data === 'object'
            ? (reconstructResult.data as Record<string, unknown>)
            : {}
        const coverageEnvelope =
          extractCoverageEnvelope(reconstructResult.data) ||
          buildCoverageEnvelope({
            coverageLevel: 'reconstruction',
            completionState:
              delegatedData.result_mode === 'queued'
                ? 'queued'
                : delegatedData.degraded
                  ? 'degraded'
                  : analysisBudgetProfile === 'deep'
                    ? 'completed'
                    : 'bounded',
            sampleSizeTier,
            analysisBudgetProfile,
            downgradeReasons: budgetDowngradeReasons,
            coverageGaps: [
              delegatedData.result_mode === 'queued'
                ? {
                    domain: 'reconstruction_export',
                    status: 'queued',
                    reason: 'Reconstruction job has not completed yet.',
                  }
                : null,
              analysisBudgetProfile !== 'deep'
                ? {
                    domain: 'build_validation',
                    status: 'skipped',
                    reason: 'Build and harness validation were bounded to control reconstruction cost.',
                  }
                : null,
              delegatedData.degraded
                ? {
                    domain: 'reconstruction',
                    status: 'degraded',
                    reason: 'Reconstruction completed with degraded or fallback artifacts.',
                  }
                : null,
            ],
            knownFindings: [
              typeof delegatedData.selected_path === 'string'
                ? `Reconstruction routed through ${delegatedData.selected_path}.`
                : null,
            ],
            suspectedFindings: [
              delegatedData.degraded ? 'Primary reconstruction path may have required degraded fallback behavior.' : null,
            ],
            unverifiedAreas: [
              analysisBudgetProfile !== 'deep'
                ? 'Full build validation or harness execution was intentionally skipped.'
                : null,
            ],
            upgradePaths: [
              {
                tool: delegatedData.result_mode === 'queued' ? 'task.status' : 'artifact.read',
                purpose:
                  delegatedData.result_mode === 'queued'
                    ? 'Wait for queued reconstruction completion.'
                    : 'Inspect export artifacts and unresolved gaps.',
                closes_gaps:
                  delegatedData.result_mode === 'queued'
                    ? ['reconstruction_export']
                    : ['reconstruction'],
                expected_coverage_gain:
                  delegatedData.result_mode === 'queued'
                    ? 'Returns completed reconstruction output once queued work finishes.'
                    : 'Shows exact reconstructed modules, gaps, and validation evidence.',
                cost_tier: 'low',
              },
            ],
          })

        return {
          ok: reconstructResult.ok,
          data: reconstructResult.ok
            ? mergeRoutingMetadata(
                mergeCoverageEnvelope(
                  {
                  sample_id: input.sample_id,
                  goal: input.goal,
                  depth: input.depth,
                  backend_policy: input.backend_policy,
                  routed_tool: 'workflow.reconstruct',
                  status: typeof delegatedData.status === 'string' ? delegatedData.status : undefined,
                  job_id: typeof delegatedData.job_id === 'string' ? delegatedData.job_id : undefined,
                  polling_guidance: delegatedData.polling_guidance,
                  routed_result: reconstructResult.data,
                  result_mode:
                    delegatedData.result_mode === 'queued' ? 'queued' : 'completed',
                  recommended_next_tools:
                    (delegatedData.recommended_next_tools as string[]) || ['task.status', 'artifact.read'],
                  next_actions:
                    (delegatedData.next_actions as string[]) || [
                      delegatedData.result_mode === 'queued'
                        ? 'Poll task.status until workflow.reconstruct completes.'
                        : 'Inspect exported artifacts and corroborating backend results before moving to semantic review.',
                    ],
                  },
                  coverageEnvelope
                ),
                routingMetadata
              )
            : undefined,
          warnings: reconstructResult.warnings,
          errors: reconstructResult.errors,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      if (input.goal === 'report') {
        const summarizeResult = await workflowSummarizeHandler({
          sample_id: input.sample_id,
          through_stage:
            input.depth === 'safe'
              ? 'triage'
              : input.depth === 'balanced'
                ? 'static'
                : analysisBudgetProfile === 'deep'
                  ? 'final'
                  : 'deep',
          synthesis_mode: 'deterministic',
          force_refresh: input.force_refresh,
        })
        const routingMetadata = extractRoutingMetadata(summarizeResult.data) || fallbackRouting
        const summarizeData =
          summarizeResult.data && typeof summarizeResult.data === 'object'
            ? (summarizeResult.data as Record<string, unknown>)
            : {}
        const synthesisData =
          summarizeData.synthesis && typeof summarizeData.synthesis === 'object'
            ? (summarizeData.synthesis as Record<string, unknown>)
            : {}
        const coverageEnvelope =
          extractCoverageEnvelope(summarizeResult.data) ||
          buildCoverageEnvelope({
            coverageLevel:
              analysisBudgetProfile === 'deep'
                ? 'reconstruction'
                : input.depth === 'safe'
                  ? 'quick'
                  : 'deep_static',
            completionState: analysisBudgetProfile === 'deep' ? 'completed' : 'bounded',
            sampleSizeTier,
            analysisBudgetProfile,
            downgradeReasons: budgetDowngradeReasons,
            coverageGaps:
              analysisBudgetProfile === 'deep'
                ? []
                : [
                    {
                      domain: 'summary_synthesis',
                      status: 'skipped',
                      reason: 'Final synthesis was intentionally bounded before the full final stage.',
                    },
                  ],
            knownFindings: [
              typeof synthesisData.executive_summary === 'string'
                ? (synthesisData.executive_summary as string)
                : null,
            ],
            unverifiedAreas:
              analysisBudgetProfile === 'deep'
                ? []
                : ['Final staged synthesis remains bounded until workflow.summarize runs through final.'],
            upgradePaths:
              analysisBudgetProfile === 'deep'
                ? []
                : [
                    {
                      tool: 'workflow.summarize',
                      purpose: 'Continue staged synthesis through the final summary stage.',
                      closes_gaps: ['summary_synthesis'],
                      expected_coverage_gain: 'Restates known, suspected, and unverified findings from the full staged summary path.',
                      cost_tier: 'medium',
                    },
                  ],
          })

        return {
          ok: summarizeResult.ok,
          data: summarizeResult.ok
            ? mergeRoutingMetadata(
                mergeCoverageEnvelope(
                  {
                  sample_id: input.sample_id,
                  goal: input.goal,
                  depth: input.depth,
                  backend_policy: input.backend_policy,
                  routed_tool: 'workflow.summarize',
                  routed_result: summarizeResult.data,
                  result_mode: 'completed',
                  recommended_next_tools:
                    (summarizeResult.data as Record<string, unknown>)?.recommended_next_tools as string[] || [
                      'artifact.read',
                      'artifacts.list',
                    ],
                  next_actions:
                    (summarizeResult.data as Record<string, unknown>)?.next_actions as string[] || [
                      'Read the staged summary artifacts when you need more detail than the compact summary.',
                    ],
                  },
                  coverageEnvelope
                ),
                routingMetadata
              )
            : undefined,
          warnings: summarizeResult.warnings,
          errors: summarizeResult.errors,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const dynamicPreflight = await dynamicDependenciesHandler({
        sample_id: input.sample_id,
      })
      const dynamicComponents =
        dynamicPreflight.ok &&
        dynamicPreflight.data &&
        typeof dynamicPreflight.data === 'object' &&
        typeof (dynamicPreflight.data as Record<string, unknown>).components === 'object'
          ? ((dynamicPreflight.data as Record<string, unknown>).components as Record<string, unknown>)
          : {}

      const qilingReady =
        Boolean((dynamicComponents.qiling as Record<string, unknown> | undefined)?.available) &&
        Boolean((dynamicComponents.qiling as Record<string, unknown> | undefined)?.rootfs_exists)
      const pandaReady = Boolean(
        (dynamicComponents.panda as Record<string, unknown> | undefined)?.available
      )
      const dynamicRouting = buildIntentBackendPlan({
        goal: 'dynamic',
        depth: input.depth,
        backendPolicy: input.backend_policy,
        allowTransformations: input.allow_transformations,
        allowLiveExecution: input.allow_live_execution,
        readiness,
        signals: {
          qiling_rootfs_ready: qilingReady,
          panda_ready: pandaReady,
        },
      })

      const sandboxMode =
        input.depth === 'deep' && Boolean((dynamicComponents.speakeasy as Record<string, unknown> | undefined)?.available)
          ? 'speakeasy'
          : 'safe_simulation'

      const sandboxResult = await sandboxExecuteHandler({
        sample_id: input.sample_id,
        mode: sandboxMode,
        network: 'disabled',
        approved: false,
        persist_artifact: true,
      })

      let qilingResult: WorkerResult | undefined
      let pandaResult: WorkerResult | undefined
      const selected = new Set(dynamicRouting.backend_selected.map((item) => item.tool))
      if (selected.has('qiling.inspect')) {
        qilingResult = await qilingInspectHandler({
          sample_id: input.sample_id,
          operation: 'preflight',
        })
      }
      if (selected.has('panda.inspect')) {
        pandaResult = await pandaInspectHandler({
          sample_id: input.sample_id,
        })
      }

      const warnings = dedupeStrings([
        ...(dynamicPreflight.warnings || []),
        ...(sandboxResult.warnings || []),
        ...(qilingResult?.warnings || []),
        ...(pandaResult?.warnings || []),
      ])
      const errors = dedupeStrings([
        ...(dynamicPreflight.errors || []),
        ...(sandboxResult.errors || []),
        ...(qilingResult?.errors || []),
        ...(pandaResult?.errors || []),
      ])

      return {
        ok: dynamicPreflight.ok || sandboxResult.ok,
        data:
          dynamicPreflight.ok || sandboxResult.ok
            ? mergeRoutingMetadata(
                mergeCoverageEnvelope(
                  {
                  sample_id: input.sample_id,
                  goal: input.goal,
                  depth: input.depth,
                  backend_policy: input.backend_policy,
                  routed_tool: 'dynamic.dependencies+sandbox.execute',
                  status: sandboxResult.ok ? 'completed' : 'partial',
                  dynamic_preflight: dynamicPreflight.data,
                  sandbox: sandboxResult.data,
                  backend_enrichments: {
                    ...(qilingResult?.ok && qilingResult.data ? { qiling: qilingResult.data } : {}),
                    ...(pandaResult?.ok && pandaResult.data ? { panda: pandaResult.data } : {}),
                  },
                  result_mode: 'completed',
                  recommended_next_tools: dedupeStrings([
                    'dynamic.dependencies',
                    'sandbox.execute',
                    qilingResult?.ok ? 'qiling.inspect' : undefined,
                    pandaResult?.ok ? 'panda.inspect' : undefined,
                    'wine.run',
                  ]),
                  next_actions: dedupeStrings([
                    'Start with the returned dynamic preflight and sandbox summary before considering any live execution path.',
                    qilingReady
                      ? 'Qiling readiness is available if you later add a Qiling-backed execution workflow.'
                      : 'Configure QILING_ROOTFS before expecting useful Qiling-backed emulation.',
                    'wine.run remains manual-only and still requires approved=true for run or debug modes.',
                  ]),
                  },
                  buildCoverageEnvelope({
                    coverageLevel: 'dynamic_verified',
                    completionState: sandboxResult.ok ? 'bounded' : 'partial',
                    sampleSizeTier,
                    analysisBudgetProfile,
                    downgradeReasons: dedupeStrings([
                      ...budgetDowngradeReasons,
                      !input.allow_live_execution
                        ? 'Live execution remained disabled, so dynamic routing stayed in readiness and safe-simulation mode.'
                        : null,
                    ]),
                    coverageGaps: [
                      {
                        domain: 'dynamic_behavior',
                        status: sandboxResult.ok ? 'degraded' : 'missing',
                        reason:
                          'Dynamic routing currently emphasizes readiness and safe simulation instead of full live execution.',
                      },
                    ],
                    knownFindings: [
                      sandboxResult.ok ? 'Safe simulation or bounded sandbox execution completed.' : null,
                    ],
                    suspectedFindings: [
                      qilingReady ? 'Qiling-backed emulation could deepen dynamic confirmation.' : null,
                    ],
                    unverifiedAreas: ['Live process execution and full runtime verification were not performed automatically.'],
                    upgradePaths: [
                      {
                        tool: qilingReady ? 'qiling.inspect' : 'dynamic.dependencies',
                        purpose: 'Check whether a deeper dynamic path is ready.',
                        closes_gaps: ['dynamic_behavior'],
                        expected_coverage_gain: 'Clarifies whether emulation-oriented dynamic upgrades are immediately available.',
                        cost_tier: 'medium',
                        availability: qilingReady ? 'ready' : 'blocked',
                        blockers: qilingReady ? [] : ['QILING_ROOTFS is missing or incomplete.'],
                      },
                      {
                        tool: 'wine.run',
                        purpose: 'Launch the sample under an explicit live-execution path.',
                        closes_gaps: ['dynamic_behavior'],
                        expected_coverage_gain: 'Provides live-execution observations that safe simulation cannot confirm.',
                        cost_tier: 'high',
                        availability: 'manual_only',
                        requires_approval: true,
                        prerequisites: ['approved=true'],
                      },
                    ],
                  })
                ),
                dynamicRouting
              )
            : undefined,
        warnings: warnings.length > 0 ? warnings : undefined,
        errors: errors.length > 0 ? errors : undefined,
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
