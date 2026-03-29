import { z } from 'zod'
import type { CreateMessageRequest } from '@modelcontextprotocol/sdk/types.js'
import type { ArtifactRef, ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager, Artifact, Function as DbFunction } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { MCPServer } from '../server.js'
import {
  createReportSummarizeHandler,
} from '../tools/report-summarize.js'
import { loadSemanticFunctionExplanationIndex } from '../semantic-name-suggestion-artifacts.js'
import {
  loadSummaryDigestArtifactSelection,
  persistSummaryDigestArtifact,
  type SummaryStage,
} from '../summary-artifacts.js'
import {
  SummaryArtifactRefSchema,
  TriageStageDigestSchema,
  StaticStageDigestSchema,
  DeepStageDigestSchema,
  FinalStageDigestSchema,
  FunctionExplanationPreviewSchema,
  ExplanationGraphSummarySchema,
  TopFunctionDigestSchema,
  buildArtifactRefFromParts,
  buildDeepStageDigest,
  buildFinalStageDigest,
  buildStaticStageDigest,
  buildTriageStageDigest,
  dedupeArtifactRefs,
  dedupeStrings,
} from '../summary-digests.js'
import { GhidraExecutionSummarySchema } from '../ghidra-execution-summary.js'
import {
  CoverageEnvelopeSchema,
  buildCoverageEnvelope,
  classifySampleSizeTier,
  deriveAnalysisBudgetProfile,
} from '../analysis-coverage.js'
import {
  getAnalysisRunSummary,
  createOrReuseAnalysisRun,
} from '../analysis-run-state.js'
import { ToolSurfaceRoleSchema } from '../tool-surface-guidance.js'

const TOOL_NAME = 'workflow.summarize'

const WorkflowSummarizeStageSchema = z.enum(['triage', 'static', 'deep', 'final'])

const SummarySamplingPayloadSchema = z.object({
  executive_summary: z.string(),
  analyst_summary: z.string(),
  key_findings: z.array(z.string()),
  next_steps: z.array(z.string()),
  unresolved_unknowns: z.array(z.string()),
})

const PersistedSummaryVisibilitySchema = z.object({
  persisted_run_id: z.string().nullable(),
  reused_stage_artifacts: z.boolean(),
  loaded_run_stages: z.array(z.string()),
  deferred_requirements: z.array(z.string()),
})

export const WorkflowSummarizeInputSchema = z
  .object({
    sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
    through_stage: WorkflowSummarizeStageSchema.default('final').describe(
      'Execute summary generation through this stage and stop there. Stop at triage/static/deep for bounded medium/large-sample reporting, or use final for the full compact staged summary.'
    ),
    session_tag: z
      .string()
      .optional()
      .describe('Optional summary digest session tag used for persisted stage artifact reuse.'),
    reuse_digests: z
      .boolean()
      .default(true)
      .describe('Reuse persisted summary-stage digest artifacts when a matching recent/session-scoped artifact exists.'),
    synthesis_mode: z
      .enum(['auto', 'deterministic', 'sampling'])
      .default('auto')
      .describe(
        'Final-stage synthesis mode. auto prefers client-mediated sampling when available, otherwise deterministic.'
      ),
    force_refresh: z
      .boolean()
      .default(false)
      .describe('Rebuild stage digests instead of reusing cached summary artifacts.'),
    evidence_scope: z
      .enum(['all', 'latest', 'session'])
      .default('all')
      .describe('Runtime evidence scope forwarded to the compact report builder.'),
    evidence_session_tag: z
      .string()
      .optional()
      .describe('Optional runtime evidence session selector used when evidence_scope=session.'),
    static_scope: z
      .enum(['all', 'latest', 'session'])
      .default('latest')
      .describe('Static-analysis artifact scope forwarded to the compact report builder.'),
    static_session_tag: z
      .string()
      .optional()
      .describe('Optional static-analysis session selector used when static_scope=session.'),
    semantic_scope: z
      .enum(['all', 'latest', 'session'])
      .default('all')
      .describe('Semantic explanation artifact scope forwarded to the compact report builder.'),
    semantic_session_tag: z
      .string()
      .optional()
      .describe('Optional semantic explanation selector used when semantic_scope=session.'),
    compare_evidence_scope: z
      .enum(['all', 'latest', 'session'])
      .optional()
      .describe('Optional baseline runtime evidence scope passed through to compact report generation.'),
    compare_evidence_session_tag: z.string().optional(),
    compare_static_scope: z
      .enum(['all', 'latest', 'session'])
      .optional()
      .describe('Optional baseline static-analysis scope passed through to compact report generation.'),
    compare_static_session_tag: z.string().optional(),
    compare_semantic_scope: z
      .enum(['all', 'latest', 'session'])
      .optional()
      .describe('Optional baseline semantic scope passed through to compact report generation.'),
    compare_semantic_session_tag: z.string().optional(),
  })
  .refine((value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()), {
    message: 'evidence_session_tag is required when evidence_scope=session',
    path: ['evidence_session_tag'],
  })
  .refine((value) => value.static_scope !== 'session' || Boolean(value.static_session_tag?.trim()), {
    message: 'static_session_tag is required when static_scope=session',
    path: ['static_session_tag'],
  })
  .refine((value) => value.semantic_scope !== 'session' || Boolean(value.semantic_session_tag?.trim()), {
    message: 'semantic_session_tag is required when semantic_scope=session',
    path: ['semantic_session_tag'],
  })
  .refine(
    (value) =>
      value.compare_evidence_scope !== 'session' || Boolean(value.compare_evidence_session_tag?.trim()),
    {
      message: 'compare_evidence_session_tag is required when compare_evidence_scope=session',
      path: ['compare_evidence_session_tag'],
    }
  )
  .refine(
    (value) =>
      value.compare_static_scope !== 'session' || Boolean(value.compare_static_session_tag?.trim()),
    {
      message: 'compare_static_session_tag is required when compare_static_scope=session',
      path: ['compare_static_session_tag'],
    }
  )
  .refine(
    (value) =>
      value.compare_semantic_scope !== 'session' ||
      Boolean(value.compare_semantic_session_tag?.trim()),
    {
      message: 'compare_semantic_session_tag is required when compare_semantic_scope=session',
      path: ['compare_semantic_session_tag'],
    }
  )

export const WorkflowSummarizeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      through_stage: WorkflowSummarizeStageSchema,
      detail_level: z.literal('compact'),
      tool_surface_role: ToolSurfaceRoleSchema,
      preferred_primary_tools: z.array(z.string()),
      completed_stages: z.array(WorkflowSummarizeStageSchema),
      stages: z.object({
        triage: TriageStageDigestSchema.optional(),
        static: StaticStageDigestSchema.optional(),
        deep: DeepStageDigestSchema.optional(),
        final: FinalStageDigestSchema.optional(),
      }),
      stage_artifacts: z.object({
        triage: SummaryArtifactRefSchema.optional(),
        static: SummaryArtifactRefSchema.optional(),
        deep: SummaryArtifactRefSchema.optional(),
        final: SummaryArtifactRefSchema.optional(),
      }),
      synthesis: z.object({
        requested_mode: z.enum(['auto', 'deterministic', 'sampling']),
        resolved_mode: z.enum(['deterministic', 'sampling']),
        sampling_available: z.boolean(),
        used_existing_stage_artifacts: z.boolean(),
        model_name: z.string().nullable(),
      }),
      explanation_graphs: z.array(ExplanationGraphSummarySchema).optional(),
      explanation_artifacts: z.array(SummaryArtifactRefSchema).optional(),
      persisted_state_visibility: PersistedSummaryVisibilitySchema.optional(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .extend(CoverageEnvelopeSchema.shape)
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

export const workflowSummarizeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Primary staged reporting workflow. Builds or reuses bounded triage/static/deep/final digest artifacts and returns compact final reporting output by stage. ' +
    'Prefer this over report.summarize when you need the final analyst-facing summary path without one monolithic payload. ' +
    'Read coverage_level, completion_state, known_findings, suspected_findings, unverified_areas, and upgrade_paths on the result before treating the summary as complete. ' +
    '\n\nDecision guide:\n' +
    '- Use when: you want staged digest artifacts, resumable summary generation, or a final compact summary.\n' +
    '- Best for: medium/large samples or any run that already progressed through queued analysis stages.\n' +
    '- Do not use when: you only need a single deterministic digest snapshot; report.summarize is enough.\n' +
    '- Typical next step: use artifact.read or artifacts.list on returned stage_artifacts for supporting detail.\n' +
    '- Common mistake: expecting the workflow to inline raw backend payloads instead of returning digest artifacts.',
  inputSchema: WorkflowSummarizeInputSchema,
  outputSchema: WorkflowSummarizeOutputSchema,
}

function extractCoverage(payload: unknown): z.infer<typeof CoverageEnvelopeSchema> | null {
  if (!payload || typeof payload !== 'object') {
    return null
  }
  const parsed = CoverageEnvelopeSchema.safeParse(payload)
  return parsed.success ? parsed.data : null
}

interface WorkflowSummarizeDependencies {
  reportSummarizeHandler?: (args: ToolArgs) => Promise<WorkerResult>
  samplingRequester?: (params: CreateMessageRequest['params']) => Promise<any>
  clientCapabilitiesProvider?: () => { sampling?: unknown } | undefined
  clientVersionProvider?: () => { name?: string; version?: string } | undefined
}

function toolMetrics(startTime: number) {
  return {
    elapsed_ms: Date.now() - startTime,
    tool: TOOL_NAME,
  }
}

function artifactRefFromArtifact(artifact: Artifact, stage: SummaryStage) {
  return buildArtifactRefFromParts({
    id: artifact.id,
    type: artifact.type,
    path: artifact.path,
    sha256: artifact.sha256,
    mime: artifact.mime,
    metadata: {
      summary_stage: stage,
    },
  })
}

function getArtifactMap(database: DatabaseManager, sampleId: string) {
  return new Map(database.findArtifacts(sampleId).map((item) => [item.id, item]))
}

function parseSummaryJsonCandidate(rawText: string) {
  const candidates: string[] = []
  const start = rawText.indexOf('{')
  const end = rawText.lastIndexOf('}')
  if (start >= 0 && end > start) {
    candidates.push(rawText.slice(start, end + 1))
  }
  candidates.push(rawText)

  for (const candidate of candidates) {
    try {
      return SummarySamplingPayloadSchema.parse(JSON.parse(candidate))
    } catch {
      continue
    }
  }

  throw new Error(
    'Sampling response could not be parsed as strict JSON summary payload. Return JSON only.'
  )
}

function extractTextBlocks(result: any): string {
  const content = Array.isArray(result?.content) ? result.content : []
  return content
    .filter((item) => item && typeof item === 'object' && item.type === 'text')
    .map((item) => String(item.text || ''))
    .join('\n')
    .trim()
}

function buildSamplingRequest(
  triageDigest: z.infer<typeof TriageStageDigestSchema>,
  staticDigest: z.infer<typeof StaticStageDigestSchema> | null,
  deepDigest: z.infer<typeof DeepStageDigestSchema> | null
): CreateMessageRequest['params'] {
  const systemPrompt = [
    'You are an evidence-grounded reverse-engineering reporting assistant.',
    'Return strict JSON only.',
    'Do not call tools.',
    'Do not include markdown, commentary, or code fences.',
    'Use only the supplied staged digests.',
    'Preserve uncertainty explicitly.',
  ].join(' ')

  const taskPrompt = JSON.stringify(
    {
      task: 'Synthesize a compact final analyst summary from staged digests only.',
      output_contract: {
        executive_summary: 'string',
        analyst_summary: 'string',
        key_findings: ['string'],
        next_steps: ['string'],
        unresolved_unknowns: ['string'],
      },
      boundary_rules: [
        'Do not claim skipped stages were completed.',
        'Preserve the distinction between known findings, suspected findings, and unverified areas from the digests.',
      ],
      digests: {
        triage: triageDigest,
        static: staticDigest,
        deep: deepDigest,
      },
    },
    null,
    2
  )

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
    systemPrompt,
    maxTokens: 1200,
    temperature: 0.2,
    modelPreferences: {
      intelligencePriority: 0.6,
      speedPriority: 0.4,
      costPriority: 0.4,
    },
  }
}

function buildTopFunctions(functions: DbFunction[]) {
  return functions.map((item) =>
    TopFunctionDigestSchema.parse({
      address: item.address,
      name: item.name || null,
      score: typeof item.score === 'number' ? item.score : null,
      summary: item.summary || null,
    })
  )
}

async function loadFunctionExplanationSummaries(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  options?: { scope?: 'all' | 'latest' | 'session'; sessionTag?: string }
) {
  const index = await loadSemanticFunctionExplanationIndex(workspaceManager, database, sampleId, {
    scope: options?.scope,
    sessionTag: options?.sessionTag,
  })
  const explanations = Array.from(index.byAddress.values())
  explanations.sort((a, b) => {
    if (b.confidence !== a.confidence) {
      return b.confidence - a.confidence
    }
    return (b.created_at || '').localeCompare(a.created_at || '')
  })
  return explanations.slice(0, 6).map((item) =>
    FunctionExplanationPreviewSchema.parse({
      address: item.address,
      function: item.function,
      behavior: item.behavior,
      summary: item.summary,
      confidence: item.confidence,
      rewrite_guidance: (item.rewrite_guidance || []).slice(0, 4),
      source: item.model_name || item.client_name || null,
    })
  )
}

export function createWorkflowSummarizeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  mcpServer?: MCPServer,
  deps?: WorkflowSummarizeDependencies
) {
  const reportSummarizeHandler =
    deps?.reportSummarizeHandler ||
    createReportSummarizeHandler(workspaceManager, database, cacheManager)
  const samplingRequester =
    deps?.samplingRequester ||
    (mcpServer ? (params: CreateMessageRequest['params']) => mcpServer.createMessage(params) : undefined)
  const clientCapabilitiesProvider =
    deps?.clientCapabilitiesProvider ||
    (mcpServer ? () => mcpServer.getClientCapabilities() : undefined)
  const clientVersionProvider =
    deps?.clientVersionProvider ||
    (mcpServer ? () => mcpServer.getClientVersion() : undefined)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const warnings: string[] = []

    try {
      const input = WorkflowSummarizeInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: toolMetrics(startTime),
        }
      }
      
      // Check if there's a persisted analysis run for this sample
      // If found, consume run state and stage artifacts instead of rerunning analysis
      const runs = database.findAnalysisRunsBySample(input.sample_id)
      const latestRun = runs.length > 0 ? runs.sort((a, b) => b.updated_at.localeCompare(a.updated_at))[0] : null

      // Initialize stage tracking variables
      const completedStages: SummaryStage[] = []
      const stageArtifacts: Partial<Record<SummaryStage, ArtifactRef>> = {}

      if (latestRun && latestRun.status !== 'created') {
        warnings.push(
          `Consuming persisted analysis run state (run_id: ${latestRun.id}, status: ${latestRun.status}, latest_stage: ${latestRun.latest_stage || 'none'}).`
        )
        
        // Map run stages to summary stages
        const stageMap: Record<string, SummaryStage> = {
          fast_profile: 'triage',
          enrich_static: 'static',
          function_map: 'deep',
          reconstruct: 'deep',
          dynamic_plan: 'triage',
          dynamic_execute: 'triage',
          summarize: 'final',
        }
        
        // Load stage artifacts from run state
        const runStages = database.findAnalysisRunStages(latestRun.id)
        for (const stage of runStages) {
          if (stage.status === 'completed' && stage.artifact_refs_json) {
            const summaryStage = stageMap[stage.stage]
            if (summaryStage && !stageArtifacts[summaryStage]) {
              try {
                const artifactRefs = JSON.parse(stage.artifact_refs_json) as ArtifactRef[]
                if (artifactRefs.length > 0) {
                  stageArtifacts[summaryStage] = artifactRefs[0]
                  completedStages.push(summaryStage)
                  warnings.push(
                    `Loaded ${summaryStage} stage artifacts from run stage ${stage.stage}.`
                  )
                }
              } catch {
                // Ignore JSON parse errors, continue without this stage's artifacts
              }
            }
          }
        }
      }
      
      const sampleSizeTier = classifySampleSizeTier(sample.size || 0)
      const analysisBudgetProfile = deriveAnalysisBudgetProfile(
        input.through_stage === 'final' ? 'deep' : input.through_stage === 'triage' ? 'safe' : 'balanced',
        sampleSizeTier
      )
      const persistedStateVisibility = PersistedSummaryVisibilitySchema.parse({
        persisted_run_id: latestRun?.id || null,
        reused_stage_artifacts: false,
        loaded_run_stages: latestRun ? database.findAnalysisRunStages(latestRun.id).map((stage) => stage.stage) : [],
        deferred_requirements: latestRun
          ? []
          : ['analysis_run: no persisted staged analysis run was available for this sample.'],
      })

      const artifactMap = getArtifactMap(database, input.sample_id)
      const stageDigests: Partial<Record<SummaryStage, unknown>> = {}
      const effectiveReuse = input.reuse_digests && !input.force_refresh
      let reusedAnyStage = false
      let compactReportResult: WorkerResult | null = null
      const currentStageArtifactRefs = () =>
        Object.values(stageArtifacts).filter((item): item is ArtifactRef => Boolean(item))

      const getCompactReportData = async () => {
        if (compactReportResult) {
          return compactReportResult
        }
        compactReportResult = await reportSummarizeHandler({
          sample_id: input.sample_id,
          mode: 'triage',
          detail_level: 'compact',
          force_refresh: input.force_refresh,
          evidence_scope: input.evidence_scope,
          evidence_session_tag: input.evidence_session_tag,
          static_scope: input.static_scope,
          static_session_tag: input.static_session_tag,
          semantic_scope: input.semantic_scope,
          semantic_session_tag: input.semantic_session_tag,
          compare_evidence_scope: input.compare_evidence_scope,
          compare_evidence_session_tag: input.compare_evidence_session_tag,
          compare_static_scope: input.compare_static_scope,
          compare_static_session_tag: input.compare_static_session_tag,
          compare_semantic_scope: input.compare_semantic_scope,
          compare_semantic_session_tag: input.compare_semantic_session_tag,
        })
        warnings.push(...(compactReportResult.warnings || []))
        return compactReportResult
      }

      const loadReusedStage = async <TSchema extends z.ZodTypeAny>(
        stage: SummaryStage,
        schema: TSchema
      ): Promise<z.infer<TSchema> | null> => {
        if (!effectiveReuse) {
          return null
        }
        const selection = await loadSummaryDigestArtifactSelection<unknown>(
          workspaceManager,
          database,
          input.sample_id,
          stage,
          {
            scope: input.session_tag ? 'session' : 'latest',
            sessionTag: input.session_tag,
          }
        )
        if (!selection.latest_payload || selection.artifact_ids.length === 0) {
          return null
        }
        try {
          const parsed = schema.parse(selection.latest_payload)
          const artifact = artifactMap.get(selection.artifact_ids[0])
          if (artifact) {
            stageArtifacts[stage] = artifactRefFromArtifact(artifact, stage)
          }
          reusedAnyStage = true
          warnings.push(
            `Reused persisted ${stage} summary digest from ${selection.latest_created_at || 'latest available artifact'}.`
          )
          return parsed
        } catch {
          return null
        }
      }

      const persistStage = async (stage: SummaryStage, payload: unknown) => {
        const artifact = await persistSummaryDigestArtifact(
          workspaceManager,
          database,
          input.sample_id,
          stage,
          payload,
          input.session_tag
        )
        stageArtifacts[stage] = artifact
      }

      const ensureTriageStage = async () => {
        if (stageDigests.triage) {
          return stageDigests.triage as z.infer<typeof TriageStageDigestSchema>
        }
        const reused = await loadReusedStage('triage', TriageStageDigestSchema)
        if (reused) {
          stageDigests.triage = reused
          completedStages.push('triage')
          return reused
        }

        const report = await getCompactReportData()
        if (!report.ok || !report.data) {
          throw new Error((report.errors || ['report.summarize failed']).join('; '))
        }
        const data = report.data as any
        const triageDigest = buildTriageStageDigest({
          sample_id: input.sample_id,
          session_tag: input.session_tag || null,
          summary: String(data.summary || ''),
          confidence: Number(data.confidence || 0),
          threat_level: data.threat_level,
          iocs: data.iocs || {
            suspicious_imports: [],
            suspicious_strings: [],
            yara_matches: [],
          },
          evidence: Array.isArray(data.evidence) ? data.evidence : [],
          evidence_lineage: data.evidence_lineage,
          confidence_semantics: data.confidence_semantics,
          recommendation: String(data.recommendation || ''),
          source_artifact_refs: Array.isArray(data.artifact_refs?.supporting)
            ? (data.artifact_refs.supporting as ArtifactRef[])
            : [],
          coverage: extractCoverage(data) || undefined,
        })
        await persistStage('triage', triageDigest)
        stageDigests.triage = triageDigest
        completedStages.push('triage')
        return triageDigest
      }

      const ensureStaticStage = async () => {
        if (stageDigests.static) {
          return stageDigests.static as z.infer<typeof StaticStageDigestSchema>
        }
        const reused = await loadReusedStage('static', StaticStageDigestSchema)
        if (reused) {
          stageDigests.static = reused
          completedStages.push('static')
          return reused
        }
        const report = await getCompactReportData()
        if (!report.ok || !report.data) {
          throw new Error((report.errors || ['report.summarize failed']).join('; '))
        }
        const data = report.data as any
        const staticDigest = buildStaticStageDigest({
          sample_id: input.sample_id,
          session_tag: input.session_tag || null,
          binary_profile_summary: data.binary_profile_summary || undefined,
          rust_profile_summary: data.rust_profile_summary || undefined,
          static_capability_summary: data.static_capability_summary || undefined,
          pe_structure_summary: data.pe_structure_summary || undefined,
          compiler_packer_summary: data.compiler_packer_summary || undefined,
          semantic_explanation_summary: data.semantic_explanation_summary || undefined,
          key_findings: dedupeStrings([
            data.binary_profile_summary?.summary,
            data.rust_profile_summary?.summary,
            data.static_capability_summary?.summary,
            data.pe_structure_summary?.summary,
            data.compiler_packer_summary?.summary,
            data.semantic_explanation_summary?.summary,
            data.packed_state ? `Packed state: ${data.packed_state}.` : null,
            data.unpack_state ? `Unpack state: ${data.unpack_state}.` : null,
            ...(Array.isArray(data.unpack_debug_diffs)
              ? data.unpack_debug_diffs.flatMap((item: any) =>
                  Array.isArray(item.findings) ? item.findings.slice(0, 2) : []
                )
              : []),
          ]),
          recommendation: String(data.recommendation || ''),
          source_artifact_refs: Array.isArray(data.artifact_refs?.supporting)
            ? (data.artifact_refs.supporting as ArtifactRef[])
            : [],
          coverage: extractCoverage(data) || undefined,
        })
        await persistStage('static', staticDigest)
        stageDigests.static = staticDigest
        completedStages.push('static')
        return staticDigest
      }

      const ensureDeepStage = async () => {
        if (stageDigests.deep) {
          return stageDigests.deep as z.infer<typeof DeepStageDigestSchema>
        }
        const reused = await loadReusedStage('deep', DeepStageDigestSchema)
        if (reused) {
          stageDigests.deep = reused
          completedStages.push('deep')
          return reused
        }
        const report = await getCompactReportData()
        if (!report.ok || !report.data) {
          throw new Error((report.errors || ['report.summarize failed']).join('; '))
        }
        const data = report.data as any
        const topFunctions = buildTopFunctions(database.findFunctionsByScore(input.sample_id, 8))
        const functionExplanations = await loadFunctionExplanationSummaries(
          workspaceManager,
          database,
          input.sample_id,
          {
            scope: input.semantic_scope,
            sessionTag: input.semantic_session_tag,
          }
        )
        const ghidraExecution =
          data.ghidra_execution ? GhidraExecutionSummarySchema.parse(data.ghidra_execution) : null
        const analysisGaps = dedupeStrings([
          ...(Array.isArray(ghidraExecution?.warnings) ? ghidraExecution.warnings : []),
          ...(topFunctions.length === 0
            ? ['No scored functions are currently persisted for deep-stage review.']
            : []),
          ...(functionExplanations.length === 0
            ? ['No semantic function explanations are currently persisted.']
            : []),
          ...(data.packed_state && data.packed_state !== 'not_packed'
            ? [`Packed/debug progression is still relevant: packed_state=${data.packed_state}, unpack_state=${data.unpack_state || 'unknown'}.`]
            : []),
        ])
        const deepDigest = buildDeepStageDigest({
          sample_id: input.sample_id,
          session_tag: input.session_tag || null,
          summary:
            ghidraExecution
              ? `Deep-stage digest summarizes persisted Ghidra execution plus ${topFunctions.length} scored function(s).`
              : `Deep-stage digest summarizes persisted reconstruction context plus ${topFunctions.length} scored function(s).`,
          ghidra_execution: ghidraExecution,
          top_functions: topFunctions,
          function_explanations: functionExplanations,
          analysis_gaps: analysisGaps,
          recommendation:
            topFunctions.length > 0
              ? 'Use artifact.read on referenced summary or reconstruction artifacts before requesting broader narrative output.'
              : 'Run ghidra.analyze or workflow.reconstruct to produce deeper persisted artifacts before relying on deep-stage synthesis.',
          source_artifact_refs: dedupeArtifactRefs([
            ...(Array.isArray(data.artifact_refs?.supporting)
              ? (data.artifact_refs.supporting as ArtifactRef[])
              : []),
            ...(Array.isArray(data.artifact_refs?.supporting)
              ? (data.artifact_refs.supporting as ArtifactRef[]).filter((item) =>
                  typeof item.type === 'string' && item.type === 'analysis_diff_digest'
                )
              : []),
          ]),
          coverage: buildCoverageEnvelope({
            coverageLevel: 'deep_static',
            completionState: topFunctions.length > 0 ? 'completed' : 'bounded',
            sampleSizeTier,
            analysisBudgetProfile,
            coverageGaps: [
              ...analysisGaps.map((item) => ({
                domain: 'deep_analysis_gap',
                status: 'degraded' as const,
                reason: item,
              })),
              ...(topFunctions.length === 0
                ? [
                    {
                      domain: 'decompilation',
                      status: 'missing' as const,
                      reason: 'No scored functions were available for the deep-stage digest.',
                    },
                  ]
                : []),
              {
                domain: 'reconstruction_export',
                status: 'missing' as const,
                reason: 'Deep-stage digest does not include source-like reconstruction export.',
              },
            ],
            knownFindings: topFunctions.slice(0, 3).map((item) => `${item.address}: ${item.name || 'function'}`),
            suspectedFindings: analysisGaps,
            unverifiedAreas: ['Source-like reconstruction and runtime verification remain outside the deep-stage digest.'],
            upgradePaths: [
              {
                tool: 'workflow.reconstruct',
                purpose: 'Continue from deep-stage context into reconstruction export.',
                closes_gaps: ['reconstruction_export'],
                expected_coverage_gain: 'Adds export artifacts and validation notes beyond the deep-stage digest.',
                cost_tier: 'high',
              },
            ],
          }),
        })
        await persistStage('deep', deepDigest)
        stageDigests.deep = deepDigest
        completedStages.push('deep')
        return deepDigest
      }

      const ensureFinalStage = async () => {
        if (stageDigests.final) {
          return stageDigests.final as z.infer<typeof FinalStageDigestSchema>
        }
        const reused = await loadReusedStage('final', FinalStageDigestSchema)
        if (reused) {
          stageDigests.final = reused
          completedStages.push('final')
          return reused
        }
        const triageDigest = await ensureTriageStage()
        const staticDigest = await ensureStaticStage()
        const deepDigest = await ensureDeepStage()
        const compactReport = await getCompactReportData()
        const compactReportData =
          compactReport.ok && compactReport.data ? (compactReport.data as Record<string, unknown>) : {}
        const explanationGraphs = Array.isArray(compactReportData.explanation_graphs)
          ? compactReportData.explanation_graphs
          : undefined
        const explanationArtifacts =
          compactReportData.artifact_refs &&
          typeof compactReportData.artifact_refs === 'object' &&
          Array.isArray((compactReportData.artifact_refs as Record<string, unknown>).explanation_graphs)
            ? ((compactReportData.artifact_refs as Record<string, unknown>).explanation_graphs as ArtifactRef[])
            : undefined
        const samplingAvailable = Boolean(clientCapabilitiesProvider?.()?.sampling && samplingRequester)
        const requestedMode = input.synthesis_mode
        const shouldUseSampling =
          requestedMode === 'sampling' || (requestedMode === 'auto' && samplingAvailable)
        let finalDigest = buildFinalStageDigest({
          sample_id: input.sample_id,
          session_tag: input.session_tag || null,
          triage: triageDigest,
          staticDigest,
          deepDigest,
          stage_artifact_refs: currentStageArtifactRefs(),
          synthesis_mode: shouldUseSampling ? 'sampling' : 'deterministic',
          explanation_graphs: Array.isArray(explanationGraphs) ? explanationGraphs as any[] : undefined,
          explanation_artifact_refs: explanationArtifacts,
          source_artifact_refs: dedupeArtifactRefs([
            ...(triageDigest.source_artifact_refs as ArtifactRef[]),
            ...(staticDigest.source_artifact_refs as ArtifactRef[]),
            ...(deepDigest.source_artifact_refs as ArtifactRef[]),
          ]),
        })

        if (shouldUseSampling) {
          if (!samplingAvailable) {
            warnings.push(
              'Requested sampling synthesis, but the connected MCP client did not advertise sampling support. Falling back to deterministic synthesis.'
            )
            finalDigest = buildFinalStageDigest({
              sample_id: input.sample_id,
              session_tag: input.session_tag || null,
              triage: triageDigest,
              staticDigest,
              deepDigest,
              stage_artifact_refs: currentStageArtifactRefs(),
              synthesis_mode: 'deterministic',
              explanation_graphs: Array.isArray(explanationGraphs) ? explanationGraphs as any[] : undefined,
              explanation_artifact_refs: explanationArtifacts,
              source_artifact_refs: dedupeArtifactRefs([
                ...(triageDigest.source_artifact_refs as ArtifactRef[]),
                ...(staticDigest.source_artifact_refs as ArtifactRef[]),
                ...(deepDigest.source_artifact_refs as ArtifactRef[]),
              ]),
            })
          } else {
            try {
              const samplingResult = await samplingRequester!(buildSamplingRequest(triageDigest, staticDigest, deepDigest))
              const responseText = extractTextBlocks(samplingResult)
              const parsed = parseSummaryJsonCandidate(responseText)
              finalDigest = {
                ...finalDigest,
                synthesis_mode: 'sampling',
                model_name: (samplingResult as any)?.model || null,
                executive_summary: parsed.executive_summary,
                analyst_summary: parsed.analyst_summary,
                key_findings: parsed.key_findings.slice(0, 8),
                next_steps: parsed.next_steps.slice(0, 5),
                unresolved_unknowns: parsed.unresolved_unknowns.slice(0, 5),
              }
            } catch (error) {
              warnings.push(
                error instanceof Error
                  ? `${error.message} Falling back to deterministic synthesis.`
                  : 'Sampling synthesis failed; falling back to deterministic synthesis.'
              )
              finalDigest = buildFinalStageDigest({
                sample_id: input.sample_id,
                session_tag: input.session_tag || null,
                triage: triageDigest,
                staticDigest,
                deepDigest,
                stage_artifact_refs: currentStageArtifactRefs(),
                synthesis_mode: 'deterministic',
                explanation_graphs: Array.isArray(explanationGraphs) ? explanationGraphs as any[] : undefined,
                explanation_artifact_refs: explanationArtifacts,
                source_artifact_refs: dedupeArtifactRefs([
                  ...(triageDigest.source_artifact_refs as ArtifactRef[]),
                  ...(staticDigest.source_artifact_refs as ArtifactRef[]),
                  ...(deepDigest.source_artifact_refs as ArtifactRef[]),
                ]),
              })
            }
          }
        }

        await persistStage('final', finalDigest)
        stageDigests.final = finalDigest
        completedStages.push('final')
        return finalDigest
      }

      await ensureTriageStage()
      if (input.through_stage === 'static' || input.through_stage === 'deep' || input.through_stage === 'final') {
        await ensureStaticStage()
      }
      if (input.through_stage === 'deep' || input.through_stage === 'final') {
        await ensureDeepStage()
      }
      if (input.through_stage === 'final') {
        await ensureFinalStage()
      }

      const finalStage = stageDigests.final as z.infer<typeof FinalStageDigestSchema> | undefined
      const currentCoverage =
        extractCoverage(finalStage) ||
        extractCoverage(stageDigests.deep) ||
        extractCoverage(stageDigests.static) ||
        extractCoverage(stageDigests.triage) ||
        buildCoverageEnvelope({
          coverageLevel:
            input.through_stage === 'triage'
              ? 'quick'
              : input.through_stage === 'static'
                ? 'static_core'
                : 'deep_static',
          completionState: input.through_stage === 'final' ? 'completed' : 'bounded',
          sampleSizeTier,
          analysisBudgetProfile,
          unverifiedAreas: ['Coverage boundary could not be derived from persisted stage artifacts.'],
        })
      const samplingAvailable = Boolean(clientCapabilitiesProvider?.()?.sampling && samplingRequester)
      const resolvedMode = finalStage?.synthesis_mode || 'deterministic'
      const recommendedNextTools =
        input.through_stage === 'final'
          ? ['artifact.read', 'artifacts.list', 'report.generate']
          : input.through_stage === 'deep'
            ? ['workflow.summarize', 'artifact.read', 'workflow.reconstruct']
            : ['workflow.summarize', 'artifact.read', 'ghidra.analyze', 'workflow.reconstruct']
      const nextActions =
        input.through_stage === 'final'
          ? [
              'Use artifact.read on stage_artifacts.final or the referenced supporting artifacts when you need deeper supporting detail.',
              'Read explanation_artifacts when you want bounded semantic graphs that explain findings, omissions, and next-stage escalation.',
              'Use artifacts.list with path_prefix=reports/summary to inspect persisted staged digests.',
            ]
          : [
              `Rerun workflow.summarize through a later stage (current through_stage=${input.through_stage}) when you need deeper synthesis.`,
              'Use artifact.read or artifacts.list on the returned stage_artifacts for supporting detail instead of requesting a monolithic inline payload.',
              'When explanation_artifacts are present, prefer them over decorative graph export requests because they carry provenance, confidence, and omission boundaries.',
            ]

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          through_stage: input.through_stage,
          detail_level: 'compact',
          tool_surface_role: 'primary',
          preferred_primary_tools: [],
          completed_stages: completedStages,
          stages: {
            ...(stageDigests.triage ? { triage: stageDigests.triage as any } : {}),
            ...(stageDigests.static ? { static: stageDigests.static as any } : {}),
            ...(stageDigests.deep ? { deep: stageDigests.deep as any } : {}),
            ...(stageDigests.final ? { final: stageDigests.final as any } : {}),
          },
          stage_artifacts: {
            ...(stageArtifacts.triage ? { triage: stageArtifacts.triage } : {}),
            ...(stageArtifacts.static ? { static: stageArtifacts.static } : {}),
            ...(stageArtifacts.deep ? { deep: stageArtifacts.deep } : {}),
            ...(stageArtifacts.final ? { final: stageArtifacts.final } : {}),
          },
          synthesis: {
            requested_mode: input.synthesis_mode,
            resolved_mode: resolvedMode,
            sampling_available: samplingAvailable,
            used_existing_stage_artifacts: reusedAnyStage,
            model_name: finalStage?.model_name || null,
          },
          ...(finalStage?.explanation_graphs
            ? { explanation_graphs: finalStage.explanation_graphs }
            : {}),
          ...(finalStage?.explanation_artifact_refs
            ? { explanation_artifacts: finalStage.explanation_artifact_refs }
            : {}),
          persisted_state_visibility: {
            ...persistedStateVisibility,
            reused_stage_artifacts: reusedAnyStage,
          },
          ...currentCoverage,
          recommended_next_tools: recommendedNextTools,
          next_actions: nextActions,
        },
        warnings: warnings.length > 0 ? dedupeStrings(warnings) : undefined,
        metrics: toolMetrics(startTime),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: toolMetrics(startTime),
      }
    }
  }
}
