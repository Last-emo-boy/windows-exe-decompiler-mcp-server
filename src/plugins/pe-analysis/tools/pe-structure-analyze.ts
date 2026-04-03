import { randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult , PluginToolDeps} from '../../sdk.js'
import {
  buildPeStructureConfidenceSemantics,
  ConfidenceSemanticsSchema,
} from '../../../confidence-semantics.js'
import {
  buildBaselinePythonSetupActions,
  buildStaticAnalysisRequiredUserInputs,
  buildStaticAnalysisSetupActions,
  mergeSetupActions,
} from '../../../setup-guidance.js'
import {
  persistStaticAnalysisJsonArtifact,
  PE_STRUCTURE_ANALYSIS_ARTIFACT_TYPE,
} from '../../../static-analysis-artifacts.js'
import { resolvePrimarySamplePath } from '../../../sample-workspace.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker,
  type StaticWorkerResponse,
} from '../../../tools/static-worker-client.js'

const TOOL_NAME = 'pe.structure.analyze'
const TOOL_VERSION = '0.2.0'

const PeStructureSummarySchema = z.object({
  section_count: z.number().int().nonnegative(),
  import_dll_count: z.number().int().nonnegative(),
  import_function_count: z.number().int().nonnegative(),
  export_count: z.number().int().nonnegative(),
  forwarder_count: z.number().int().nonnegative(),
  resource_count: z.number().int().nonnegative(),
  overlay_present: z.boolean(),
  parser_preference: z.string(),
})

export const peStructureAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist normalized PE structure analysis into reports/static_analysis'),
  register_analysis: z
    .boolean()
    .default(true)
    .describe('Insert a completed analysis row for PE structure analysis'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag for persisted static-analysis artifacts'),
})

export const PEStructureAnalyzeDataSchema = z.object({
  status: z.enum(['ready', 'partial', 'setup_required']),
  sample_id: z.string(),
  summary: PeStructureSummarySchema,
  headers: z.any(),
  entry_point: z.any(),
  sections: z.array(z.any()),
  imports: z.any(),
  exports: z.any(),
  resources: z.any(),
  overlay: z.any(),
  backend_details: z.record(z.any()),
  confidence_semantics: ConfidenceSemanticsSchema.nullable(),
  analysis_id: z.string().optional(),
  artifact: z
    .object({
      id: z.string(),
      type: z.string(),
      path: z.string(),
      sha256: z.string(),
      mime: z.string().optional(),
    })
    .optional(),
})

export const peStructureAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: PEStructureAnalyzeDataSchema.optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
      worker_elapsed_ms: z.number().optional(),
    })
    .optional(),
})

export const peStructureAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Parse PE headers, sections, imports, exports, resources, and overlays through pefile and LIEF with a canonical MCP schema.',
  inputSchema: peStructureAnalyzeInputSchema,
  outputSchema: peStructureAnalyzeOutputSchema,
}

interface PEStructureAnalyzeDependencies {
  callWorker?: (
    request: ReturnType<typeof buildStaticWorkerRequest>,
    options?: { database?: any; family?: string }
  ) => Promise<StaticWorkerResponse>
}

function uniqueWarnings(response: StaticWorkerResponse, data: Record<string, unknown>) {
  const warnings: string[] = []
  if (Array.isArray(response.warnings)) {
    warnings.push(...response.warnings.map((item) => String(item)))
  }
  if (Array.isArray(data.warnings)) {
    warnings.push(...data.warnings.map((item) => String(item)))
  }
  return Array.from(new Set(warnings.filter((item) => item.trim().length > 0)))
}

export function createPEStructureAnalyzeHandler(deps: PluginToolDeps) {
  const { workspaceManager, database } = deps
  const callWorker = callStaticWorker

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = peStructureAnalyzeInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const workerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        toolVersion: TOOL_VERSION,
      })
      const workerResponse = await callWorker(workerRequest, {
        database,
        family: 'static_python.preview',
      })
      if (!workerResponse.ok || !workerResponse.data || typeof workerResponse.data !== 'object') {
        return {
          ok: false,
          errors: workerResponse.errors?.length ? workerResponse.errors : ['PE structure analysis failed.'],
          warnings: workerResponse.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
            worker_elapsed_ms: Number(workerResponse.metrics?.elapsed_ms || 0) || undefined,
          },
        }
      }

      const workerData = workerResponse.data as Record<string, unknown>
      const backendDetails =
        workerData.backend_details && typeof workerData.backend_details === 'object'
          ? (workerData.backend_details as Record<string, unknown>)
          : {}
      const backendCount = Object.keys(backendDetails).length
      const summary = PeStructureSummarySchema.parse(workerData.summary || {})
      const warnings = uniqueWarnings(workerResponse, workerData)
      const status: 'ready' | 'partial' | 'setup_required' =
        backendCount === 0
          ? 'setup_required'
          : warnings.some((item) => /unavailable|failed/i.test(item))
            ? 'partial'
            : 'ready'

      const confidenceSemantics =
        backendCount > 0
          ? buildPeStructureConfidenceSemantics({
              score: Math.min(
                0.98,
                0.38 +
                  Math.min(0.22, backendCount * 0.18) +
                  Math.min(0.16, summary.section_count * 0.02) +
                  Math.min(0.12, summary.import_dll_count * 0.02) +
                  Math.min(0.1, summary.export_count * 0.03)
              ),
              backendCount,
              sections: summary.section_count,
              imports: summary.import_function_count,
              exports: summary.export_count,
            })
          : null

      const setupActions =
        status === 'setup_required'
          ? mergeSetupActions(buildBaselinePythonSetupActions(), buildStaticAnalysisSetupActions())
          : undefined
      const requiredUserInputs =
        status === 'setup_required' ? buildStaticAnalysisRequiredUserInputs() : undefined

      let artifact
      const artifacts = []
      if (backendCount > 0 && input.persist_artifact) {
        const artifactPayload = {
          session_tag: input.session_tag || null,
          sample_id: input.sample_id,
          status,
          summary,
          headers: workerData.headers ?? {},
          entry_point: workerData.entry_point ?? {},
          sections: Array.isArray(workerData.sections) ? workerData.sections : [],
          imports: workerData.imports ?? {},
          exports: workerData.exports ?? {},
          resources: workerData.resources ?? {},
          overlay: workerData.overlay ?? {},
          backend_details: backendDetails,
          confidence_semantics: confidenceSemantics,
          warnings,
          created_at: new Date().toISOString(),
        }
        artifact = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          PE_STRUCTURE_ANALYSIS_ARTIFACT_TYPE,
          'pe_structure',
          artifactPayload,
          input.session_tag
        )
        artifacts.push(artifact)
      }

      let analysisId: string | undefined
      if (backendCount > 0 && input.register_analysis) {
        analysisId = randomUUID()
        database.insertAnalysis({
          id: analysisId,
          sample_id: input.sample_id,
          stage: 'pe_structure_analysis',
          backend: backendCount > 1 ? 'pefile+lief' : Object.keys(backendDetails)[0] || 'unknown',
          status: status === 'ready' ? 'done' : 'partial_success',
          started_at: new Date(startTime).toISOString(),
          finished_at: new Date().toISOString(),
          output_json: JSON.stringify({
            summary,
            backend_count: backendCount,
            backends: Object.keys(backendDetails),
            artifact_id: artifact?.id || null,
          }),
          metrics_json: JSON.stringify({
            section_count: summary.section_count,
            import_dll_count: summary.import_dll_count,
            export_count: summary.export_count,
            resource_count: summary.resource_count,
          }),
        })
      }

      return {
        ok: true,
        data: {
          status,
          sample_id: input.sample_id,
          summary,
          headers: workerData.headers ?? {},
          entry_point: workerData.entry_point ?? {},
          sections: Array.isArray(workerData.sections) ? workerData.sections : [],
          imports: workerData.imports ?? {},
          exports: workerData.exports ?? {},
          resources: workerData.resources ?? {},
          overlay: workerData.overlay ?? {},
          backend_details: backendDetails,
          confidence_semantics: confidenceSemantics,
          analysis_id: analysisId,
          artifact,
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        setup_actions: setupActions,
        required_user_inputs: requiredUserInputs,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
          worker_elapsed_ms: Number(workerResponse.metrics?.elapsed_ms || 0) || undefined,
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
