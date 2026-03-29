import { randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import {
  buildCapabilityConfidenceSemantics,
  ConfidenceSemanticsSchema,
} from '../confidence-semantics.js'
import {
  buildStaticAnalysisRequiredUserInputs,
  buildStaticAnalysisSetupActions,
} from '../setup-guidance.js'
import {
  persistStaticAnalysisJsonArtifact,
  STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
} from '../static-analysis-artifacts.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker,
  type StaticWorkerResponse,
} from './static-worker-client.js'

const TOOL_NAME = 'static.capability.triage'
const TOOL_VERSION = '0.2.0'

const CapabilityFindingSchema = z.object({
  rule_id: z.string(),
  name: z.string(),
  namespace: z.string().nullable().optional(),
  scopes: z.array(z.string()),
  group: z.string(),
  confidence: z.number().min(0).max(1),
  match_count: z.number().int().nonnegative(),
  evidence_summary: z.string(),
})

const CapabilityBackendSchema = z.object({
  available: z.boolean(),
  engine: z.string().nullable().optional(),
  source: z.string().nullable().optional(),
  version: z.string().nullable().optional(),
  command: z.array(z.string()).optional(),
  error: z.string().nullable().optional(),
  rules: z
    .object({
      available: z.boolean(),
      path: z.string().nullable().optional(),
      source: z.string().nullable().optional(),
      error: z.string().nullable().optional(),
    })
    .optional(),
})

export const staticCapabilityTriageInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  rules_path: z
    .string()
    .optional()
    .describe('Optional explicit capa rules directory or rules file path'),
  timeout: z
    .number()
    .int()
    .min(10)
    .max(600)
    .default(300)
    .describe('Maximum capa execution time in seconds'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist normalized capability findings into reports/static_analysis'),
  register_analysis: z
    .boolean()
    .default(true)
    .describe('Insert a completed analysis row for capability triage runs'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag for persisted static-analysis artifacts'),
})

export const StaticCapabilityTriageDataSchema = z.object({
  status: z.enum(['ready', 'setup_required']),
  sample_id: z.string(),
  capability_count: z.number().int().nonnegative(),
  behavior_namespaces: z.array(z.string()),
  capability_groups: z.record(z.number().int().nonnegative()),
  capabilities: z.array(CapabilityFindingSchema),
  summary: z.string(),
  backend: CapabilityBackendSchema,
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
  raw_backend: z.any().nullable().optional(),
})

export const staticCapabilityTriageOutputSchema = z.object({
  ok: z.boolean(),
  data: StaticCapabilityTriageDataSchema.optional(),
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

export const staticCapabilityTriageToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Analyze executable behavior capabilities with a capa-style backend and return normalized capability groups, evidence summaries, and setup guidance.',
  inputSchema: staticCapabilityTriageInputSchema,
  outputSchema: staticCapabilityTriageOutputSchema,
}

interface StaticCapabilityTriageDependencies {
  callWorker?: (
    request: ReturnType<typeof buildStaticWorkerRequest>,
    options?: { database?: DatabaseManager; family?: string }
  ) => Promise<StaticWorkerResponse>
}

function normalizeBackend(rawBackend: unknown) {
  if (!rawBackend || typeof rawBackend !== 'object') {
    return {
      available: false,
      engine: null,
      source: null,
      version: null,
      command: undefined,
      error: null,
      rules: undefined,
    }
  }

  const raw = rawBackend as Record<string, unknown>
  const rulesValue =
    raw.rules && typeof raw.rules === 'object' ? (raw.rules as Record<string, unknown>) : undefined

  return {
    available: Boolean(raw.available),
    engine: typeof raw.engine === 'string' ? raw.engine : null,
    source: typeof raw.source === 'string' ? raw.source : null,
    version: typeof raw.version === 'string' ? raw.version : null,
    command: Array.isArray(raw.command) ? raw.command.map((item) => String(item)) : undefined,
    error: typeof raw.error === 'string' ? raw.error : null,
    rules: rulesValue
      ? {
          available: Boolean(rulesValue.available),
          path: typeof rulesValue.path === 'string' ? rulesValue.path : null,
          source: typeof rulesValue.source === 'string' ? rulesValue.source : null,
          error: typeof rulesValue.error === 'string' ? rulesValue.error : null,
        }
      : undefined,
  }
}

function collectWarnings(response: StaticWorkerResponse, data: Record<string, unknown>): string[] {
  const warnings: string[] = []
  if (Array.isArray(response.warnings)) {
    warnings.push(...response.warnings.map((item) => String(item)))
  }
  if (Array.isArray(data.warnings)) {
    warnings.push(...data.warnings.map((item) => String(item)))
  }
  return Array.from(new Set(warnings.filter((item) => item.trim().length > 0)))
}

export function createStaticCapabilityTriageHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies: StaticCapabilityTriageDependencies = {}
) {
  const callWorker = dependencies.callWorker || callStaticWorker

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = staticCapabilityTriageInputSchema.parse(args)
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
        args: {
          rules_path: input.rules_path,
          timeout: input.timeout,
        },
        toolVersion: TOOL_VERSION,
      })
      const workerResponse = await callWorker(workerRequest, {
        database,
        family: 'static_python.preview',
      })
      if (!workerResponse.ok || !workerResponse.data || typeof workerResponse.data !== 'object') {
        return {
          ok: false,
          errors: workerResponse.errors?.length ? workerResponse.errors : ['Static capability triage failed.'],
          warnings: workerResponse.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
            worker_elapsed_ms: Number(workerResponse.metrics?.elapsed_ms || 0) || undefined,
          },
        }
      }

      const workerData = workerResponse.data as Record<string, unknown>
      const status = workerData.status === 'setup_required' ? 'setup_required' : 'ready'
      const capabilities = Array.isArray(workerData.capabilities)
        ? workerData.capabilities.map((item) => CapabilityFindingSchema.parse(item))
        : []
      const behaviorNamespaces = Array.isArray(workerData.behavior_namespaces)
        ? workerData.behavior_namespaces.map((item) => String(item))
        : []
      const capabilityGroups =
        workerData.capability_groups && typeof workerData.capability_groups === 'object'
          ? Object.fromEntries(
              Object.entries(workerData.capability_groups as Record<string, unknown>).map(([key, value]) => [
                key,
                Number(value) || 0,
              ])
            )
          : {}
      const backend = normalizeBackend(workerData.backend)
      const confidenceScore =
        status === 'ready'
          ? Math.min(
              0.97,
              0.28 +
                Math.min(0.45, capabilities.length * 0.04) +
                Math.min(0.18, Object.keys(capabilityGroups).length * 0.05)
            )
          : 0
      const confidenceSemantics =
        status === 'ready'
          ? buildCapabilityConfidenceSemantics({
              score: confidenceScore,
              findings: capabilities.length,
              groups: Object.keys(capabilityGroups),
              rulesSource: backend.rules?.source || backend.source || null,
            })
          : null
      const warnings = collectWarnings(workerResponse, workerData)
      const setupActions =
        status === 'setup_required' ? buildStaticAnalysisSetupActions() : undefined
      const requiredUserInputs =
        status === 'setup_required' ? buildStaticAnalysisRequiredUserInputs() : undefined

      let artifact
      const artifacts = []
      if (status === 'ready' && input.persist_artifact) {
        const artifactPayload = {
          session_tag: input.session_tag || null,
          sample_id: input.sample_id,
          status,
          capability_count: capabilities.length,
          behavior_namespaces: behaviorNamespaces,
          capability_groups: capabilityGroups,
          capabilities,
          summary:
            typeof workerData.summary === 'string'
              ? workerData.summary
              : `Recovered ${capabilities.length} static capability findings.`,
          backend,
          confidence_semantics: confidenceSemantics,
          raw_backend: workerData.raw_backend ?? null,
          created_at: new Date().toISOString(),
        }
        artifact = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
          'capabilities',
          artifactPayload,
          input.session_tag
        )
        artifacts.push(artifact)
      }

      let analysisId: string | undefined
      if (status === 'ready' && input.register_analysis) {
        analysisId = randomUUID()
        database.insertAnalysis({
          id: analysisId,
          sample_id: input.sample_id,
          stage: 'static_capability_triage',
          backend: 'capa',
          status: 'done',
          started_at: new Date(startTime).toISOString(),
          finished_at: new Date().toISOString(),
          output_json: JSON.stringify({
            capability_count: capabilities.length,
            behavior_namespaces: behaviorNamespaces,
            capability_groups: capabilityGroups,
            artifact_id: artifact?.id || null,
          }),
          metrics_json: JSON.stringify({
            capability_count: capabilities.length,
            group_count: Object.keys(capabilityGroups).length,
          }),
        })
      }

      return {
        ok: true,
        data: {
          status,
          sample_id: input.sample_id,
          capability_count: capabilities.length,
          behavior_namespaces: behaviorNamespaces,
          capability_groups: capabilityGroups,
          capabilities,
          summary:
            typeof workerData.summary === 'string'
              ? workerData.summary
              : `Recovered ${capabilities.length} static capability findings.`,
          backend,
          confidence_semantics: confidenceSemantics,
          analysis_id: analysisId,
          artifact,
          raw_backend: workerData.raw_backend ?? null,
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
