import fs from 'fs/promises'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { ArtifactRef } from './types.js'
import type { WorkspaceManager } from './workspace-manager.js'
import type { DatabaseManager } from './database.js'

export const EXPLANATION_GRAPH_TYPE_VALUES = [
  'call_graph',
  'data_flow',
  'crypto_flow',
  'runtime_stage',
] as const

export const EXPLANATION_SURFACE_ROLE_VALUES = [
  'explanation_artifact',
  'local_navigation_aid',
  'render_export_helper',
  'runtime_stage_view',
] as const

export const EXPLANATION_CONFIDENCE_STATE_VALUES = ['observed', 'correlated', 'inferred'] as const

export const EXPLANATION_SERIALIZER_VALUES = ['json', 'dot', 'mermaid', 'svg', 'png'] as const

export const ANALYSIS_EXPLANATION_GRAPH_ARTIFACT_TYPE = 'analysis_explanation_graph'

export const ExplanationGraphTypeSchema = z.enum(EXPLANATION_GRAPH_TYPE_VALUES)
export const ExplanationSurfaceRoleSchema = z.enum(EXPLANATION_SURFACE_ROLE_VALUES)
export const ExplanationConfidenceStateSchema = z.enum(EXPLANATION_CONFIDENCE_STATE_VALUES)
export const ExplanationSerializerSchema = z.enum(EXPLANATION_SERIALIZER_VALUES)

export const ExplanationArtifactRefSchema = z.object({
  id: z.string(),
  type: z.string(),
  path: z.string(),
  sha256: z.string(),
  mime: z.string().optional(),
  metadata: z.record(z.any()).optional(),
})

export const ExplanationGraphProvenanceSchema = z.object({
  kind: z.enum(['artifact', 'stage', 'heuristic', 'selection']),
  label: z.string(),
  detail: z.string().optional(),
  artifact_ref: ExplanationArtifactRefSchema.optional(),
})

export const ExplanationGraphOmissionSchema = z.object({
  code: z.string(),
  reason: z.string(),
})

export const ExplanationGraphNodeSchema = z.object({
  id: z.string(),
  label: z.string(),
  kind: z.string(),
  confidence_state: ExplanationConfidenceStateSchema,
})

export const ExplanationGraphEdgeSchema = z.object({
  source: z.string(),
  target: z.string(),
  relation: z.string(),
  label: z.string().optional(),
  confidence_state: ExplanationConfidenceStateSchema,
})

export const ExplanationGraphDigestSchema = z.object({
  graph_type: ExplanationGraphTypeSchema,
  surface_role: ExplanationSurfaceRoleSchema,
  title: z.string(),
  semantic_summary: z.string(),
  confidence_state: ExplanationConfidenceStateSchema,
  confidence_states_present: z.array(ExplanationConfidenceStateSchema),
  confidence_score: z.number().min(0).max(1).optional(),
  node_count: z.number().int().nonnegative(),
  edge_count: z.number().int().nonnegative(),
  bounded: z.boolean(),
  available_serializers: z.array(ExplanationSerializerSchema),
  provenance: z.array(ExplanationGraphProvenanceSchema),
  omissions: z.array(ExplanationGraphOmissionSchema).optional(),
  recommended_next_tools: z.array(z.string()),
  artifact_ref: ExplanationArtifactRefSchema.optional(),
})

export const ExplanationGraphArtifactSchema = ExplanationGraphDigestSchema.extend({
  schema_version: z.literal(1),
  sample_id: z.string(),
  created_at: z.string(),
  nodes: z.array(ExplanationGraphNodeSchema),
  edges: z.array(ExplanationGraphEdgeSchema),
  serializers: z
    .object({
      json: z.boolean().default(true),
      dot: z.string().optional(),
      mermaid: z.string().optional(),
      svg_artifact: ExplanationArtifactRefSchema.optional(),
      png_artifact: ExplanationArtifactRefSchema.optional(),
    })
    .default({ json: true }),
})

export type ExplanationGraphDigest = z.infer<typeof ExplanationGraphDigestSchema>
export type ExplanationGraphArtifact = z.infer<typeof ExplanationGraphArtifactSchema>

function sanitizeSegment(value: string | undefined, fallback: string) {
  const normalized = (value || fallback)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return normalized.length > 0 ? normalized.slice(0, 64) : fallback
}

function artifactRefFromParts(input: {
  id: string
  path: string
  sha256: string
  mime?: string
  metadata?: Record<string, unknown>
}): ArtifactRef {
  return {
    id: input.id,
    type: ANALYSIS_EXPLANATION_GRAPH_ARTIFACT_TYPE,
    path: input.path,
    sha256: input.sha256,
    ...(input.mime ? { mime: input.mime } : {}),
    ...(input.metadata ? { metadata: input.metadata } : {}),
  }
}

export function buildExplanationGraphArtifactMetadata(
  graph: Pick<
    ExplanationGraphDigest,
    | 'graph_type'
    | 'surface_role'
    | 'confidence_state'
    | 'confidence_states_present'
    | 'recommended_next_tools'
    | 'node_count'
    | 'edge_count'
    | 'bounded'
  >
) {
  return {
    artifact_family: 'explanation_graphs',
    graph_type: graph.graph_type,
    surface_role: graph.surface_role,
    confidence_state: graph.confidence_state,
    confidence_states_present: graph.confidence_states_present,
    recommended_next_tools: graph.recommended_next_tools,
    node_count: graph.node_count,
    edge_count: graph.edge_count,
    bounded: graph.bounded,
  }
}

export function attachExplanationArtifactRef(
  graph: ExplanationGraphDigest,
  artifactRef: ArtifactRef
): ExplanationGraphDigest {
  return {
    ...graph,
    artifact_ref: ExplanationArtifactRefSchema.parse(artifactRef),
  }
}

export function buildRuntimeStageExplanationGraph(input: {
  sample_id: string
  completed_stages: string[]
  deferred_requirements?: string[]
  recoverable_stages?: Array<{ stage: string; reason: string }>
  recommended_next_tools?: string[]
  stage_plan?: string[]
  coverage_gaps?: Array<{ domain: string; status: string; reason: string }>
}): ExplanationGraphArtifact {
  const stagePlan = input.stage_plan?.length
    ? input.stage_plan
    : ['fast_profile', 'enrich_static', 'function_map', 'reconstruct', 'summarize']
  const completed = new Set(input.completed_stages)
  const recoverable = new Map((input.recoverable_stages || []).map((item) => [item.stage, item.reason]))
  const deferredDomains = new Map(
    (input.coverage_gaps || [])
      .filter((item) => item.status === 'queued' || item.status === 'missing' || item.status === 'degraded')
      .map((item) => [item.domain, item.reason])
  )

  const nodes = stagePlan.map((stage) => {
    const confidence_state: z.infer<typeof ExplanationConfidenceStateSchema> = completed.has(stage)
      ? 'observed'
      : recoverable.has(stage)
        ? 'correlated'
        : 'inferred'
    const label =
      completed.has(stage)
        ? `${stage} (done)`
        : recoverable.has(stage)
          ? `${stage} (recoverable)`
          : deferredDomains.has(stage)
            ? `${stage} (deferred)`
            : `${stage} (not-yet-run)`
    return {
      id: stage,
      label,
      kind: 'analysis_stage',
      confidence_state,
    }
  })

  const edges = stagePlan.slice(0, -1).map((stage, index) => ({
    source: stage,
    target: stagePlan[index + 1],
    relation: 'promotes_to',
    confidence_state: completed.has(stage) ? 'observed' : 'correlated',
  }))

  const omissions = [
    ...(input.deferred_requirements || []).map((reason) => ({
      code: 'deferred_requirement',
      reason,
    })),
    ...(input.coverage_gaps || [])
      .filter((item) => item.status === 'missing' || item.status === 'degraded')
      .slice(0, 8)
      .map((item) => ({
        code: `${item.status}:${item.domain}`,
        reason: item.reason,
      })),
  ]

  return ExplanationGraphArtifactSchema.parse({
    schema_version: 1,
    sample_id: input.sample_id,
    created_at: new Date().toISOString(),
    graph_type: 'runtime_stage',
    surface_role: 'runtime_stage_view',
    title: 'Staged Analysis Runtime View',
    semantic_summary:
      'Bounded staged-runtime explanation graph showing which analysis stages are completed, recoverable, deferred, or still absent.',
    confidence_state: 'observed',
    confidence_states_present: ['observed', ...(recoverable.size > 0 || deferredDomains.size > 0 ? ['correlated', 'inferred'] : [])],
    node_count: nodes.length,
    edge_count: edges.length,
    bounded: true,
    available_serializers: ['json'],
    provenance: [
      {
        kind: 'stage',
        label: 'persisted_run_state',
        detail: 'Derived from persisted run/stage status rather than from a renderer-specific export.',
      },
    ],
    omissions: omissions.length > 0 ? omissions : undefined,
    recommended_next_tools: input.recommended_next_tools || ['workflow.analyze.status', 'workflow.analyze.promote'],
    nodes,
    edges,
    serializers: {
      json: true,
    },
  })
}

export async function persistExplanationGraphArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  graph: ExplanationGraphArtifact,
  options?: {
    sessionTag?: string | null
    filePrefix?: string
  }
): Promise<ArtifactRef> {
  const workspace = await workspaceManager.createWorkspace(sampleId)
  const sessionSegment = sanitizeSegment(options?.sessionTag || undefined, 'default')
  const graphSegment = sanitizeSegment(graph.graph_type, 'graph')
  const reportDir = path.join(workspace.reports, 'explanations', sessionSegment, graphSegment)
  await fs.mkdir(reportDir, { recursive: true })

  const filePrefix = sanitizeSegment(options?.filePrefix || graph.graph_type, 'graph')
  const fileName = `${filePrefix}_${Date.now()}.json`
  const absolutePath = path.join(reportDir, fileName)
  const serialized = JSON.stringify(graph, null, 2)
  await fs.writeFile(absolutePath, serialized, 'utf8')

  const sha256 = createHash('sha256').update(serialized).digest('hex')
  const relativePath = path.relative(workspace.root, absolutePath).replace(/\\/g, '/')
  const artifactId = randomUUID()
  const createdAt = new Date().toISOString()

  database.insertArtifact({
    id: artifactId,
    sample_id: sampleId,
    type: ANALYSIS_EXPLANATION_GRAPH_ARTIFACT_TYPE,
    path: relativePath,
    sha256,
    mime: 'application/json',
    created_at: createdAt,
  })

  return artifactRefFromParts({
    id: artifactId,
    path: relativePath,
    sha256,
    mime: 'application/json',
    metadata: {
      session_tag: options?.sessionTag || null,
      ...buildExplanationGraphArtifactMetadata(graph),
    },
  })
}
