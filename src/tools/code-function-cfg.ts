/**
 * code.function.cfg MCP Tool
 *
 * Extract bounded function CFG exports plus optional local call-relationship previews.
 */

import { z } from 'zod'
import type { DatabaseManager } from '../database.js'
import { DecompilerWorker, getGhidraDiagnostics, normalizeGhidraError, type ControlFlowGraph } from '../decompiler-worker.js'
import { logger } from '../logger.js'
import type { ArtifactRef, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import {
  ExplanationConfidenceStateSchema,
  ExplanationSurfaceRoleSchema,
} from '../explanation-graphs.js'
import { ToolSurfaceRoleSchema } from '../tool-surface-guidance.js'
import {
  buildCFGExport,
  buildCFGSummary,
  buildGraphvizSetupActions,
  buildLocalCallGraphExport,
  buildLocalCallGraphPreview,
  detectGraphvizAvailability,
  persistGraphArtifact,
  renderGraphvizArtifact,
  type CFGExportFormat,
  type CFGRenderFormat,
  type GraphvizAvailability,
  type LocalCallGraph,
} from '../cfg-visual-exports.js'

const TOOL_NAME = 'code.function.cfg'

const ArtifactRefSchema = z.object({
  id: z.string(),
  type: z.string(),
  path: z.string(),
  sha256: z.string(),
  mime: z.string().optional(),
  metadata: z.any().optional(),
})

export const codeFunctionCFGInputSchema = z
  .object({
    sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
    address: z.string().optional().describe('Function address (hex string)'),
    symbol: z.string().optional().describe('Function symbol name'),
    timeout: z
      .number()
      .int()
      .min(1)
      .max(300)
      .optional()
      .default(30)
      .describe('Timeout in seconds for the Ghidra CFG extraction (default: 30)'),
    format: z
      .enum(['json', 'dot', 'mermaid'])
      .optional()
      .default('json')
      .describe('Primary graph export format. dot and mermaid return bounded inline previews plus persisted text artifacts.'),
    render: z
      .enum(['none', 'svg', 'png'])
      .optional()
      .default('none')
      .describe('Optional rendered artifact format. Rendered SVG/PNG is written to an artifact and never inlined.'),
    preview_max_chars: z
      .number()
      .int()
      .min(256)
      .max(12000)
      .optional()
      .default(3000)
      .describe('Maximum inline preview characters for dot or mermaid graph text.'),
    preview_max_nodes: z
      .number()
      .int()
      .min(1)
      .max(128)
      .optional()
      .default(12)
      .describe('Maximum CFG nodes surfaced in compact inline JSON previews.'),
    preview_max_edges: z
      .number()
      .int()
      .min(1)
      .max(256)
      .optional()
      .default(16)
      .describe('Maximum CFG edges surfaced in compact inline JSON previews.'),
    include_call_relationships: z
      .boolean()
      .optional()
      .default(false)
      .describe('Include a bounded local caller/callee preview around the requested function.'),
    call_relationship_depth: z
      .number()
      .int()
      .min(1)
      .max(2)
      .optional()
      .default(1)
      .describe('Depth for the bounded local call-relationship preview when include_call_relationships=true.'),
    call_relationship_limit: z
      .number()
      .int()
      .min(1)
      .max(32)
      .optional()
      .default(8)
      .describe('Maximum call-relationship edges to surface when include_call_relationships=true.'),
    persist_artifacts: z
      .boolean()
      .optional()
      .default(true)
      .describe('Persist full graph text and rendered outputs as artifacts. Recommended for artifact-first workflows.'),
    session_tag: z
      .string()
      .optional()
      .describe('Optional graph artifact session tag used to group CFG exports under one reports/graphs/<tag> path.'),
  })
  .superRefine((data, ctx) => {
    if (!data.address && !data.symbol) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['address'],
        message: 'Either address or symbol must be provided',
      })
    }
  })

export type CodeFunctionCFGInput = z.infer<typeof codeFunctionCFGInputSchema>

export const codeFunctionCFGOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready']),
      sample_id: z.string(),
      target: z.object({
        query: z.string(),
        function: z.string(),
        address: z.string(),
      }),
      format: z.enum(['json', 'dot', 'mermaid']),
      tool_surface_role: ToolSurfaceRoleSchema,
      preferred_primary_tools: z.array(z.string()),
      graph_semantics: z.object({
        surface_role: ExplanationSurfaceRoleSchema,
        confidence_state: ExplanationConfidenceStateSchema,
        omissions: z.array(z.object({ code: z.string(), reason: z.string() })).optional(),
        recommended_next_tools: z.array(z.string()),
      }),
      graph_summary: z.object({
        function: z.string(),
        address: z.string(),
        node_count: z.number().int().nonnegative(),
        edge_count: z.number().int().nonnegative(),
        block_type_counts: z.record(z.number()),
        entry_node_count: z.number().int().nonnegative(),
        exit_node_count: z.number().int().nonnegative(),
      }),
      preview: z.object({
        format: z.enum(['json', 'dot', 'mermaid']),
        inline_text: z.string().optional(),
        inline_json: z.any().optional(),
        truncated: z.boolean(),
        preview_char_count: z.number().int().nonnegative().optional(),
        preview_node_count: z.number().int().nonnegative().optional(),
        preview_edge_count: z.number().int().nonnegative().optional(),
        omitted_nodes: z.number().int().nonnegative().optional(),
        omitted_edges: z.number().int().nonnegative().optional(),
        full_output_available: z.boolean(),
      }),
      call_relationships: z
        .object({
          status: z.enum(['available', 'unavailable']),
          bounded: z.boolean(),
          depth: z.number().int().nonnegative(),
          limit: z.number().int().positive(),
          node_count: z.number().int().nonnegative(),
          edge_count: z.number().int().nonnegative(),
          truncated: z.boolean(),
          summary: z.string(),
          preview: z.any().optional(),
          artifact: ArtifactRefSchema.optional(),
        })
        .optional(),
      artifact_refs: z
        .object({
          primary_graph: ArtifactRefSchema.optional(),
          call_relationship_graph: ArtifactRefSchema.optional(),
          rendered_graph: ArtifactRefSchema.optional(),
        })
        .optional(),
      render: z.object({
        requested: z.enum(['none', 'svg', 'png']),
        status: z.enum(['not_requested', 'rendered', 'unavailable']),
        backend: z.string().nullable(),
        available: z.boolean(),
        artifact: ArtifactRefSchema.optional(),
        guidance: z.array(z.string()).optional(),
      }),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

interface CodeFunctionCFGDependencies {
  getFunctionCFG?: (
    sampleId: string,
    addressOrSymbol: string,
    timeoutMs: number
  ) => Promise<ControlFlowGraph>
  detectRendererAvailability?: () => GraphvizAvailability
  persistGraphArtifact?: (
    workspaceManager: WorkspaceManager,
    database: DatabaseManager,
    content: string | Buffer,
    options: {
      sampleId: string
      functionName: string
      functionAddress: string
      format: CFGExportFormat | 'svg' | 'png'
      scope: 'cfg' | 'call_relationships'
      sessionTag?: string | null
      renderBackend?: string | null
    }
  ) => Promise<ArtifactRef>
  renderGraphvizArtifact?: (
    workspaceManager: WorkspaceManager,
    database: DatabaseManager,
    dotText: string,
    options: {
      sampleId: string
      functionName: string
      functionAddress: string
      format: 'svg' | 'png'
      sessionTag?: string | null
    }
  ) => Promise<ArtifactRef>
}

function buildToolMetrics(startTime: number) {
  return {
    elapsed_ms: Date.now() - startTime,
    tool: TOOL_NAME,
  }
}

function buildSummary(
  graphSummary: ReturnType<typeof buildCFGSummary>,
  format: CFGExportFormat,
  callGraph?: LocalCallGraph | null
): string {
  const base = `Resolved CFG for ${graphSummary.function} at ${graphSummary.address} with ${graphSummary.node_count} node(s) and ${graphSummary.edge_count} edge(s) in ${format} format.`
  if (!callGraph) {
    return base
  }
  return `${base} Local call-relationship preview surfaced ${callGraph.nodes.length} node(s) and ${callGraph.edges.length} edge(s) with depth=${callGraph.depth} and limit=${callGraph.limit}.`
}

function buildNextActions(input: CodeFunctionCFGInput, renderStatus: 'not_requested' | 'rendered' | 'unavailable') {
  const actions = [
    'Use artifact.read on artifact_refs.primary_graph when you need the complete graph text instead of the bounded preview.',
    input.include_call_relationships
      ? 'Use the bounded call_relationships preview only for local navigation; it is not a whole-program call graph.'
      : 'Set include_call_relationships=true when you need a bounded local caller/callee view around the same function.',
    'Continue with code.function.decompile or workflow.reconstruct when you need source-like reasoning beyond graph structure.',
  ]

  if (renderStatus === 'unavailable') {
    actions.splice(
      1,
      0,
      'Install Graphviz dot if you want render=svg or render=png; text exports remain available without it.'
    )
  }

  return actions
}

function buildRenderGuidance(render: CFGRenderFormat, availability: GraphvizAvailability | null): string[] | undefined {
  if (render === 'none') {
    return undefined
  }
  if (!availability || availability.available) {
    return undefined
  }
  return [
    'Graphviz dot is unavailable, so the server returned text graph exports only.',
    availability.error ? `Renderer probe error: ${availability.error}` : 'Renderer backend was not detected.',
    'Install Graphviz to enable artifact-first SVG or PNG rendering.',
  ]
}

export const codeFunctionCFGToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Export a bounded function control-flow graph in json, dot, or mermaid format, with optional artifact-first SVG/PNG rendering. Mermaid and DOT are serializer choices over the same bounded graph semantics, not separate analysis goals. ' +
    'Use this after ghidra.analyze when you need graph structure or a report-friendly graph artifact before full reconstruction. ' +
    'Do not use it as a whole-program call graph; local caller/callee previews are bounded by depth and edge limit.' +
    '\n\nDecision guide:\n' +
    '- Use when: you need compact CFG structure, report-ready graph text, or artifact-first rendered SVG/PNG.\n' +
    '- Do not use when: you need full source-like semantics; prefer code.function.decompile or workflow.reconstruct.\n' +
    '- Typical next step: read the returned artifact_refs with artifact.read, or continue with code.function.decompile / workflow.reconstruct.\n' +
    '- Common mistake: expecting render=svg/png to inline XML or binary output into the MCP response.',
  inputSchema: codeFunctionCFGInputSchema,
  outputSchema: codeFunctionCFGOutputSchema,
}

export function createCodeFunctionCFGHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies: CodeFunctionCFGDependencies = {}
): (args: unknown) => Promise<WorkerResult> {
  const detectRendererAvailability = dependencies.detectRendererAvailability || detectGraphvizAvailability
  const persistArtifactImpl = dependencies.persistGraphArtifact || persistGraphArtifact
  const renderArtifactImpl = dependencies.renderGraphvizArtifact || renderGraphvizArtifact

  return async (args: unknown): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = codeFunctionCFGInputSchema.parse(args)
      const addressOrSymbol = input.address || input.symbol || ''

      logger.info(
        {
          sample_id: input.sample_id,
          address_or_symbol: addressOrSymbol,
          format: input.format,
          render: input.render,
          include_call_relationships: input.include_call_relationships,
        },
        'code.function.cfg tool called'
      )

      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: buildToolMetrics(startTime),
        }
      }

      const decompilerWorker = new DecompilerWorker(database, workspaceManager)
      const getFunctionCFG = dependencies.getFunctionCFG
        ? dependencies.getFunctionCFG
        : (sampleId: string, target: string, timeoutMs: number) =>
            decompilerWorker.getFunctionCFG(sampleId, target, timeoutMs)

      const timeoutMs = input.timeout * 1000
      const cfg = await getFunctionCFG(input.sample_id, addressOrSymbol, timeoutMs)
      const graphSummary = buildCFGSummary(cfg)
      const primaryExport = buildCFGExport(
        cfg,
        input.format,
        input.preview_max_chars,
        input.preview_max_nodes,
        input.preview_max_edges
      )

      const warnings: string[] = []
      const artifacts: ArtifactRef[] = []
      let primaryGraphArtifact: ArtifactRef | undefined
      if (input.persist_artifacts !== false) {
        primaryGraphArtifact = await persistArtifactImpl(workspaceManager, database, primaryExport.text, {
          sampleId: input.sample_id,
          functionName: cfg.function,
          functionAddress: cfg.address,
          format: input.format,
          scope: 'cfg',
          sessionTag: input.session_tag,
        })
        artifacts.push(primaryGraphArtifact)
      }

      let callGraph: LocalCallGraph | null = null
      let callRelationshipArtifact: ArtifactRef | undefined
      let callRelationshipData:
        | {
            status: 'available' | 'unavailable'
            bounded: boolean
            depth: number
            limit: number
            node_count: number
            edge_count: number
            truncated: boolean
            summary: string
            preview?: unknown
            artifact?: ArtifactRef
          }
        | undefined

      if (input.include_call_relationships) {
        const functions = typeof database.findFunctions === 'function' ? database.findFunctions(input.sample_id) : []
        callGraph = buildLocalCallGraphPreview(functions, cfg, input.call_relationship_depth, input.call_relationship_limit)
        const callExport = buildLocalCallGraphExport(callGraph, input.format, input.preview_max_chars)

        if (input.persist_artifacts !== false) {
          callRelationshipArtifact = await persistArtifactImpl(
            workspaceManager,
            database,
            callExport.text,
            {
              sampleId: input.sample_id,
              functionName: cfg.function,
              functionAddress: cfg.address,
              format: input.format,
              scope: 'call_relationships',
              sessionTag: input.session_tag,
            }
          )
          artifacts.push(callRelationshipArtifact)
        }

        callRelationshipData = {
          status: 'available',
          bounded: true,
          depth: callGraph.depth,
          limit: callGraph.limit,
          node_count: callGraph.nodes.length,
          edge_count: callGraph.edges.length,
          truncated: callExport.preview.truncated,
          summary: callGraph.note,
          preview: callExport.preview.inline_text
            ? {
                format: callExport.format,
                inline_text: callExport.preview.inline_text,
                truncated: callExport.preview.truncated,
                preview_char_count: callExport.preview.preview_char_count,
              }
            : {
                format: callExport.format,
                inline_json: callExport.preview.inline_json,
                truncated: callExport.preview.truncated,
                preview_node_count: callExport.preview.preview_node_count,
                preview_edge_count: callExport.preview.preview_edge_count,
                omitted_nodes: callExport.preview.omitted_nodes,
                omitted_edges: callExport.preview.omitted_edges,
              },
          ...(callRelationshipArtifact ? { artifact: callRelationshipArtifact } : {}),
        }
      }

      let renderArtifact: ArtifactRef | undefined
      let renderStatus: 'not_requested' | 'rendered' | 'unavailable' = 'not_requested'
      let rendererAvailability: GraphvizAvailability | null = null
      let setupActions: unknown[] | undefined
      let renderGuidance: string[] | undefined

      if (input.render !== 'none') {
        rendererAvailability = detectRendererAvailability()
        if (!rendererAvailability.available) {
          renderStatus = 'unavailable'
          warnings.push(
            `Graphviz renderer is unavailable; returning ${input.format} graph export without ${input.render} render artifact.`
          )
          setupActions = buildGraphvizSetupActions()
          renderGuidance = buildRenderGuidance(input.render, rendererAvailability)
        } else {
          try {
            const dotText = buildCFGExport(
              cfg,
              'dot',
              input.preview_max_chars,
              input.preview_max_nodes,
              input.preview_max_edges
            ).text
            renderArtifact = await renderArtifactImpl(workspaceManager, database, dotText, {
              sampleId: input.sample_id,
              functionName: cfg.function,
              functionAddress: cfg.address,
              format: input.render,
              sessionTag: input.session_tag,
            })
            artifacts.push(renderArtifact)
            renderStatus = 'rendered'
          } catch (renderError) {
            renderStatus = 'unavailable'
            warnings.push(
              `Graphviz render failed for ${input.render}; returned text graph export only: ${
                renderError instanceof Error ? renderError.message : String(renderError)
              }`
            )
            setupActions = buildGraphvizSetupActions()
            renderGuidance = [
              'Graphviz rendering failed after CFG export succeeded, so only text graph artifacts were returned.',
              'Retry after validating the dot renderer installation and permissions in the current environment.',
            ]
          }
        }
      }

      const data = {
        status: 'ready' as const,
        sample_id: input.sample_id,
        target: {
          query: addressOrSymbol,
          function: cfg.function,
          address: cfg.address,
        },
        format: input.format,
        tool_surface_role: 'primary' as const,
        preferred_primary_tools: [],
        graph_semantics: {
          surface_role: 'local_navigation_aid' as const,
          confidence_state: 'observed' as const,
          omissions: [
            {
              code: 'bounded_preview',
              reason:
                'Inline previews stay bounded. Use artifact.read on the returned graph artifacts for the full serializer output.',
            },
            ...(input.include_call_relationships
              ? [
                  {
                    code: 'local_call_relationships_only',
                    reason:
                      'Caller/callee previews are intentionally local and do not claim whole-program coverage.',
                  },
                ]
              : []),
          ],
          recommended_next_tools: ['artifact.read', 'code.function.decompile', 'workflow.reconstruct'],
        },
        graph_summary: graphSummary,
        preview: primaryExport.preview,
        ...(callRelationshipData ? { call_relationships: callRelationshipData } : {}),
        artifact_refs:
          primaryGraphArtifact || callRelationshipArtifact || renderArtifact
            ? {
                ...(primaryGraphArtifact ? { primary_graph: primaryGraphArtifact } : {}),
                ...(callRelationshipArtifact
                  ? { call_relationship_graph: callRelationshipArtifact }
                  : {}),
                ...(renderArtifact ? { rendered_graph: renderArtifact } : {}),
              }
            : undefined,
        render: {
          requested: input.render,
          status: renderStatus,
          backend: rendererAvailability?.backend || null,
          available: rendererAvailability?.available || input.render === 'none',
          ...(renderArtifact ? { artifact: renderArtifact } : {}),
          ...((renderGuidance || buildRenderGuidance(input.render, rendererAvailability))
            ? { guidance: renderGuidance || buildRenderGuidance(input.render, rendererAvailability) }
            : {}),
        },
        summary: buildSummary(graphSummary, input.format, callGraph),
        recommended_next_tools: ['artifact.read', 'code.function.decompile', 'workflow.reconstruct'],
        next_actions: buildNextActions(input, renderStatus),
      }

      logger.info(
        {
          sample_id: input.sample_id,
          function: cfg.function,
          node_count: cfg.nodes.length,
          edge_count: cfg.edges.length,
          format: input.format,
          render_status: renderStatus,
        },
        'Function CFG extracted successfully'
      )

      return {
        ok: true,
        data,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
        setup_actions: setupActions,
        metrics: buildToolMetrics(startTime),
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      const diagnostics = getGhidraDiagnostics(error)
      const normalizedError = normalizeGhidraError(error, TOOL_NAME)

      logger.error(
        {
          error: errorMessage,
          ghidra_diagnostics: diagnostics,
          normalized_error: normalizedError,
        },
        'code.function.cfg tool failed'
      )

      return {
        ok: false,
        errors: [errorMessage],
        warnings: normalizedError.remediation_hints,
        metrics: buildToolMetrics(startTime),
      }
    }
  }
}
