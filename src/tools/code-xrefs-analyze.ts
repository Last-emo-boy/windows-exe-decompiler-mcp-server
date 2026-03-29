import { z } from 'zod'
import type { ToolDefinition, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { generateCacheKey } from '../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import {
  DecompilerWorker,
  getGhidraDiagnostics,
  normalizeGhidraError,
  type CrossReferenceAnalysis,
} from '../decompiler-worker.js'
import {
  XREF_ANALYSIS_ARTIFACT_TYPE,
  persistStringXrefJsonArtifact,
} from '../string-xref-artifacts.js'

const TOOL_NAME = 'code.xrefs.analyze'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000

export const codeXrefsAnalyzeInputSchema = z
  .object({
    sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
    target_type: z
      .enum(['function', 'api', 'string', 'data'])
      .describe('Cross-reference target type'),
    address: z.string().optional().describe('Function address when target_type=function'),
    symbol: z.string().optional().describe('Function symbol when target_type=function'),
    query: z.string().optional().describe('API name, string substring, or generic query value'),
    data_address: z.string().optional().describe('Data address when target_type=data'),
    depth: z
      .number()
      .int()
      .min(1)
      .max(3)
      .optional()
      .default(1)
      .describe('Traversal depth for function caller/callee expansion'),
    limit: z
      .number()
      .int()
      .min(1)
      .max(100)
      .optional()
      .default(20)
      .describe('Maximum inbound or outbound nodes retained in the result'),
    timeout: z
      .number()
      .int()
      .min(5)
      .max(300)
      .optional()
      .default(30)
      .describe('Timeout in seconds for Ghidra-backed cross-reference analysis'),
    force_refresh: z
      .boolean()
      .optional()
      .default(false)
      .describe('Bypass cache lookup and recompute from the current Ghidra project state'),
    persist_artifact: z
      .boolean()
      .optional()
      .default(true)
      .describe('Persist the normalized cross-reference snapshot as a JSON artifact'),
    session_tag: z
      .string()
      .optional()
      .describe('Optional session tag used when persisting cross-reference artifacts'),
  })
  .superRefine((data, ctx) => {
    if (data.target_type === 'function' && !data.address && !data.symbol) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['address'],
        message: 'Either address or symbol must be provided when target_type=function',
      })
    }

    if ((data.target_type === 'api' || data.target_type === 'string') && !data.query) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['query'],
        message: 'query is required when target_type=api or target_type=string',
      })
    }

    if (data.target_type === 'data' && !data.data_address && !data.query) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['data_address'],
        message: 'data_address or query is required when target_type=data',
      })
    }
  })

export type CodeXrefsAnalyzeInput = z.infer<typeof codeXrefsAnalyzeInputSchema>

export const codeXrefsAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      sample_id: z.string(),
      target_type: z.enum(['function', 'api', 'string', 'data']),
      target: z.object({
        query: z.string(),
        resolved_address: z.string().optional(),
        resolved_name: z.string().optional(),
      }),
      inbound: z.array(z.any()),
      outbound: z.array(z.any()),
      direct_xrefs: z.array(z.any()).optional(),
      truncated: z.boolean(),
      limits: z.object({
        depth: z.number().int(),
        limit: z.number().int(),
      }),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
      artifact: z.any().optional(),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
      cached: z.boolean().optional(),
      cache_key: z.string().optional(),
      cache_tier: z.string().optional(),
      cache_created_at: z.string().optional(),
      cache_expires_at: z.string().optional(),
      cache_hit_at: z.string().optional(),
    })
    .optional(),
})

export const codeXrefsAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Analyze bounded cross references for function, API, string, or data targets. ' +
    'Use this when you need indicator-to-function navigation before full reconstruction. ' +
    'Do not use it as a replacement for source-like export; continue with workflow.reconstruct or code.function.decompile after narrowing the target set.',
  inputSchema: codeXrefsAnalyzeInputSchema,
  outputSchema: codeXrefsAnalyzeOutputSchema,
}

interface CodeXrefsAnalyzeDependencies {
  analyzeCrossReferences?: (
    sampleId: string,
    options: {
      targetType: 'function' | 'api' | 'string' | 'data'
      query: string
      depth?: number
      limit?: number
      timeout?: number
    }
  ) => Promise<CrossReferenceAnalysis>
}

function resolveTargetQuery(input: CodeXrefsAnalyzeInput): string {
  if (input.target_type === 'function') {
    return input.address || input.symbol || ''
  }
  if (input.target_type === 'data') {
    return input.data_address || input.query || ''
  }
  return input.query || ''
}

function buildAnalysisMarker(database: DatabaseManager, sampleId: string): string {
  const latest = database
    .findAnalysesBySample(sampleId)
    .find((analysis) => analysis.backend === 'ghidra')

  if (!latest) {
    return 'no_ghidra_analysis'
  }

  return [
    latest.id,
    latest.status,
    latest.finished_at || latest.started_at || 'unknown',
  ].join(':')
}

function buildSummary(result: CrossReferenceAnalysis): string {
  const inboundCount = result.inbound.length
  const outboundCount = result.outbound.length
  const targetLabel = result.target.resolved_name || result.target.resolved_address || result.target.query

  if (result.target_type === 'function') {
    return `Resolved function target ${targetLabel} with ${inboundCount} inbound and ${outboundCount} outbound relationship(s).`
  }

  return `Resolved ${result.target_type} target ${targetLabel} with ${inboundCount} referencing function(s).`
}

function buildSetupRequiredData(input: CodeXrefsAnalyzeInput, query: string, message: string) {
  return {
    status: 'setup_required' as const,
    sample_id: input.sample_id,
    target_type: input.target_type,
    target: {
      query,
    },
    inbound: [],
    outbound: [],
    direct_xrefs: [],
    truncated: false,
    limits: {
      depth: input.depth,
      limit: input.limit,
    },
    summary: message,
    recommended_next_tools: ['ghidra.analyze', 'task.status'],
    next_actions: [
      'Run ghidra.analyze and wait until function_index readiness is available before retrying code.xrefs.analyze.',
      'Use task.status if ghidra.analyze returns a queued or running job.',
    ],
  }
}

function buildReadyData(
  input: CodeXrefsAnalyzeInput,
  result: CrossReferenceAnalysis,
  artifact?: ArtifactRef
) {
  return {
    status: 'ready' as const,
    sample_id: input.sample_id,
    target_type: result.target_type,
    target: {
      query: result.target.query,
      resolved_address: result.target.resolved_address,
      resolved_name: result.target.resolved_name,
    },
    inbound: result.inbound,
    outbound: result.outbound,
    direct_xrefs: result.direct_xrefs,
    truncated: result.truncated,
    limits: result.limits,
    summary: buildSummary(result),
    recommended_next_tools:
      result.target_type === 'function'
        ? ['code.function.decompile', 'analysis.context.link', 'workflow.reconstruct']
        : ['analysis.context.link', 'code.function.decompile', 'workflow.reconstruct'],
    next_actions:
      result.target_type === 'function'
        ? [
            'Use code.function.decompile on the resolved function when you need pseudocode and direct xrefs.',
            'Use workflow.reconstruct when the narrowed function set is ready for deeper reverse engineering.',
          ]
        : [
            'Use analysis.context.link if you want compact function-context summaries correlated from strings and xrefs.',
            'Use code.function.decompile on the highest-signal returned function when you need pseudocode.',
          ],
    artifact,
  }
}

function isPrerequisiteError(message: string): boolean {
  const normalized = message.toLowerCase()
  return (
    normalized.includes('please run ghidra.analyze first') ||
    normalized.includes('function index readiness') ||
    normalized.includes('ghidra is not properly configured') ||
    normalized.includes('ghidra function_index is not ready') ||
    normalized.includes('ghidra function index is not ready')
  )
}

export function createCodeXrefsAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies: CodeXrefsAnalyzeDependencies = {}
): (args: unknown) => Promise<WorkerResult> {
  return async (args: unknown): Promise<WorkerResult> => {
    const input = codeXrefsAnalyzeInputSchema.parse(args)
    const startTime = Date.now()
    const query = resolveTargetQuery(input)

    try {
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

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          target_type: input.target_type,
          query,
          depth: input.depth,
          limit: input.limit,
          analysis_marker: buildAnalysisMarker(database, input.sample_id),
        },
      })

      if (!input.force_refresh) {
        const cachedLookup = await lookupCachedResult(cacheManager, cacheKey)
        if (cachedLookup) {
          return {
            ok: true,
            data: cachedLookup.data,
            warnings: ['Result from cache', formatCacheWarning(cachedLookup.metadata)],
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
              cached: true,
              cache_key: cachedLookup.metadata.key,
              cache_tier: cachedLookup.metadata.tier,
              cache_created_at: cachedLookup.metadata.createdAt,
              cache_expires_at: cachedLookup.metadata.expiresAt,
              cache_hit_at: cachedLookup.metadata.fetchedAt,
            },
          }
        }
      }

      const decompilerWorker = new DecompilerWorker(database, workspaceManager)
      const analyzeCrossReferences =
        dependencies.analyzeCrossReferences ||
        ((sampleId: string, options: Parameters<DecompilerWorker['analyzeCrossReferences']>[1]) =>
          decompilerWorker.analyzeCrossReferences(sampleId, options))

      let result: CrossReferenceAnalysis
      try {
        result = await analyzeCrossReferences(input.sample_id, {
          targetType: input.target_type,
          query,
          depth: input.depth,
          limit: input.limit,
          timeout: input.timeout * 1000,
        })
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error)
        if (isPrerequisiteError(errorMessage)) {
          return {
            ok: true,
            data: buildSetupRequiredData(input, query, errorMessage),
            warnings: [errorMessage],
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
            },
          }
        }
        throw error
      }

      let artifact: ArtifactRef | undefined
      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact !== false) {
        artifact = await persistStringXrefJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          XREF_ANALYSIS_ARTIFACT_TYPE,
          'xrefs',
          {
            sample_id: input.sample_id,
            session_tag: input.session_tag || null,
            created_at: new Date().toISOString(),
            target_type: result.target_type,
            target: result.target,
            data: result,
          },
          input.session_tag
        )
        artifacts.push(artifact)
      }

      const outputData = buildReadyData(input, result, artifact)
      await cacheManager.setCachedResult(cacheKey, outputData, CACHE_TTL_MS, sample.sha256)

      return {
        ok: true,
        data: outputData,
        artifacts,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      const diagnostics = getGhidraDiagnostics(error)
      const normalizedError = normalizeGhidraError(error, TOOL_NAME)
      return {
        ok: false,
        errors: [message],
        warnings: normalizedError.remediation_hints,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
          ...(diagnostics ? { ghidra_stage: normalizedError.stage || null } : {}),
        },
      }
    }
  }
}
