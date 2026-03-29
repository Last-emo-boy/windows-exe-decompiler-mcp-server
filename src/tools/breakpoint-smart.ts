import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { createCryptoIdentifyHandler } from './crypto-identify.js'
import { createDynamicDependenciesHandler } from './dynamic-dependencies.js'
import { loadDynamicTraceEvidence, type DynamicEvidenceScope, type DynamicTraceSummary } from '../dynamic-trace.js'
import {
  BreakpointCandidateSchema,
  buildBreakpointCandidates,
  summarizeBreakpointCandidates,
  type CryptoFinding,
} from '../crypto-breakpoint-analysis.js'
import {
  loadCryptoPlanningArtifactSelection,
  persistCryptoPlanningJsonArtifact,
  CRYPTO_IDENTIFICATION_ARTIFACT_TYPE,
  SMART_BREAKPOINT_PLAN_ARTIFACT_TYPE,
  type CryptoPlanningArtifactScope,
} from '../crypto-planning-artifacts.js'
import { RequiredUserInputSchema, SetupActionSchema } from '../setup-guidance.js'

const TOOL_NAME = 'breakpoint.smart'

export const breakpointSmartInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  include_runtime_evidence: z
    .boolean()
    .optional()
    .default(true)
    .describe('Strengthen breakpoint ranking with imported runtime evidence when available'),
  runtime_evidence_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .default('latest')
    .describe('Dynamic evidence selection scope used when correlating runtime artifacts'),
  max_candidates: z
    .number()
    .int()
    .min(1)
    .max(20)
    .optional()
    .default(8)
    .describe('Maximum ranked breakpoint candidates returned inline'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist compact breakpoint recommendations as a JSON artifact'),
  reuse_cached: z
    .boolean()
    .optional()
    .default(true)
    .describe('Reuse the latest persisted smart breakpoint plan when available'),
  artifact_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .default('latest')
    .describe('Artifact selection scope used when reuse_cached=true'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass persisted artifacts and rebuild breakpoint recommendations'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag used when persisting breakpoint artifacts'),
})

export const breakpointSmartOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'partial']),
      sample_id: z.string(),
      recommended_breakpoints: z.array(BreakpointCandidateSchema),
      runtime_readiness: z.object({
        status: z.enum(['ready', 'partial', 'setup_required']),
        ready: z.boolean(),
        recommended_runtime_tool: z.enum(['frida.runtime.instrument', 'frida.script.inject']),
        available_components: z.array(z.string()),
        summary: z.string(),
        setup_actions: z.array(SetupActionSchema).optional(),
        required_user_inputs: z.array(RequiredUserInputSchema).optional(),
      }),
      summary: z.string(),
      source_artifact_refs: z.array(z.any()),
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
    })
    .optional(),
})

export const breakpointSmartToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Rank crypto and sensitive-API breakpoint candidates from compact static and optional dynamic evidence without executing instrumentation. ' +
    'Use this after crypto.identify when you want a planning-first breakpoint shortlist before building a trace plan.',
  inputSchema: breakpointSmartInputSchema,
  outputSchema: breakpointSmartOutputSchema,
}

interface BreakpointSmartDependencies {
  cryptoIdentify?: (args: unknown) => Promise<WorkerResult>
  dynamicDependencies?: (args: unknown) => Promise<WorkerResult>
  loadDynamicTrace?: (
    workspaceManager: WorkspaceManager,
    database: DatabaseManager,
    sampleId: string,
    options?: { evidenceScope?: DynamicEvidenceScope; sessionTag?: string }
  ) => Promise<DynamicTraceSummary | null>
}

function dedupeArtifactRefs(artifacts: ArtifactRef[]): ArtifactRef[] {
  const seen = new Set<string>()
  const output: ArtifactRef[] = []
  for (const artifact of artifacts) {
    const key = artifact.id || `${artifact.type}:${artifact.path}`
    if (!key || seen.has(key)) {
      continue
    }
    seen.add(key)
    output.push(artifact)
  }
  return output
}

function collectArtifactRefs(result: WorkerResult | undefined): ArtifactRef[] {
  if (!result) {
    return []
  }
  const refs: ArtifactRef[] = []
  if (Array.isArray(result.artifacts)) {
    refs.push(...(result.artifacts.filter((item) => item && typeof item === 'object') as ArtifactRef[]))
  }
  const data = result.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  if (data.artifact && typeof data.artifact === 'object') {
    refs.push(data.artifact as ArtifactRef)
  }
  if (Array.isArray(data.source_artifact_refs)) {
    refs.push(...(data.source_artifact_refs.filter((item) => item && typeof item === 'object') as ArtifactRef[]))
  }
  return refs
}

function parseCryptoFindings(result: WorkerResult | undefined): CryptoFinding[] {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  return Array.isArray(data.algorithms)
    ? data.algorithms.filter((item) => item && typeof item === 'object') as CryptoFinding[]
    : []
}

function buildRuntimeReadiness(result: WorkerResult | undefined) {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  const components = data.components && typeof data.components === 'object'
    ? (data.components as Record<string, unknown>)
    : {}
  const fridaAvailable = Boolean((components.frida as Record<string, unknown> | undefined)?.available)
  const workerAvailable = Boolean((components.worker as Record<string, unknown> | undefined)?.available)
  const ready = fridaAvailable && workerAvailable
  const availableComponents = Array.isArray(data.available_components)
    ? data.available_components.map((item) => String(item))
    : []
  return {
    status: ready
      ? 'ready'
      : availableComponents.length > 0
        ? 'partial'
        : 'setup_required',
    ready,
    recommended_runtime_tool: 'frida.runtime.instrument' as const,
    available_components: availableComponents,
    summary: ready
      ? 'Frida runtime instrumentation prerequisites are available.'
      : 'Frida runtime instrumentation is not fully ready yet; inspect setup guidance before trying to instrument a live process.',
    setup_actions: Array.isArray(data.setup_actions) ? data.setup_actions : undefined,
    required_user_inputs: Array.isArray(data.required_user_inputs) ? data.required_user_inputs : undefined,
  }
}

export function createBreakpointSmartHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies: BreakpointSmartDependencies = {}
) {
  const cryptoIdentifyHandler =
    dependencies.cryptoIdentify || createCryptoIdentifyHandler(workspaceManager, database, cacheManager)
  const dynamicDependenciesHandler =
    dependencies.dynamicDependencies || createDynamicDependenciesHandler(workspaceManager, database)
  const dynamicTraceLoader = dependencies.loadDynamicTrace || loadDynamicTraceEvidence

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = breakpointSmartInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      if (input.reuse_cached && !input.force_refresh) {
        const selection = await loadCryptoPlanningArtifactSelection<Record<string, unknown>>(
          workspaceManager,
          database,
          input.sample_id,
          SMART_BREAKPOINT_PLAN_ARTIFACT_TYPE,
          {
            scope: input.artifact_scope as CryptoPlanningArtifactScope,
            sessionTag: input.session_tag,
          }
        )
        if (selection.latest_payload) {
          return {
            ok: true,
            data: selection.latest_payload,
            warnings: ['Result from persisted artifact', selection.scope_note],
            artifacts: selection.artifact_refs,
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
              cached: true,
            },
          }
        }
      }

      const warnings: string[] = []
      let cryptoResult: WorkerResult | undefined

      if (input.reuse_cached && !input.force_refresh) {
        const cryptoSelection = await loadCryptoPlanningArtifactSelection<Record<string, unknown>>(
          workspaceManager,
          database,
          input.sample_id,
          CRYPTO_IDENTIFICATION_ARTIFACT_TYPE,
          {
            scope: input.artifact_scope as CryptoPlanningArtifactScope,
            sessionTag: input.session_tag,
          }
        )
        if (cryptoSelection.latest_payload) {
          cryptoResult = {
            ok: true,
            data: cryptoSelection.latest_payload,
            artifacts: cryptoSelection.artifact_refs,
          }
        }
      }

      if (!cryptoResult) {
        cryptoResult = await cryptoIdentifyHandler({
          sample_id: input.sample_id,
          include_runtime_evidence: input.include_runtime_evidence,
          runtime_evidence_scope: input.runtime_evidence_scope,
          persist_artifact: false,
          reuse_cached: true,
          artifact_scope: input.artifact_scope,
          force_refresh: input.force_refresh,
          session_tag: input.session_tag,
        })
      }

      warnings.push(...(cryptoResult.warnings || []))
      const dynamicEvidence =
        input.include_runtime_evidence
          ? await dynamicTraceLoader(workspaceManager, database, input.sample_id, {
              evidenceScope: input.runtime_evidence_scope,
              sessionTag: input.session_tag,
            })
          : null
      const candidates = buildBreakpointCandidates({
        findings: parseCryptoFindings(cryptoResult),
        dynamicEvidence,
        maxCandidates: input.max_candidates,
      })
      const runtimeReadiness = buildRuntimeReadiness(
        await dynamicDependenciesHandler({ sample_id: input.sample_id })
      )
      const sourceArtifactRefs = dedupeArtifactRefs(collectArtifactRefs(cryptoResult))
      const summary = summarizeBreakpointCandidates(candidates)
      const outputData = {
        status: (candidates.length > 0 ? 'ready' : 'partial') as 'ready' | 'partial',
        sample_id: input.sample_id,
        recommended_breakpoints: candidates,
        runtime_readiness: runtimeReadiness,
        summary,
        source_artifact_refs: sourceArtifactRefs,
        recommended_next_tools: runtimeReadiness.ready
          ? ['trace.condition', 'frida.runtime.instrument', 'frida.script.inject']
          : ['trace.condition', 'dynamic.dependencies', 'frida.runtime.instrument'],
        next_actions: runtimeReadiness.ready
          ? [
              'Use trace.condition on the top breakpoint candidate to define bounded capture rules before live instrumentation.',
              'Then pass the normalized plan into frida.runtime.instrument or frida.script.inject with the suggested script and process/session details.',
            ]
          : [
              'Inspect runtime_readiness.setup_actions before attempting any Frida-backed follow-on step.',
              'Use trace.condition now if you want a bounded capture plan even though the runtime prerequisites are not ready yet.',
            ],
      }

      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistCryptoPlanningJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          SMART_BREAKPOINT_PLAN_ARTIFACT_TYPE,
          'smart_breakpoints',
          {
            ...outputData,
            session_tag: input.session_tag || null,
          },
          input.session_tag
        )
      }

      return {
        ok: true,
        data: {
          ...outputData,
          ...(artifact ? { artifact } : {}),
        },
        warnings: Array.from(new Set(warnings.filter((item) => item.trim().length > 0))),
        artifacts: artifact ? [...sourceArtifactRefs, artifact] : sourceArtifactRefs,
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
