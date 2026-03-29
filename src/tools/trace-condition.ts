import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { createBreakpointSmartHandler } from './breakpoint-smart.js'
import { createDynamicDependenciesHandler } from './dynamic-dependencies.js'
import {
  BreakpointCandidateSchema,
  NormalizedTracePlanSchema,
  TraceCapturePlanSchema,
  TraceConditionGroupSchema,
  buildNormalizedTracePlan,
  summarizeCapturePlan,
  summarizeConditionGroup,
  summarizeNormalizedTracePlan,
} from '../crypto-breakpoint-analysis.js'
import {
  CONDITIONAL_TRACE_PLAN_ARTIFACT_TYPE,
  SMART_BREAKPOINT_PLAN_ARTIFACT_TYPE,
  loadCryptoPlanningArtifactSelection,
  persistCryptoPlanningJsonArtifact,
  type CryptoPlanningArtifactScope,
} from '../crypto-planning-artifacts.js'
import { RequiredUserInputSchema, SetupActionSchema } from '../setup-guidance.js'

const TOOL_NAME = 'trace.condition'

export const traceConditionInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  breakpoint_index: z
    .number()
    .int()
    .min(0)
    .max(31)
    .optional()
    .default(0)
    .describe('Zero-based index into the latest smart breakpoint artifact when breakpoint is omitted'),
  breakpoint: BreakpointCandidateSchema
    .optional()
    .describe('Optional explicit breakpoint candidate override; when omitted the latest smart breakpoint plan is used'),
  condition: TraceConditionGroupSchema
    .optional()
    .default({ logic: 'all', predicates: [] })
    .describe('Bounded condition block over registers, arguments, hit counts, or module/function identity'),
  capture: TraceCapturePlanSchema
    .optional()
    .describe('Optional capture overrides for registers, arguments, return value, stack bytes, and bounded memory slices'),
  max_hits: z
    .number()
    .int()
    .min(1)
    .max(100)
    .optional()
    .default(12)
    .describe('Maximum breakpoint hits retained by the normalized plan'),
  max_events: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .default(64)
    .describe('Maximum serialized events retained by the normalized plan'),
  max_memory_bytes: z
    .number()
    .int()
    .min(0)
    .max(2048)
    .optional()
    .default(256)
    .describe('Overall cap applied across stack capture and bounded memory slices'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist the normalized trace plan as a JSON artifact'),
  reuse_cached: z
    .boolean()
    .optional()
    .default(true)
    .describe('Reuse the latest persisted trace plan artifact when available'),
  artifact_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .default('latest')
    .describe('Artifact selection scope used when reuse_cached=true'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass persisted artifacts and rebuild the normalized trace plan'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag used when persisting trace-plan artifacts'),
})

export const traceConditionOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      sample_id: z.string(),
      selected_breakpoint: BreakpointCandidateSchema,
      normalized_plan: NormalizedTracePlanSchema,
      condition_summary: z.string(),
      capture_summary: z.string(),
      summary: z.string(),
      runtime_readiness: z.object({
        status: z.enum(['ready', 'partial', 'setup_required']),
        ready: z.boolean(),
        available_components: z.array(z.string()),
        summary: z.string(),
        setup_actions: z.array(SetupActionSchema).optional(),
        required_user_inputs: z.array(RequiredUserInputSchema).optional(),
      }),
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

export const traceConditionToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Compile a bounded conditional trace plan from a smart breakpoint candidate without executing instrumentation. ' +
    'Use this after breakpoint.smart to define capture scope, hit limits, and the recommended Frida-oriented runtime path.',
  inputSchema: traceConditionInputSchema,
  outputSchema: traceConditionOutputSchema,
}

interface TraceConditionDependencies {
  breakpointSmart?: (args: unknown) => Promise<WorkerResult>
  dynamicDependencies?: (args: unknown) => Promise<WorkerResult>
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
    available_components: availableComponents,
    summary: ready
      ? 'Frida runtime instrumentation prerequisites are available for this plan.'
      : 'Frida runtime instrumentation is not fully ready; keep this as a planning artifact until setup is complete.',
    setup_actions: Array.isArray(data.setup_actions) ? data.setup_actions : undefined,
    required_user_inputs: Array.isArray(data.required_user_inputs) ? data.required_user_inputs : undefined,
  }
}

function parseBreakpointCandidates(result: WorkerResult | undefined) {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  return Array.isArray(data.recommended_breakpoints)
    ? data.recommended_breakpoints.filter((item) => item && typeof item === 'object')
    : []
}

function applyMemoryCap(
  plan: z.infer<typeof NormalizedTracePlanSchema>
): { plan: z.infer<typeof NormalizedTracePlanSchema>; warnings: string[] } {
  const warnings: string[] = []
  let remaining = plan.limits.max_memory_bytes
  let stackBytes = plan.capture.stack_bytes
  if (stackBytes > remaining) {
    warnings.push(`Stack capture reduced from ${stackBytes}B to ${remaining}B to honor max_memory_bytes.`)
    stackBytes = remaining
  }
  remaining -= stackBytes

  const memorySlices = []
  for (const slice of plan.capture.memory_slices) {
    if (remaining <= 0) {
      warnings.push(`Dropped memory slice ${slice.label || slice.source} because max_memory_bytes was exhausted.`)
      continue
    }
    const maxBytes = Math.min(slice.max_bytes, remaining)
    if (maxBytes < slice.max_bytes) {
      warnings.push(`Memory slice ${slice.label || slice.source} reduced from ${slice.max_bytes}B to ${maxBytes}B.`)
    }
    remaining -= maxBytes
    memorySlices.push({
      ...slice,
      max_bytes: maxBytes,
    })
  }

  return {
    plan: {
      ...plan,
      capture: {
        ...plan.capture,
        stack_bytes: stackBytes,
        memory_slices: memorySlices,
      },
    },
    warnings,
  }
}

export function createTraceConditionHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies: TraceConditionDependencies = {}
) {
  const breakpointSmartHandler =
    dependencies.breakpointSmart || createBreakpointSmartHandler(workspaceManager, database, cacheManager)
  const dynamicDependenciesHandler =
    dependencies.dynamicDependencies || createDynamicDependenciesHandler(workspaceManager, database)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = traceConditionInputSchema.parse(args)
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
          CONDITIONAL_TRACE_PLAN_ARTIFACT_TYPE,
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

      let sourceResult: WorkerResult | undefined
      let selectedBreakpoint = input.breakpoint

      if (!selectedBreakpoint && input.reuse_cached && !input.force_refresh) {
        const breakpointSelection = await loadCryptoPlanningArtifactSelection<Record<string, unknown>>(
          workspaceManager,
          database,
          input.sample_id,
          SMART_BREAKPOINT_PLAN_ARTIFACT_TYPE,
          {
            scope: input.artifact_scope as CryptoPlanningArtifactScope,
            sessionTag: input.session_tag,
          }
        )
        if (breakpointSelection.latest_payload) {
          sourceResult = {
            ok: true,
            data: breakpointSelection.latest_payload,
            artifacts: breakpointSelection.artifact_refs,
          }
        }
      }

      if (!sourceResult && !selectedBreakpoint) {
        sourceResult = await breakpointSmartHandler({
          sample_id: input.sample_id,
          persist_artifact: false,
          reuse_cached: true,
          artifact_scope: input.artifact_scope,
          force_refresh: input.force_refresh,
          session_tag: input.session_tag,
        })
      }

      if (!selectedBreakpoint) {
        const candidates = parseBreakpointCandidates(sourceResult)
        selectedBreakpoint = candidates[input.breakpoint_index] as z.infer<typeof BreakpointCandidateSchema> | undefined
      }

      if (!selectedBreakpoint) {
        return {
          ok: false,
          errors: ['No breakpoint candidate was available. Run breakpoint.smart first or provide breakpoint explicitly.'],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const runtimeReadiness = buildRuntimeReadiness(
        await dynamicDependenciesHandler({ sample_id: input.sample_id })
      )
      const builtPlan = buildNormalizedTracePlan({
        breakpoint: BreakpointCandidateSchema.parse(selectedBreakpoint),
        condition: input.condition,
        capture: input.capture,
        limits: {
          max_hits: input.max_hits,
          max_events: input.max_events,
          max_memory_bytes: input.max_memory_bytes,
        },
        runtimeReady: runtimeReadiness.ready,
      })
      const capped = applyMemoryCap(builtPlan)
      const plan = NormalizedTracePlanSchema.parse(capped.plan)
      const sourceArtifactRefs = dedupeArtifactRefs(collectArtifactRefs(sourceResult))
      const conditionSummary = summarizeConditionGroup(plan.condition)
      const captureSummary = summarizeCapturePlan(plan.capture)
      const summary = summarizeNormalizedTracePlan(plan)
      const outputData = {
        status: (runtimeReadiness.ready ? 'ready' : 'setup_required') as 'ready' | 'setup_required',
        sample_id: input.sample_id,
        selected_breakpoint: BreakpointCandidateSchema.parse(selectedBreakpoint),
        normalized_plan: plan,
        condition_summary: conditionSummary,
        capture_summary: captureSummary,
        summary,
        runtime_readiness: runtimeReadiness,
        source_artifact_refs: sourceArtifactRefs,
        recommended_next_tools: runtimeReadiness.ready
          ? [plan.runtime_mapping.recommended_tool, 'dynamic.dependencies']
          : ['dynamic.dependencies', plan.runtime_mapping.recommended_tool],
        next_actions: runtimeReadiness.ready
          ? [
              `Invoke ${plan.runtime_mapping.recommended_tool} with the suggested script ${plan.runtime_mapping.suggested_script_name} and provide the required PID or spawn/session details.`,
              'Keep the normalized plan as the source of truth for hit limits and capture scope instead of widening the trace ad hoc.',
            ]
          : [
              'Inspect runtime_readiness.setup_actions and required_user_inputs before attempting any Frida-backed execution.',
              `Once the runtime is ready, invoke ${plan.runtime_mapping.recommended_tool} with the suggested script ${plan.runtime_mapping.suggested_script_name}.`,
            ],
      }

      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistCryptoPlanningJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          CONDITIONAL_TRACE_PLAN_ARTIFACT_TYPE,
          'conditional_trace_plan',
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
        warnings: capped.warnings.length > 0 ? capped.warnings : undefined,
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
