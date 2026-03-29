import { z } from 'zod'
import type { ToolchainBackendResolution } from './static-backend-discovery.js'
import {
  AnalysisCostClassSchema,
  ExecutionBucketSchema,
} from './analysis-budget-scheduler.js'

export const AnalysisIntentGoalSchema = z.enum(['triage', 'static', 'reverse', 'dynamic', 'report'])
export const AnalysisIntentDepthSchema = z.enum(['safe', 'balanced', 'deep'])
export const BackendPolicySchema = z.enum(['auto', 'prefer_new', 'legacy_only', 'strict'])

export type AnalysisIntentGoal = z.infer<typeof AnalysisIntentGoalSchema>
export type AnalysisIntentDepth = z.infer<typeof AnalysisIntentDepthSchema>
export type BackendPolicy = z.infer<typeof BackendPolicySchema>

export const BackendRoutingRecordSchema = z.object({
  backend: z.string(),
  tool: z.string(),
  reason: z.string(),
  ready: z.boolean().optional(),
})

export const BackendStageSchema = z.enum([
  'fast_profile',
  'enrich_static',
  'function_map',
  'reconstruct',
  'dynamic_plan',
  'dynamic_execute',
  'reporting',
])

export const BackendSelectionPolicySchema = z.enum([
  'default',
  'conditional',
  'fallback',
  'manual',
])

export const StageBackendRoleSchema = z.object({
  stage: BackendStageSchema,
  backend: z.string(),
  tool: z.string(),
  role: z.string(),
  execution_bucket: ExecutionBucketSchema,
  cost_class: AnalysisCostClassSchema,
  worker_family: z.string(),
  selection_policy: BackendSelectionPolicySchema,
  reason: z.string(),
  ready: z.boolean().optional(),
})

export const BackendRoutingMetadataSchema = z.object({
  goal: AnalysisIntentGoalSchema,
  depth: AnalysisIntentDepthSchema,
  backend_policy: BackendPolicySchema,
  backend_considered: z.array(BackendRoutingRecordSchema),
  backend_selected: z.array(BackendRoutingRecordSchema),
  backend_skipped: z.array(BackendRoutingRecordSchema),
  backend_escalation_reasons: z.array(z.string()),
  manual_only_backends: z.array(BackendRoutingRecordSchema),
  omitted_backend_reasons: z.array(z.string()),
  stage_backend_roles: z.array(StageBackendRoleSchema),
})

export type BackendRoutingRecord = z.infer<typeof BackendRoutingRecordSchema>
export type BackendRoutingMetadata = z.infer<typeof BackendRoutingMetadataSchema>

type BackendStage = z.infer<typeof BackendStageSchema>

export interface BackendPlanSignals {
  large_sample_preview?: boolean
  packer_suspected?: boolean
  packed_confirmed?: boolean
  debug_requested?: boolean
  legacy_yara_weak?: boolean
  degraded_structure?: boolean
  import_parsing_weak?: boolean
  weak_function_coverage?: boolean
  degraded_reconstruction?: boolean
  unresolved_control_flow?: boolean
  qiling_rootfs_ready?: boolean
  panda_ready?: boolean
  yara_x_rules_ready?: boolean
}

interface CandidateDecisionArgs {
  depth: AnalysisIntentDepth
  backendPolicy: BackendPolicy
  allowTransformations: boolean
  allowLiveExecution: boolean
  signals: BackendPlanSignals
}

interface BackendCandidate {
  backend: keyof ToolchainBackendResolution
  tool: string
  kind: 'safe_auto' | 'manual_only'
  selectWhen: (args: CandidateDecisionArgs) => boolean
  selectedReason: string
  skippedReason: string
  manualReason?: string
}

interface StageBackendRoleTemplate {
  stage: BackendStage
  backend: keyof ToolchainBackendResolution
  tool: string
  role: string
  executionBucket: z.infer<typeof ExecutionBucketSchema>
  costClass: z.infer<typeof AnalysisCostClassSchema>
  workerFamily: string
  selectionPolicy: z.infer<typeof BackendSelectionPolicySchema>
  reason: string
}

type ReadinessMap = ToolchainBackendResolution | undefined

function makeRecord(
  candidate: Pick<BackendCandidate, 'backend' | 'tool'>,
  reason: string,
  ready?: boolean
): BackendRoutingRecord {
  return {
    backend: candidate.backend,
    tool: candidate.tool,
    reason,
    ...(typeof ready === 'boolean' ? { ready } : {}),
  }
}

function isReady(readiness: ReadinessMap, backend: keyof ToolchainBackendResolution): boolean {
  if (!readiness) {
    return false
  }
  return Boolean(readiness[backend]?.available)
}

function prefersNewBackend(policy: BackendPolicy): boolean {
  return policy === 'prefer_new'
}

function isStrictPolicy(policy: BackendPolicy): boolean {
  return policy === 'strict'
}

function isLegacyOnly(policy: BackendPolicy): boolean {
  return policy === 'legacy_only'
}

function triageCandidates(): BackendCandidate[] {
  return [
    {
      backend: 'upx',
      tool: 'upx.inspect',
      kind: 'safe_auto',
      selectWhen: ({ signals }) => Boolean(signals.packer_suspected),
      selectedReason: 'Packer or overlay signals suggest UPX-style packing; run bounded UPX validation.',
      skippedReason: 'UPX validation was not triggered because packer suspicion is weak.',
    },
    {
      backend: 'yara_x',
      tool: 'yara_x.scan',
      kind: 'safe_auto',
      selectWhen: ({ backendPolicy, signals }) =>
        Boolean(signals.yara_x_rules_ready) &&
        (Boolean(signals.legacy_yara_weak) || prefersNewBackend(backendPolicy)),
      selectedReason: 'Legacy YARA evidence is weak or newer-engine comparison is preferred; run bounded YARA-X corroboration.',
      skippedReason:
        'YARA-X corroboration was not triggered because legacy YARA evidence is already strong enough or no default YARA-X rules are available.',
    },
    {
      backend: 'rizin',
      tool: 'rizin.analyze',
      kind: 'safe_auto',
      selectWhen: ({ backendPolicy, depth, signals }) =>
        Boolean(signals.large_sample_preview) ||
        Boolean(signals.degraded_structure || signals.import_parsing_weak) ||
        (depth === 'deep' && prefersNewBackend(backendPolicy)),
      selectedReason:
        'Large-sample preview or degraded structure/import parsing favors bounded Rizin inspection before deeper attribution.',
      skippedReason: 'Rizin corroboration was not triggered because fast preview signals do not justify extra parser corroboration yet.',
    },
  ]
}

function buildStageBackendRoles(readiness: ReadinessMap): z.infer<typeof StageBackendRoleSchema>[] {
  const templates: StageBackendRoleTemplate[] = [
    {
      stage: 'fast_profile',
      backend: 'rizin',
      tool: 'rizin.analyze',
      role: 'default_preview_correlator',
      executionBucket: 'preview-static',
      costClass: 'cheap',
      workerFamily: 'rizin.preview',
      selectionPolicy: 'default',
      reason: 'Rizin is the default fast corroboration backend for bounded static preview and malformed PE fallback.',
    },
    {
      stage: 'fast_profile',
      backend: 'yara_x',
      tool: 'yara_x.scan',
      role: 'bounded_rule_correlator',
      executionBucket: 'preview-static',
      costClass: 'cheap',
      workerFamily: 'yarax.preview',
      selectionPolicy: 'conditional',
      reason: 'YARA-X supplements legacy YARA when new-engine corroboration is useful and rules are available.',
    },
    {
      stage: 'fast_profile',
      backend: 'upx',
      tool: 'upx.inspect',
      role: 'non_mutating_packer_probe',
      executionBucket: 'preview-static',
      costClass: 'cheap',
      workerFamily: 'upx.preview',
      selectionPolicy: 'conditional',
      reason: 'UPX stays in the fast profile only for non-mutating validation when packer hints are present.',
    },
    {
      stage: 'enrich_static',
      backend: 'rizin',
      tool: 'rizin.analyze',
      role: 'corroborating_static_parser',
      executionBucket: 'enrich-static',
      costClass: 'moderate',
      workerFamily: 'rizin.preview',
      selectionPolicy: 'conditional',
      reason: 'Rizin remains available during enrich_static for cheap corroboration without pulling Ghidra into preview paths.',
    },
    {
      stage: 'function_map',
      backend: 'rizin',
      tool: 'rizin.analyze',
      role: 'fast_function_index_corroboration',
      executionBucket: 'deep-attribution',
      costClass: 'moderate',
      workerFamily: 'rizin.preview',
      selectionPolicy: 'fallback',
      reason: 'Rizin corroborates basic function inventory and import context before or alongside deeper attribution.',
    },
    {
      stage: 'function_map',
      backend: 'graphviz',
      tool: 'graphviz.render',
      role: 'artifact_graph_renderer',
      executionBucket: 'artifact-only',
      costClass: 'cheap',
      workerFamily: 'graphviz.render',
      selectionPolicy: 'conditional',
      reason: 'Graphviz is only used to render persisted graph artifacts after function-map data exists.',
    },
    {
      stage: 'reconstruct',
      backend: 'angr',
      tool: 'angr.analyze',
      role: 'targeted_cfg_fallback',
      executionBucket: 'deep-attribution',
      costClass: 'expensive',
      workerFamily: 'angr_analyze',
      selectionPolicy: 'fallback',
      reason: 'angr is reserved for unresolved CFG or weak function-coverage fallback during reconstruction.',
    },
    {
      stage: 'reconstruct',
      backend: 'retdec',
      tool: 'retdec.decompile',
      role: 'alternate_decompiler_fallback',
      executionBucket: 'deep-attribution',
      costClass: 'expensive',
      workerFamily: 'retdec_decompile',
      selectionPolicy: 'fallback',
      reason: 'RetDec provides an alternate persisted reconstruction view when primary decompilation is degraded.',
    },
    {
      stage: 'dynamic_plan',
      backend: 'upx',
      tool: 'upx.inspect',
      role: 'safe_unpack_probe',
      executionBucket: 'dynamic-plan',
      costClass: 'cheap',
      workerFamily: 'upx.preview',
      selectionPolicy: 'conditional',
      reason: 'UPX remains available during dynamic planning for safe dump-oriented unpack preparation on packed samples.',
    },
    {
      stage: 'dynamic_plan',
      backend: 'qiling',
      tool: 'qiling.inspect',
      role: 'emulation_readiness_probe',
      executionBucket: 'dynamic-plan',
      costClass: 'moderate',
      workerFamily: 'qiling.inspect',
      selectionPolicy: 'conditional',
      reason: 'Qiling enters the graph as readiness and planning evidence before any emulation is promoted.',
    },
    {
      stage: 'dynamic_plan',
      backend: 'panda',
      tool: 'panda.inspect',
      role: 'record_replay_readiness_probe',
      executionBucket: 'dynamic-plan',
      costClass: 'moderate',
      workerFamily: 'panda.inspect',
      selectionPolicy: 'conditional',
      reason: 'PANDA is planning-only until guest images and trace assets justify deeper dynamic promotion.',
    },
    {
      stage: 'dynamic_execute',
      backend: 'wine',
      tool: 'wine.run',
      role: 'approval_gated_live_execution',
      executionBucket: 'manual-execution',
      costClass: 'manual-only',
      workerFamily: 'wine.run',
      selectionPolicy: 'manual',
      reason: 'Wine remains manual-only because it launches the sample and crosses the execution boundary.',
    },
    {
      stage: 'dynamic_execute',
      backend: 'winedbg',
      tool: 'wine.run',
      role: 'approval_gated_debug_execution',
      executionBucket: 'manual-execution',
      costClass: 'manual-only',
      workerFamily: 'wine.run',
      selectionPolicy: 'manual',
      reason: 'winedbg remains manual-only for the same approval-gated execution boundary as Wine.',
    },
    {
      stage: 'dynamic_execute',
      backend: 'frida_cli',
      tool: 'frida.trace.capture',
      role: 'manual_instrumentation_surface',
      executionBucket: 'manual-execution',
      costClass: 'manual-only',
      workerFamily: 'frida.trace.capture',
      selectionPolicy: 'manual',
      reason: 'Frida-backed live instrumentation remains explicit even when dynamic planning has already completed.',
    },
    {
      stage: 'reporting',
      backend: 'graphviz',
      tool: 'graphviz.render',
      role: 'artifact_only_visualization',
      executionBucket: 'artifact-only',
      costClass: 'cheap',
      workerFamily: 'graphviz.render',
      selectionPolicy: 'conditional',
      reason: 'Graphviz only materializes persisted report artifacts and should not widen synchronous inline payloads.',
    },
  ]

  return templates.map((template) =>
    StageBackendRoleSchema.parse({
      stage: template.stage,
      backend: template.backend,
      tool: template.tool,
      role: template.role,
      execution_bucket: template.executionBucket,
      cost_class: template.costClass,
      worker_family: template.workerFamily,
      selection_policy: template.selectionPolicy,
      reason: template.reason,
      ready: isReady(readiness, template.backend),
    })
  )
}

function deepStaticCandidates(): BackendCandidate[] {
  return [
    {
      backend: 'rizin',
      tool: 'rizin.analyze',
      kind: 'safe_auto',
      selectWhen: ({ backendPolicy, depth, signals }) =>
        Boolean(signals.weak_function_coverage || signals.degraded_structure) ||
        (depth === 'deep' && prefersNewBackend(backendPolicy)),
      selectedReason: 'Function coverage or structure quality is weak; use Rizin as a fast corroborating discovery backend.',
      skippedReason: 'Rizin fallback was not triggered because baseline static coverage looks acceptable.',
    },
    {
      backend: 'angr',
      tool: 'angr.analyze',
      kind: 'safe_auto',
      selectWhen: ({ backendPolicy, signals }) =>
        Boolean(signals.weak_function_coverage || signals.unresolved_control_flow) ||
        (prefersNewBackend(backendPolicy) && !isStrictPolicy(backendPolicy)),
      selectedReason: 'Weak function coverage or unresolved control-flow requires a bounded angr CFGFast pass.',
      skippedReason: 'angr CFGFast was not triggered because baseline function discovery looks sufficient.',
    },
    {
      backend: 'retdec',
      tool: 'retdec.decompile',
      kind: 'safe_auto',
      selectWhen: ({ depth, backendPolicy, signals }) =>
        depth === 'deep' &&
        Boolean(signals.degraded_reconstruction || signals.weak_function_coverage || prefersNewBackend(backendPolicy)),
      selectedReason: 'Decompilation or reconstruction quality is degraded; add a bounded RetDec alternate decompiler artifact.',
      skippedReason: 'RetDec fallback was not triggered because the current decompiler output is sufficient or depth is below deep.',
    },
  ]
}

function dynamicCandidates(): BackendCandidate[] {
  return [
    {
      backend: 'qiling',
      tool: 'qiling.inspect',
      kind: 'safe_auto',
      selectWhen: ({ depth, signals }) =>
        Boolean(signals.qiling_rootfs_ready) ||
        Boolean(signals.packer_suspected) ||
        Boolean(signals.debug_requested) ||
        depth !== 'safe',
      selectedReason: 'Dynamic intent should surface Qiling readiness and packed/debug-safe planning before any emulation-oriented escalation.',
      skippedReason: 'Qiling readiness was not surfaced because the current request does not yet justify unpack/debug planning depth.',
    },
    {
      backend: 'panda',
      tool: 'panda.inspect',
      kind: 'safe_auto',
      selectWhen: ({ depth, signals }) =>
        Boolean(signals.panda_ready) || depth === 'deep' || Boolean(signals.debug_requested),
      selectedReason: 'Dynamic intent should surface PANDA record/replay readiness for deeper or session-oriented debug workflows.',
      skippedReason: 'PANDA readiness was not surfaced because the requested depth did not justify it.',
    },
    {
      backend: 'frida_cli',
      tool: 'frida.trace.capture',
      kind: 'manual_only',
      selectWhen: () => false,
      selectedReason: 'Frida live capture is never auto-selected.',
      skippedReason: 'Frida live instrumentation is approval-gated.',
      manualReason:
        'Frida trace capture remains manual-only until a persisted debug session exists and live execution has been explicitly approved.',
    },
    {
      backend: 'wine',
      tool: 'wine.run',
      kind: 'manual_only',
      selectWhen: () => false,
      selectedReason: 'Wine execution is never auto-selected.',
      skippedReason: 'Wine execution is approval-gated.',
      manualReason:
        'Wine or winedbg can launch the sample and therefore remains manual-only until allow_live_execution and approved=true are both present.',
    },
  ]
}

function reportCandidates(): BackendCandidate[] {
  return []
}

function getCandidatesForGoal(goal: AnalysisIntentGoal): BackendCandidate[] {
  switch (goal) {
    case 'triage':
      return triageCandidates()
    case 'static':
    case 'reverse':
      return deepStaticCandidates()
    case 'dynamic':
      return dynamicCandidates()
    case 'report':
    default:
      return reportCandidates()
  }
}

export interface BuildIntentBackendPlanOptions {
  goal: AnalysisIntentGoal
  depth?: AnalysisIntentDepth
  backendPolicy?: BackendPolicy
  allowTransformations?: boolean
  allowLiveExecution?: boolean
  readiness?: ToolchainBackendResolution
  signals?: BackendPlanSignals
}

export function buildIntentBackendPlan(
  options: BuildIntentBackendPlanOptions
): BackendRoutingMetadata {
  const depth = options.depth ?? 'balanced'
  const backendPolicy = options.backendPolicy ?? 'auto'
  const allowTransformations = options.allowTransformations ?? false
  const allowLiveExecution = options.allowLiveExecution ?? false
  const signals = options.signals || {}
  const readiness = options.readiness

  const metadata: BackendRoutingMetadata = {
    goal: options.goal,
    depth,
    backend_policy: backendPolicy,
    backend_considered: [],
    backend_selected: [],
    backend_skipped: [],
    backend_escalation_reasons: [],
    manual_only_backends: [],
    omitted_backend_reasons: [],
    stage_backend_roles: buildStageBackendRoles(readiness),
  }

  const decisionArgs: CandidateDecisionArgs = {
    depth,
    backendPolicy,
    allowTransformations,
    allowLiveExecution,
    signals,
  }

  for (const candidate of getCandidatesForGoal(options.goal)) {
    const ready = isReady(readiness, candidate.backend)
    metadata.backend_considered.push(
      makeRecord(candidate, `Consider ${candidate.tool} for ${options.goal} intent.`, ready)
    )

    if (candidate.kind === 'manual_only') {
      metadata.manual_only_backends.push(
        makeRecord(candidate, candidate.manualReason || candidate.skippedReason, ready)
      )
      metadata.omitted_backend_reasons.push(candidate.manualReason || candidate.skippedReason)
      continue
    }

    if (isLegacyOnly(backendPolicy)) {
      const reason = 'backend_policy=legacy_only suppressed newer corroborating backends.'
      metadata.backend_skipped.push(
        makeRecord(candidate, reason, ready)
      )
      metadata.omitted_backend_reasons.push(reason)
      continue
    }

    if (!ready) {
      const reason = 'Backend is unavailable in the current environment.'
      metadata.backend_skipped.push(
        makeRecord(candidate, reason, ready)
      )
      metadata.omitted_backend_reasons.push(`${candidate.tool}: ${reason}`)
      continue
    }

    if (candidate.selectWhen(decisionArgs)) {
      metadata.backend_selected.push(makeRecord(candidate, candidate.selectedReason, ready))
      metadata.backend_escalation_reasons.push(candidate.selectedReason)
      continue
    }

    metadata.backend_skipped.push(makeRecord(candidate, candidate.skippedReason, ready))
    metadata.omitted_backend_reasons.push(`${candidate.tool}: ${candidate.skippedReason}`)
  }

  if (options.goal === 'dynamic' && !allowLiveExecution) {
    const reason = 'Dynamic intent remains simulation-first; live execution backends stay approval-gated.'
    metadata.backend_escalation_reasons.push(reason)
    metadata.omitted_backend_reasons.push(reason)
  }

  return metadata
}

export function mergeRoutingMetadata<T extends Record<string, unknown>>(
  data: T,
  metadata: BackendRoutingMetadata
): T & BackendRoutingMetadata {
  return {
    ...data,
    ...metadata,
  }
}

export function selectedBackendTools(metadata: BackendRoutingMetadata): string[] {
  return metadata.backend_selected.map((item) => item.tool)
}
