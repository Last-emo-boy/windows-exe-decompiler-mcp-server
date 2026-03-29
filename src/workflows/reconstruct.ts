/**
 * Reconstruction workflow implementation
 * One-shot orchestration for source-like reconstruction across native/.NET paths.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { JobQueue } from '../job-queue.js'
import { generateCacheKey } from '../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from '../tools/cache-observability.js'
import { createRuntimeDetectHandler } from '../tools/runtime-detect.js'
import { createCodeReconstructPlanHandler } from '../tools/code-reconstruct-plan.js'
import { createCodeReconstructExportHandler } from '../tools/code-reconstruct-export.js'
import { createDotNetReconstructExportHandler } from '../tools/dotnet-reconstruct-export.js'
import {
  findBestGhidraAnalysis,
  isGhidraCapabilityReady,
} from '../ghidra-analysis-status.js'
import { loadDynamicTraceEvidence } from '../dynamic-trace.js'
import {
  loadSemanticFunctionExplanationIndex,
  loadSemanticNameSuggestionIndex,
} from '../semantic-name-suggestion-artifacts.js'
import {
  BinaryRoleProfileDataSchema,
  createBinaryRoleProfileHandler,
} from '../tools/binary-role-profile.js'
import {
  ComRoleProfileDataSchema,
  createComRoleProfileHandler,
} from '../tools/com-role-profile.js'
import {
  DllExportProfileDataSchema,
  createDllExportProfileHandler,
} from '../tools/dll-export-profile.js'
import {
  RustBinaryAnalyzeDataSchema,
  createRustBinaryAnalyzeHandler,
} from '../tools/rust-binary-analyze.js'
import { createFunctionIndexRecoverWorkflowHandler } from './function-index-recover.js'
import {
  AnalysisProvenanceSchema,
  buildRuntimeArtifactProvenance,
  buildSemanticArtifactProvenance,
} from '../analysis-provenance.js'
import {
  GhidraExecutionSummarySchema,
  buildGhidraExecutionSummary,
} from '../ghidra-execution-summary.js'
import {
  AnalysisSelectionDiffSchema,
  buildArtifactSelectionDiff,
} from '../selection-diff.js'
import {
  RequiredUserInputSchema,
  SetupActionSchema,
  collectSetupGuidanceFromWorkerResult,
  mergeRequiredUserInputs,
  mergeSetupActions,
} from '../setup-guidance.js'
import { PollingGuidanceSchema, buildPollingGuidance } from '../polling-guidance.js'
import {
  AnalysisIntentDepthSchema,
  BackendPolicySchema,
  BackendRoutingMetadataSchema,
  buildIntentBackendPlan,
  mergeRoutingMetadata,
  selectedBackendTools,
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
import {
  createAngrAnalyzeHandler,
  createRetDecDecompileHandler,
  createRizinAnalyzeHandler,
} from '../tools/docker-backend-tools.js'

const TOOL_NAME = 'workflow.reconstruct'
const TOOL_VERSION = '0.1.5'
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000 // 7 days

export const ReconstructWorkflowInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  path: z
    .enum(['auto', 'native', 'dotnet'])
    .default('auto')
    .describe('Routing strategy for reconstruction path'),
  topk: z
    .number()
    .int()
    .min(1)
    .max(40)
    .default(16)
    .describe('Top-K high-value functions used by export tools'),
  export_name: z
    .string()
    .min(1)
    .max(64)
    .optional()
    .describe('Optional export folder name'),
  validate_build: z
    .boolean()
    .default(true)
    .describe('For native path, compile the exported C skeleton when clang is available'),
  run_harness: z
    .boolean()
    .default(true)
    .describe('For native path, execute reconstruct_harness after a successful build'),
  compiler_path: z
    .string()
    .min(1)
    .max(260)
    .optional()
    .describe('Optional explicit clang compiler path for native validation'),
  build_timeout_ms: z
    .number()
    .int()
    .min(5000)
    .max(300000)
    .default(60000)
    .describe('Timeout for native clang build validation in milliseconds'),
  run_timeout_ms: z
    .number()
    .int()
    .min(5000)
    .max(300000)
    .default(30000)
    .describe('Timeout for reconstruct_harness execution in milliseconds'),
  evidence_scope: z
    .enum(['all', 'latest', 'session'])
    .default('all')
    .describe('Runtime evidence scope forwarded to downstream reconstruct/export tools'),
  evidence_session_tag: z
    .string()
    .optional()
    .describe('Optional runtime evidence session selector used when evidence_scope=session or to narrow all/latest results'),
  semantic_scope: z
    .enum(['all', 'latest', 'session'])
    .default('all')
    .describe('Semantic review artifact scope forwarded to native reconstruct/export tools'),
  semantic_session_tag: z
    .string()
    .optional()
    .describe('Optional semantic review session selector used when semantic_scope=session or to narrow all/latest results'),
  compare_evidence_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .describe('Optional baseline runtime evidence scope used to compare this workflow result against another runtime artifact selection'),
  compare_evidence_session_tag: z
    .string()
    .optional()
    .describe('Optional baseline runtime evidence session selector used when compare_evidence_scope=session'),
  compare_semantic_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .describe('Optional baseline semantic artifact scope used to compare this workflow result against another naming/explanation selection'),
  compare_semantic_session_tag: z
    .string()
    .optional()
    .describe('Optional baseline semantic artifact session selector used when compare_semantic_scope=session'),
  include_preflight: z
    .boolean()
    .default(true)
    .describe('Run binary role and language-specific preflight profiling before planning and export'),
  auto_recover_function_index: z
    .boolean()
    .default(true)
    .describe('When native function-index coverage is missing, automatically run workflow.function_index_recover before export'),
  include_plan: z
    .boolean()
    .default(true)
    .describe('Include code.reconstruct.plan stage in the workflow'),
  include_obfuscation_fallback: z
    .boolean()
    .default(true)
    .describe('When routing to .NET path, generate IL fallback notes when needed'),
  fallback_on_error: z
    .boolean()
    .default(true)
    .describe('When primary export path fails, automatically try the alternative path'),
  allow_partial: z
    .boolean()
    .default(true)
    .describe('When all export paths fail, still return runtime/plan as partial output'),
  depth: AnalysisIntentDepthSchema
    .default('balanced')
    .describe('Controls how aggressively safe corroborating recovery backends are auto-selected.'),
  backend_policy: BackendPolicySchema
    .default('auto')
    .describe('Controls whether newer installed backends are auto-preferred, suppressed, or only selected when reconstruction quality is weak.'),
  allow_transformations: z
    .boolean()
    .default(false)
    .describe('Reserved for future transform-capable reverse workflows. Keep false for normal artifact-first reconstruction.'),
  reuse_cached: z
    .boolean()
    .default(true)
    .describe('Reuse cached workflow result for identical inputs'),
})
  .refine((value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()), {
    message: 'evidence_session_tag is required when evidence_scope=session',
    path: ['evidence_session_tag'],
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
      value.compare_semantic_scope !== 'session' || Boolean(value.compare_semantic_session_tag?.trim()),
    {
      message: 'compare_semantic_session_tag is required when compare_semantic_scope=session',
      path: ['compare_semantic_session_tag'],
    }
  )

export type ReconstructWorkflowInput = z.infer<typeof ReconstructWorkflowInputSchema>

const RuntimeSummarySchema = z.object({
  is_dotnet: z.boolean().nullable(),
  dotnet_version: z.string().nullable(),
  target_framework: z.string().nullable(),
  primary_runtime: z.string().nullable(),
})

const PlanSummarySchema = z.object({
  feasibility: z.enum(['high', 'medium', 'low']),
  confidence: z.number().min(0).max(1),
  restoration_expectation: z.string(),
  blockers: z.array(z.string()),
  recommendations: z.array(z.string()),
})

const BinaryProfileSchema = z.object({
  binary_role: z.string(),
  original_filename: z.string().nullable(),
  export_count: z.number().int().nonnegative(),
  forwarder_count: z.number().int().nonnegative(),
  notable_exports: z.array(z.string()),
  packed: z.boolean(),
  packing_confidence: z.number().min(0).max(1),
  analysis_priorities: z.array(z.string()),
})

const ManagedProfileSchema = z.object({
  assembly_name: z.string().nullable(),
  assembly_version: z.string().nullable(),
  module_name: z.string().nullable(),
  metadata_version: z.string().nullable(),
  is_library: z.boolean(),
  entry_point_token: z.string().nullable(),
  type_count: z.number().int().nonnegative(),
  method_count: z.number().int().nonnegative(),
  namespace_count: z.number().int().nonnegative(),
  assembly_reference_count: z.number().int().nonnegative(),
  resource_count: z.number().int().nonnegative(),
  dominant_namespaces: z.array(z.string()),
  notable_types: z.array(z.string()),
  assembly_references: z.array(z.string()),
  resources: z.array(z.string()),
  analysis_priorities: z.array(z.string()),
})

const ExportSummarySchema = z.object({
  tool: z.enum(['code.reconstruct.export', 'dotnet.reconstruct.export']),
  export_root: z.string(),
  manifest_path: z.string().nullable(),
  gaps_path: z.string().nullable(),
  notes_path: z.string().nullable(),
  metadata_path: z.string().nullable(),
  csproj_path: z.string().nullable(),
  readme_path: z.string().nullable(),
  fallback_notes_path: z.string().nullable(),
  build_validation_status: z.enum(['passed', 'failed', 'skipped', 'unavailable']).nullable(),
  harness_validation_status: z.enum(['passed', 'failed', 'skipped', 'unavailable']).nullable(),
  build_log_path: z.string().nullable(),
  harness_log_path: z.string().nullable(),
  executable_path: z.string().nullable(),
  degraded_mode: z.boolean().nullable(),
  module_count: z.number().int().nonnegative().nullable(),
  unresolved_count: z.number().int().nonnegative().nullable(),
  class_count: z.number().int().nonnegative().nullable(),
  binary_profile: BinaryProfileSchema.nullable(),
  managed_profile: ManagedProfileSchema.nullable(),
})

const PreflightRustProfileSchema = z.object({
  suspected_rust: z.boolean(),
  confidence: z.number().min(0).max(1),
  primary_runtime: z.string().nullable(),
  runtime_hints: z.array(z.string()),
  crate_hints: z.array(z.string()),
  cargo_paths: z.array(z.string()),
  recovered_function_count: z.number().int().nonnegative(),
  recovered_symbol_count: z.number().int().nonnegative(),
  importable_with_code_functions_define: z.boolean(),
  analysis_priorities: z.array(z.string()),
})

const PreflightDllProfileSchema = z.object({
  library_like: z.boolean(),
  role_confidence: z.number().min(0).max(1),
  likely_entry_model: z.string(),
  dll_entry_hints: z.array(z.string()),
  dispatch_model: z.string(),
  host_hints: z.array(z.string()),
  lifecycle_surface: DllExportProfileDataSchema.shape.lifecycle_surface,
  class_factory_surface: DllExportProfileDataSchema.shape.class_factory_surface,
  callback_surface: DllExportProfileDataSchema.shape.callback_surface,
  analysis_priorities: z.array(z.string()),
})

const PreflightComProfileSchema = z.object({
  likely_com_server: z.boolean(),
  com_confidence: z.number().min(0).max(1),
  activation_model: z.string(),
  class_factory_exports: z.array(z.string()),
  registration_exports: z.array(z.string()),
  clsid_strings: z.array(z.string()),
  progid_strings: z.array(z.string()),
  interface_hints: z.array(z.string()),
  class_factory_surface: ComRoleProfileDataSchema.shape.class_factory_surface,
  activation_steps: z.array(z.string()),
  analysis_priorities: z.array(z.string()),
})

const RoleAwareExportTuningSchema = z.object({
  topk: z.number().int().positive(),
  module_limit: z.number().int().positive(),
  min_module_size: z.number().int().positive(),
  include_imports: z.boolean(),
  include_strings: z.boolean(),
})

const RoleAwareStrategySchema = z.object({
  target_role: z.string(),
  priority_order: z.array(z.string()),
  focus_areas: z.array(z.string()),
  rationale: z.array(z.string()),
  export_tuning: RoleAwareExportTuningSchema,
})

const FunctionIndexRecoverySummarySchema = z.object({
  applied: z.boolean(),
  define_from: z.enum(['smart_recover', 'symbols_recover']).nullable(),
  recovered_function_count: z.number().int().nonnegative(),
  recovered_symbol_count: z.number().int().nonnegative(),
  imported_count: z.number().int().nonnegative(),
  function_index_status: z.enum(['ready']).nullable(),
  decompile_status: z.enum(['missing']).nullable(),
  cfg_status: z.enum(['missing']).nullable(),
  recovery_strategy: z.array(z.string()),
  next_steps: z.array(z.string()),
})

const PreflightSummarySchema = z.object({
  binary_profile: BinaryRoleProfileDataSchema.nullable(),
  dll_profile: PreflightDllProfileSchema.nullable(),
  com_profile: PreflightComProfileSchema.nullable(),
  rust_profile: PreflightRustProfileSchema.nullable(),
  function_index_recovery: FunctionIndexRecoverySummarySchema.nullable(),
  role_strategy: RoleAwareStrategySchema.nullable(),
})

const AlternateBackendSummarySchema = z.object({
  rizin: z.any().optional(),
  angr: z.any().optional(),
  retdec: z.any().optional(),
})

function buildReconstructCoverage(params: {
  sampleSize: number
  requestedDepth: z.infer<typeof AnalysisIntentDepthSchema>
  queued: boolean
  selectedPath?: 'native' | 'dotnet'
  degraded?: boolean
  validateBuild: boolean
  runHarness: boolean
  exportSummary?: z.infer<typeof ExportSummarySchema> | null
  stageStatus?: {
    export_primary: 'ok' | 'failed' | 'skipped'
    plan: 'ok' | 'failed' | 'skipped'
  }
}): z.infer<typeof CoverageEnvelopeSchema> {
  const sampleSizeTier = classifySampleSizeTier(params.sampleSize)
  const analysisBudgetProfile = deriveAnalysisBudgetProfile(params.requestedDepth, sampleSizeTier)

  return buildCoverageEnvelope({
    coverageLevel: 'reconstruction',
    completionState: params.queued
      ? 'queued'
      : params.degraded
        ? 'degraded'
        : analysisBudgetProfile === 'deep'
          ? 'completed'
          : 'bounded',
    sampleSizeTier,
    analysisBudgetProfile,
    downgradeReasons: buildBudgetDowngradeReasons({
      requestedDepth: params.requestedDepth,
      sampleSizeTier,
      analysisBudgetProfile,
      extraReasons: [
        !params.validateBuild
          ? 'Build validation was intentionally skipped or bounded for this reconstruction run.'
          : null,
        !params.runHarness
          ? 'Harness execution was intentionally skipped or bounded for this reconstruction run.'
          : null,
      ],
    }),
    coverageGaps: [
      params.queued
        ? {
            domain: 'reconstruction_export',
            status: 'queued',
            reason: 'Reconstruction has been queued but export artifacts are not ready yet.',
          }
        : null,
      !params.validateBuild
        ? {
            domain: 'build_validation',
            status: 'skipped',
            reason: 'Build validation was not requested for this reconstruction run.',
          }
        : null,
      !params.runHarness
        ? {
            domain: 'runtime_verification',
            status: 'skipped',
            reason: 'Harness execution was not requested for this reconstruction run.',
          }
        : null,
      params.degraded
        ? {
            domain: 'reconstruction_export',
            status: 'degraded',
            reason: 'Primary reconstruction path failed or returned degraded artifacts.',
          }
        : null,
      {
        domain: 'dynamic_behavior',
        status: 'missing',
        reason: 'workflow.reconstruct does not verify live runtime behavior by itself.',
      },
    ],
    confidenceByDomain: {
      function_index: params.queued ? 0.2 : 0.7,
      reconstruction:
        params.queued ? 0.15 : params.degraded ? 0.45 : params.exportSummary ? 0.78 : 0.4,
      decompilation: params.queued ? 0.1 : params.selectedPath === 'native' ? 0.7 : 0.6,
      dynamic_behavior: params.runHarness ? 0.35 : 0.1,
    },
    knownFindings: [
      params.selectedPath ? `Reconstruction routed through ${params.selectedPath}.` : null,
      !params.queued && params.exportSummary?.export_root
        ? `Export artifacts were written under ${params.exportSummary.export_root}.`
        : null,
    ],
    suspectedFindings: [
      params.degraded ? 'Primary reconstruction path required degraded or fallback handling.' : null,
      params.stageStatus?.plan === 'failed' ? 'Planning quality was degraded before export.' : null,
    ],
    unverifiedAreas: [
      !params.validateBuild ? 'Build validation remains unverified.' : null,
      !params.runHarness ? 'Harness or runtime verification remains unverified.' : null,
      'Live runtime behavior remains unverified outside reconstruction artifacts.',
    ],
    upgradePaths: [
      {
        tool: params.queued ? 'task.status' : 'artifact.read',
        purpose: params.queued
          ? 'Wait for reconstruction completion.'
          : 'Inspect reconstructed artifacts and unresolved gaps.',
        closes_gaps: params.queued ? ['reconstruction_export'] : ['reconstruction_export'],
        expected_coverage_gain: params.queued
          ? 'Returns completed reconstruction output when the queued job finishes.'
          : 'Shows exact export manifests, gaps, and validation notes.',
        cost_tier: 'low',
      },
      !params.runHarness
        ? {
            tool: 'sandbox.execute',
            purpose: 'Add bounded runtime confirmation after reconstruction.',
            closes_gaps: ['runtime_verification', 'dynamic_behavior'],
            expected_coverage_gain: 'Provides execution-oriented evidence that reconstruction alone cannot confirm.',
            cost_tier: 'medium',
          }
        : null,
    ],
  })
}

const ReconstructQueuedDataSchema = z.object({
  job_id: z.string(),
  status: z.literal('queued'),
  tool: z.literal(TOOL_NAME),
  sample_id: z.string(),
  requested_path: z.enum(['auto', 'native', 'dotnet']),
  progress: z.number().int().min(0).max(100),
  polling_guidance: PollingGuidanceSchema.nullable(),
  result_mode: z.literal('queued'),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
}).extend(CoverageEnvelopeSchema.shape).extend(BackendRoutingMetadataSchema.shape)

const ReconstructCompletedDataSchema = z.object({
  sample_id: z.string(),
  selected_path: z.enum(['native', 'dotnet']),
  degraded: z.boolean(),
  stage_status: z.object({
    runtime: z.enum(['ok', 'failed']),
    preflight_binary_profile: z.enum(['ok', 'failed', 'skipped']),
    preflight_dll_profile: z.enum(['ok', 'failed', 'skipped']),
    preflight_com_profile: z.enum(['ok', 'failed', 'skipped']),
    preflight_rust_profile: z.enum(['ok', 'failed', 'skipped']),
    function_index_recovery: z.enum(['ok', 'failed', 'skipped']),
    plan: z.enum(['ok', 'failed', 'skipped']),
    export_primary: z.enum(['ok', 'failed', 'skipped']),
    export_fallback: z.enum(['ok', 'failed', 'skipped']),
  }),
  provenance: AnalysisProvenanceSchema,
  selection_diffs: AnalysisSelectionDiffSchema.optional(),
  ghidra_execution: GhidraExecutionSummarySchema.nullable().optional(),
  runtime: RuntimeSummarySchema,
  preflight: PreflightSummarySchema.optional(),
  plan: PlanSummarySchema.nullable(),
  export: ExportSummarySchema.nullable(),
  alternate_backends: AlternateBackendSummarySchema.optional(),
  notes: z.array(z.string()),
  result_mode: z.literal('completed'),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
}).extend(CoverageEnvelopeSchema.shape).extend(BackendRoutingMetadataSchema.shape)

export const ReconstructWorkflowOutputSchema = z.object({
  ok: z.boolean(),
  data: z.union([ReconstructCompletedDataSchema, ReconstructQueuedDataSchema]).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  setup_actions: z.array(SetupActionSchema).optional(),
  required_user_inputs: z.array(RequiredUserInputSchema).optional(),
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

export type ReconstructWorkflowOutput = z.infer<typeof ReconstructWorkflowOutputSchema>

export const reconstructWorkflowToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Run the main source-like reconstruction workflow with auto routing, binary/language preflight, optional function-index recovery, planning, export, and cache observability. ' +
    'If the user has not picked a workflow yet, prefer workflow.analyze.auto so the server can route by intent first. ' +
    'Use this after sample registration when you want one orchestrated deep-analysis path instead of calling many leaf tools manually. ' +
    'Do not use this as a health check or before the sample is ingested. ' +
    'Read coverage_level, completion_state, coverage_gaps, and upgrade_paths to distinguish queued, bounded, degraded, and fully completed reconstruction output. ' +
    '\n\nDecision guide:\n' +
    '- Use when: you want one-shot reconstruction and export across native or .NET paths.\n' +
    '- Do not use when: you only need quick profiling, string/Xref correlation, or a single leaf artifact.\n' +
    '- Intermediate step: use analysis.context.link, code.xrefs.analyze, or code.function.cfg(format=dot|mermaid) first when you need bounded indicator-to-function or graph context before paying reconstruction cost.\n' +
    '- Typical next step: if queued, poll task.status(job_id); if completed, inspect export artifacts or continue with module/function review tools.\n' +
    '- Common mistake: starting reconstruct before the sample exists or without waiting for queued completion.',
  inputSchema: ReconstructWorkflowInputSchema,
  outputSchema: ReconstructWorkflowOutputSchema,
}

interface RuntimeSuspected {
  runtime: string
  confidence: number
  evidence: string[]
}

interface RuntimeDetectData {
  is_dotnet?: boolean
  dotnet_version?: string | null
  target_framework?: string | null
  suspected?: RuntimeSuspected[]
}

interface PlanData {
  feasibility: 'high' | 'medium' | 'low'
  confidence: number
  restoration_expectation: string
  blockers: string[]
  recommendations: string[]
}

interface NativeExportData {
  export_root: string
  manifest_path: string
  gaps_path: string
  notes_path?: string
  build_validation?: {
    status?: 'passed' | 'failed' | 'skipped' | 'unavailable'
    log_path?: string | null
    executable_path?: string | null
  }
  harness_validation?: {
    status?: 'passed' | 'failed' | 'skipped' | 'unavailable'
    log_path?: string | null
  }
  module_count: number
  unresolved_count: number
  binary_profile?: z.infer<typeof BinaryProfileSchema>
}

interface DotNetExportData {
  export_root: string
  csproj_path: string
  readme_path: string
  metadata_path: string | null
  reverse_notes_path: string | null
  fallback_notes_path: string | null
  degraded_mode?: boolean
  build_validation?: {
    status?: 'passed' | 'failed' | 'skipped' | 'unavailable'
  }
  managed_profile?: z.infer<typeof ManagedProfileSchema> | null
  classes: unknown[]
}

interface RustBinaryAnalyzeData extends z.infer<typeof RustBinaryAnalyzeDataSchema> {}
interface DllExportProfileData extends z.infer<typeof DllExportProfileDataSchema> {}
interface ComRoleProfileData extends z.infer<typeof ComRoleProfileDataSchema> {}

interface FunctionIndexRecoveryData {
  sample_id: string
  define_from: 'smart_recover' | 'symbols_recover'
  recovered_function_count: number
  recovered_symbol_count: number
  imported_count: number
  function_index_status: 'ready'
  decompile_status: 'missing'
  cfg_status: 'missing'
  recovery_strategy: string[]
  next_steps: string[]
}

interface ReconstructWorkflowDependencies {
  runtimeDetectHandler?: (args: ToolArgs) => Promise<WorkerResult>
  planHandler?: (args: ToolArgs) => Promise<WorkerResult>
  nativeExportHandler?: (args: ToolArgs) => Promise<WorkerResult>
  dotnetExportHandler?: (args: ToolArgs) => Promise<WorkerResult>
  binaryRoleProfileHandler?: (args: ToolArgs) => Promise<WorkerResult>
  dllExportProfileHandler?: (args: ToolArgs) => Promise<WorkerResult>
  comRoleProfileHandler?: (args: ToolArgs) => Promise<WorkerResult>
  rustBinaryAnalyzeHandler?: (args: ToolArgs) => Promise<WorkerResult>
  functionIndexRecoverHandler?: (args: ToolArgs) => Promise<WorkerResult>
  rizinAnalyzeHandler?: (args: ToolArgs) => Promise<WorkerResult>
  angrAnalyzeHandler?: (args: ToolArgs) => Promise<WorkerResult>
  retdecDecompileHandler?: (args: ToolArgs) => Promise<WorkerResult>
  resolveBackends?: typeof resolveAnalysisBackends
}

function normalizeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

function pickPrimaryRuntime(runtimeData?: RuntimeDetectData): string | null {
  const suspected = runtimeData?.suspected || []
  if (suspected.length === 0) {
    return null
  }
  const sorted = [...suspected].sort((a, b) => b.confidence - a.confidence)
  return sorted[0].runtime || null
}

function summarizeRuntime(runtimeData?: RuntimeDetectData) {
  return {
    is_dotnet: runtimeData?.is_dotnet ?? null,
    dotnet_version: runtimeData?.dotnet_version ?? null,
    target_framework: runtimeData?.target_framework ?? null,
    primary_runtime: pickPrimaryRuntime(runtimeData),
  }
}

function pickLatestAnalysisMarker(
  analyses: Array<{
    stage: string
    backend: string
    status: string
    started_at: string | null
    finished_at: string | null
  }>,
  predicate: (analysis: { stage: string; backend: string }) => boolean
) {
  const sorted = [...analyses]
    .filter(predicate)
    .sort((left, right) => {
      const leftTs = new Date(left.finished_at || left.started_at || 0).getTime()
      const rightTs = new Date(right.finished_at || right.started_at || 0).getTime()
      return rightTs - leftTs
    })

  const selected = sorted[0]
  if (!selected) {
    return null
  }

  return {
    stage: selected.stage,
    backend: selected.backend,
    status: selected.status,
    finished_at: selected.finished_at || selected.started_at || null,
  }
}

function summarizeRustPreflight(data: RustBinaryAnalyzeData) {
  return {
    suspected_rust: data.suspected_rust,
    confidence: data.confidence,
    primary_runtime: data.primary_runtime,
    runtime_hints: data.runtime_hints,
    crate_hints: data.crate_hints,
    cargo_paths: data.cargo_paths,
    recovered_function_count: data.recovered_function_count,
    recovered_symbol_count: data.recovered_symbol_count,
    importable_with_code_functions_define: data.importable_with_code_functions_define,
    analysis_priorities: data.analysis_priorities,
  }
}

function summarizeDllPreflight(data: DllExportProfileData) {
  return {
    library_like: data.library_like,
    role_confidence: data.role_confidence,
    likely_entry_model: data.likely_entry_model,
    dll_entry_hints: data.dll_entry_hints,
    dispatch_model: data.export_dispatch_profile.likely_dispatch_model,
    host_hints: data.host_interaction_profile.host_hints,
    lifecycle_surface: data.lifecycle_surface,
    class_factory_surface: data.class_factory_surface,
    callback_surface: data.callback_surface,
    analysis_priorities: data.analysis_priorities,
  }
}

function summarizeComPreflight(data: ComRoleProfileData) {
  return {
    likely_com_server: data.likely_com_server,
    com_confidence: data.com_confidence,
    activation_model: data.activation_model,
    class_factory_exports: data.class_factory_exports,
    registration_exports: data.registration_exports,
    clsid_strings: data.clsid_strings,
    progid_strings: data.progid_strings,
    interface_hints: data.interface_hints,
    class_factory_surface: data.class_factory_surface,
    activation_steps: data.activation_steps,
    analysis_priorities: data.analysis_priorities,
  }
}

function buildRoleAwareStrategy(args: {
  runtimeData?: RuntimeDetectData
  binaryProfile: z.infer<typeof BinaryRoleProfileDataSchema> | null
  dllProfile: ReturnType<typeof summarizeDllPreflight> | null
  comProfile: ReturnType<typeof summarizeComPreflight> | null
  rustProfile: ReturnType<typeof summarizeRustPreflight> | null
}) {
  const rationale: string[] = []
  const focusAreas = new Set<string>()
  const priorityOrder = new Set<string>()
  let targetRole = 'native_executable'
  const exportTuning = {
    topk: 16,
    module_limit: 8,
    min_module_size: 1,
    include_imports: true,
    include_strings: true,
  }

  if (args.runtimeData?.is_dotnet) {
    targetRole = 'managed_assembly'
    rationale.push('runtime.detect reported CLR/.NET metadata')
    focusAreas.add('managed_metadata_and_il')
  } else if (args.comProfile?.likely_com_server) {
    targetRole = 'com_server'
    rationale.push(`COM preflight suggests activation model ${args.comProfile.activation_model}`)
    focusAreas.add('class_factory_and_registration')
    exportTuning.topk = 20
    exportTuning.module_limit = 10
  } else if (args.dllProfile?.library_like && args.dllProfile.dispatch_model !== 'none') {
    targetRole = 'export_dispatch_dll'
    rationale.push(`DLL preflight suggests dispatch model ${args.dllProfile.dispatch_model}`)
    focusAreas.add('export_dispatch_surface')
    exportTuning.topk = 18
    exportTuning.module_limit = 10
  } else if (args.dllProfile?.library_like && args.dllProfile.host_hints.length > 0) {
    targetRole = 'hosted_plugin_or_service_dll'
    rationale.push('DLL preflight suggests hosted/plugin lifecycle')
    focusAreas.add('host_callbacks_and_attach_detach')
    exportTuning.topk = 18
    exportTuning.module_limit = 9
  } else if (args.dllProfile?.library_like) {
    targetRole = 'dll_library'
    rationale.push(`DLL preflight suggests entry model ${args.dllProfile.likely_entry_model}`)
    focusAreas.add('dllmain_and_export_surface')
    exportTuning.topk = 18
    exportTuning.module_limit = 9
  } else if (args.rustProfile?.suspected_rust) {
    targetRole = 'native_rust_executable'
    rationale.push(`Rust preflight confidence ${args.rustProfile.confidence.toFixed(2)}`)
    focusAreas.add('pdata_recovery_and_runtime_wrappers')
    exportTuning.topk = 20
    exportTuning.module_limit = 9
  } else if (args.binaryProfile?.indicators.service_binary.likely) {
    targetRole = 'service_binary'
    rationale.push('binary.role.profile found service-oriented indicators')
    focusAreas.add('service_entrypoints_and_hooks')
    exportTuning.topk = 18
    exportTuning.module_limit = 9
  }

  for (const item of args.binaryProfile?.analysis_priorities || []) {
    priorityOrder.add(item)
  }
  for (const item of args.dllProfile?.analysis_priorities || []) {
    priorityOrder.add(item)
  }
  for (const item of args.comProfile?.analysis_priorities || []) {
    priorityOrder.add(item)
  }
  for (const item of args.rustProfile?.analysis_priorities || []) {
    priorityOrder.add(item)
  }

  if (args.comProfile?.class_factory_exports.length) {
    focusAreas.add('class_factory_exports')
  }
  if (args.dllProfile?.dll_entry_hints.length) {
    focusAreas.add('dll_entry_lifecycle')
  }
  if (args.binaryProfile?.export_dispatch_profile.likely_dispatch_model !== 'none') {
    focusAreas.add('dispatch_model_reconstruction')
  }
  if (args.binaryProfile?.host_interaction_profile.likely_hosted) {
    focusAreas.add('host_interaction_model')
  }

  return {
    target_role: targetRole,
    priority_order: Array.from(priorityOrder),
    focus_areas: Array.from(focusAreas),
    rationale,
    export_tuning: exportTuning,
  }
}

function summarizeFunctionIndexRecovery(data: FunctionIndexRecoveryData) {
  return {
    applied: true,
    define_from: data.define_from,
    recovered_function_count: data.recovered_function_count,
    recovered_symbol_count: data.recovered_symbol_count,
    imported_count: data.imported_count,
    function_index_status: data.function_index_status,
    decompile_status: data.decompile_status,
    cfg_status: data.cfg_status,
    recovery_strategy: data.recovery_strategy,
    next_steps: data.next_steps,
  }
}

function summarizeAlternateBackendData(data: unknown) {
  return data ?? null
}

export function createReconstructWorkflowHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies?: ReconstructWorkflowDependencies,
  jobQueue?: JobQueue
) {
  const runtimeDetectHandler =
    dependencies?.runtimeDetectHandler ||
    createRuntimeDetectHandler(workspaceManager, database, cacheManager)
  const planHandler =
    dependencies?.planHandler ||
    createCodeReconstructPlanHandler(workspaceManager, database, cacheManager)
  const nativeExportHandler =
    dependencies?.nativeExportHandler ||
    createCodeReconstructExportHandler(workspaceManager, database, cacheManager)
  const dotnetExportHandler =
    dependencies?.dotnetExportHandler ||
    createDotNetReconstructExportHandler(workspaceManager, database, cacheManager)
  const binaryRoleProfileHandler =
    dependencies?.binaryRoleProfileHandler ||
    createBinaryRoleProfileHandler(workspaceManager, database, cacheManager)
  const dllExportProfileHandler =
    dependencies?.dllExportProfileHandler ||
    createDllExportProfileHandler(workspaceManager, database, cacheManager, {
      binaryRoleProfileHandler,
    })
  const comRoleProfileHandler =
    dependencies?.comRoleProfileHandler ||
    createComRoleProfileHandler(workspaceManager, database, cacheManager, {
      binaryRoleProfileHandler,
    })
  const rustBinaryAnalyzeHandler =
    dependencies?.rustBinaryAnalyzeHandler ||
    createRustBinaryAnalyzeHandler(workspaceManager, database, cacheManager)
  const functionIndexRecoverHandler =
    dependencies?.functionIndexRecoverHandler ||
    createFunctionIndexRecoverWorkflowHandler(workspaceManager, database, cacheManager)
  const rizinAnalyzeHandler =
    dependencies?.rizinAnalyzeHandler ||
    createRizinAnalyzeHandler(workspaceManager, database)
  const angrAnalyzeHandler =
    dependencies?.angrAnalyzeHandler ||
    createAngrAnalyzeHandler(workspaceManager, database)
  const retdecDecompileHandler =
    dependencies?.retdecDecompileHandler ||
    createRetDecDecompileHandler(workspaceManager, database)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = ReconstructWorkflowInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }
      const sampleSizeTier = classifySampleSizeTier(sample.size || 0)
      const analysisBudgetProfile = deriveAnalysisBudgetProfile(input.depth, sampleSizeTier)

      if (jobQueue) {
        const jobTimeoutMs = Math.max(
          input.build_timeout_ms + input.run_timeout_ms + 45 * 60 * 1000,
          60 * 60 * 1000
        )
        const queuedRoutingMetadata = buildIntentBackendPlan({
          goal: 'reverse',
          depth: input.depth,
          backendPolicy: input.backend_policy,
          allowTransformations: input.allow_transformations,
          readiness: (dependencies?.resolveBackends || resolveAnalysisBackends)(),
        })
        const jobId = jobQueue.enqueue({
          type: 'static',
          tool: TOOL_NAME,
          sampleId: input.sample_id,
          args: input,
          priority: 5,
          timeout: jobTimeoutMs,
          retryPolicy: {
            maxRetries: 1,
            backoffMs: 5000,
            retryableErrors: ['E_TIMEOUT', 'E_RESOURCE_EXHAUSTED'],
          },
        })

        return {
          ok: true,
          data: mergeRoutingMetadata(
            mergeCoverageEnvelope(
              {
                job_id: jobId,
                status: 'queued',
                tool: TOOL_NAME,
                sample_id: input.sample_id,
                requested_path: input.path,
                progress: 0,
                polling_guidance: buildPollingGuidance({
                  tool: TOOL_NAME,
                  status: 'queued',
                  progress: 0,
                  timeout_ms: jobTimeoutMs,
                }),
                result_mode: 'queued',
                recommended_next_tools: ['task.status'],
                next_actions: [
                  'Wait for approximately the recommended polling interval before checking task.status again.',
                  'Call task.status with the returned job_id until the reconstruct workflow completes, fails, or is cancelled.',
                ],
              },
              buildReconstructCoverage({
                sampleSize: sample.size || 0,
                requestedDepth: input.depth,
                queued: true,
                validateBuild: input.validate_build,
                runHarness: input.run_harness,
              })
            ),
            queuedRoutingMetadata
          ),
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const warnings: string[] = []
      const notes: string[] = []
      let setupActions = [] as z.infer<typeof SetupActionSchema>[]
      let requiredUserInputs = [] as z.infer<typeof RequiredUserInputSchema>[]
      const stageStatus = {
        runtime: 'failed' as 'ok' | 'failed',
        preflight_binary_profile: 'skipped' as 'ok' | 'failed' | 'skipped',
        preflight_dll_profile: 'skipped' as 'ok' | 'failed' | 'skipped',
        preflight_com_profile: 'skipped' as 'ok' | 'failed' | 'skipped',
        preflight_rust_profile: 'skipped' as 'ok' | 'failed' | 'skipped',
        function_index_recovery: 'skipped' as 'ok' | 'failed' | 'skipped',
        plan: 'skipped' as 'ok' | 'failed' | 'skipped',
        export_primary: 'skipped' as 'ok' | 'failed' | 'skipped',
        export_fallback: 'skipped' as 'ok' | 'failed' | 'skipped',
      }

      const runtimeResult = await runtimeDetectHandler({ sample_id: input.sample_id })
      const runtimeData =
        runtimeResult.ok && runtimeResult.data
          ? (runtimeResult.data as RuntimeDetectData)
          : undefined

      if (!runtimeResult.ok) {
        warnings.push(
          `runtime.detect unavailable: ${(runtimeResult.errors || ['unknown error']).join('; ')}`
        )
      } else if (runtimeResult.warnings && runtimeResult.warnings.length > 0) {
        warnings.push(...runtimeResult.warnings.map((item) => `runtime: ${item}`))
        stageStatus.runtime = 'ok'
      } else {
        stageStatus.runtime = 'ok'
      }
      {
        const setupGuidance = collectSetupGuidanceFromWorkerResult(runtimeResult)
        setupActions = mergeSetupActions(setupActions, setupGuidance.setupActions)
        requiredUserInputs = mergeRequiredUserInputs(
          requiredUserInputs,
          setupGuidance.requiredUserInputs
        )
      }

      let selectedPath: 'native' | 'dotnet'
      if (input.path === 'auto') {
        selectedPath = runtimeData?.is_dotnet ? 'dotnet' : 'native'
      } else {
        selectedPath = input.path
      }

      if (input.path === 'dotnet' && runtimeData?.is_dotnet === false) {
        return {
          ok: false,
          errors: ['Requested dotnet path, but runtime.detect does not recognize the sample as .NET.'],
          warnings:
            runtimeData?.suspected && runtimeData.suspected.length > 0
              ? [
                  `runtime.detect suspected: ${runtimeData.suspected
                    .map((item) => `${item.runtime}(${item.confidence.toFixed(2)})`)
                    .join(', ')}`,
                ]
              : undefined,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      if (selectedPath === 'native' && runtimeData?.is_dotnet) {
        warnings.push('Selected native path while runtime indicates .NET; forcing native as requested.')
      }

      let analyses = database.findAnalysesBySample(input.sample_id)
      let completedGhidraAnalysis = findBestGhidraAnalysis(analyses, 'function_index')
      const hasReadyGhidraFunctionIndex = Boolean(
        completedGhidraAnalysis && isGhidraCapabilityReady(completedGhidraAnalysis, 'function_index')
      )
      const hasFunctionDefinitionIndex = analyses.some(
        (analysis) => analysis.stage === 'function_definition' && analysis.status === 'done'
      )

      let binaryProfileData: z.infer<typeof BinaryRoleProfileDataSchema> | null = null
      let dllProfileData: ReturnType<typeof summarizeDllPreflight> | null = null
      let comProfileData: ReturnType<typeof summarizeComPreflight> | null = null
      let rustProfileData: RustBinaryAnalyzeData | null = null
      let functionIndexRecoveryData: ReturnType<typeof summarizeFunctionIndexRecovery> | null = null
      let functionIndexRecoveryApplied = false
      let roleStrategy: ReturnType<typeof buildRoleAwareStrategy> | null = null

      if (input.include_preflight) {
        const binaryProfileResult = await binaryRoleProfileHandler({
          sample_id: input.sample_id,
          force_refresh: !input.reuse_cached,
        })

        if (binaryProfileResult.ok && binaryProfileResult.data) {
          binaryProfileData = binaryProfileResult.data as z.infer<typeof BinaryRoleProfileDataSchema>
          stageStatus.preflight_binary_profile = 'ok'
        } else {
          stageStatus.preflight_binary_profile = 'failed'
          warnings.push(
            `binary.role.profile unavailable: ${(binaryProfileResult.errors || ['unknown error']).join('; ')}`
          )
        }

        if (binaryProfileResult.warnings?.length) {
          warnings.push(...binaryProfileResult.warnings.map((item) => `binary.role.profile: ${item}`))
        }
        {
          const setupGuidance = collectSetupGuidanceFromWorkerResult(binaryProfileResult)
          setupActions = mergeSetupActions(setupActions, setupGuidance.setupActions)
          requiredUserInputs = mergeRequiredUserInputs(
            requiredUserInputs,
            setupGuidance.requiredUserInputs
          )
        }
      }

      if (selectedPath === 'native' && !runtimeData?.is_dotnet && input.include_preflight) {
        const dllProfileResult = await dllExportProfileHandler({
          sample_id: input.sample_id,
          force_refresh: !input.reuse_cached,
        })

        if (dllProfileResult.ok && dllProfileResult.data) {
          dllProfileData = summarizeDllPreflight(dllProfileResult.data as DllExportProfileData)
          stageStatus.preflight_dll_profile = 'ok'
        } else {
          stageStatus.preflight_dll_profile = 'failed'
          warnings.push(
            `dll.export.profile unavailable: ${(dllProfileResult.errors || ['unknown error']).join('; ')}`
          )
        }

        if (dllProfileResult.warnings?.length) {
          warnings.push(...dllProfileResult.warnings.map((item) => `dll.export.profile: ${item}`))
        }
        {
          const setupGuidance = collectSetupGuidanceFromWorkerResult(dllProfileResult)
          setupActions = mergeSetupActions(setupActions, setupGuidance.setupActions)
          requiredUserInputs = mergeRequiredUserInputs(
            requiredUserInputs,
            setupGuidance.requiredUserInputs
          )
        }

        const comProfileResult = await comRoleProfileHandler({
          sample_id: input.sample_id,
          force_refresh: !input.reuse_cached,
        })

        if (comProfileResult.ok && comProfileResult.data) {
          comProfileData = summarizeComPreflight(comProfileResult.data as ComRoleProfileData)
          stageStatus.preflight_com_profile = 'ok'
        } else {
          stageStatus.preflight_com_profile = 'failed'
          warnings.push(
            `com.role.profile unavailable: ${(comProfileResult.errors || ['unknown error']).join('; ')}`
          )
        }

        if (comProfileResult.warnings?.length) {
          warnings.push(...comProfileResult.warnings.map((item) => `com.role.profile: ${item}`))
        }
        {
          const setupGuidance = collectSetupGuidanceFromWorkerResult(comProfileResult)
          setupActions = mergeSetupActions(setupActions, setupGuidance.setupActions)
          requiredUserInputs = mergeRequiredUserInputs(
            requiredUserInputs,
            setupGuidance.requiredUserInputs
          )
        }
      }

      if (selectedPath === 'native' && !runtimeData?.is_dotnet && input.include_preflight) {
        const rustProfileResult = await rustBinaryAnalyzeHandler({
          sample_id: input.sample_id,
          force_refresh: !input.reuse_cached,
        })

        if (rustProfileResult.ok && rustProfileResult.data) {
          rustProfileData = rustProfileResult.data as RustBinaryAnalyzeData
          stageStatus.preflight_rust_profile = 'ok'
        } else {
          stageStatus.preflight_rust_profile = 'failed'
          warnings.push(
            `rust_binary.analyze unavailable: ${(rustProfileResult.errors || ['unknown error']).join('; ')}`
          )
        }

        if (rustProfileResult.warnings?.length) {
          warnings.push(...rustProfileResult.warnings.map((item) => `rust_binary.analyze: ${item}`))
        }
        {
          const setupGuidance = collectSetupGuidanceFromWorkerResult(rustProfileResult)
          setupActions = mergeSetupActions(setupActions, setupGuidance.setupActions)
          requiredUserInputs = mergeRequiredUserInputs(
            requiredUserInputs,
            setupGuidance.requiredUserInputs
          )
        }
      }

      if (input.include_preflight) {
        roleStrategy = buildRoleAwareStrategy({
          runtimeData,
          binaryProfile: binaryProfileData,
          dllProfile: dllProfileData,
          comProfile: comProfileData,
          rustProfile: rustProfileData ? summarizeRustPreflight(rustProfileData) : null,
        })
      }

      if (
        selectedPath === 'native' &&
        input.auto_recover_function_index &&
        !hasReadyGhidraFunctionIndex &&
        !hasFunctionDefinitionIndex
      ) {
        const functionIndexRecoverResult = await functionIndexRecoverHandler({
          sample_id: input.sample_id,
          define_from: 'auto',
          include_rank_preview: false,
          persist_artifact: true,
          register_analysis: true,
          replace_all: true,
          force_refresh: !input.reuse_cached,
        })

        if (functionIndexRecoverResult.ok && functionIndexRecoverResult.data) {
          functionIndexRecoveryData = summarizeFunctionIndexRecovery(
            functionIndexRecoverResult.data as FunctionIndexRecoveryData
          )
          functionIndexRecoveryApplied = true
          stageStatus.function_index_recovery = 'ok'
          analyses = database.findAnalysesBySample(input.sample_id)
          completedGhidraAnalysis = findBestGhidraAnalysis(analyses, 'function_index')
        } else {
          stageStatus.function_index_recovery = 'failed'
          warnings.push(
            `workflow.function_index_recover unavailable: ${(functionIndexRecoverResult.errors || ['unknown error']).join('; ')}`
          )
        }

        if (functionIndexRecoverResult.warnings?.length) {
          warnings.push(
            ...functionIndexRecoverResult.warnings.map((item) => `workflow.function_index_recover: ${item}`)
          )
        }
        {
          const setupGuidance = collectSetupGuidanceFromWorkerResult(functionIndexRecoverResult)
          setupActions = mergeSetupActions(setupActions, setupGuidance.setupActions)
          requiredUserInputs = mergeRequiredUserInputs(
            requiredUserInputs,
            setupGuidance.requiredUserInputs
          )
        }
      }

      const dynamicEvidence = await loadDynamicTraceEvidence(workspaceManager, database, input.sample_id, {
        evidenceScope: input.evidence_scope,
        sessionTag: input.evidence_session_tag,
      })
      const semanticNameIndex = await loadSemanticNameSuggestionIndex(
        workspaceManager,
        database,
        input.sample_id,
        {
          scope: input.semantic_scope,
          sessionTag: input.semantic_session_tag,
        }
      )
      const semanticExplanationIndex = await loadSemanticFunctionExplanationIndex(
        workspaceManager,
        database,
        input.sample_id,
        {
          scope: input.semantic_scope,
          sessionTag: input.semantic_session_tag,
        }
      )
      const provenance = {
        runtime: buildRuntimeArtifactProvenance(
          dynamicEvidence,
          input.evidence_scope,
          input.evidence_session_tag
        ),
        semantic_names: buildSemanticArtifactProvenance(
          'semantic naming artifacts',
          semanticNameIndex,
          input.semantic_scope,
          input.semantic_session_tag
        ),
        semantic_explanations: buildSemanticArtifactProvenance(
          'semantic explanation artifacts',
          semanticExplanationIndex,
          input.semantic_scope,
          input.semantic_session_tag
        ),
      }
      const selectionDiffs: z.infer<typeof AnalysisSelectionDiffSchema> = {}
      if (input.compare_evidence_scope) {
        const baselineDynamicEvidence = await loadDynamicTraceEvidence(
          workspaceManager,
          database,
          input.sample_id,
          {
            evidenceScope: input.compare_evidence_scope,
            sessionTag: input.compare_evidence_session_tag,
          }
        )
        selectionDiffs.runtime = buildArtifactSelectionDiff(
          'runtime',
          provenance.runtime,
          buildRuntimeArtifactProvenance(
            baselineDynamicEvidence,
            input.compare_evidence_scope,
            input.compare_evidence_session_tag
          )
        )
      }
      if (input.compare_semantic_scope) {
        const baselineSemanticNameIndex = await loadSemanticNameSuggestionIndex(
          workspaceManager,
          database,
          input.sample_id,
          {
            scope: input.compare_semantic_scope,
            sessionTag: input.compare_semantic_session_tag,
          }
        )
        const baselineSemanticExplanationIndex = await loadSemanticFunctionExplanationIndex(
          workspaceManager,
          database,
          input.sample_id,
          {
            scope: input.compare_semantic_scope,
            sessionTag: input.compare_semantic_session_tag,
          }
        )
        selectionDiffs.semantic_names = buildArtifactSelectionDiff(
          'semantic_names',
          provenance.semantic_names!,
          buildSemanticArtifactProvenance(
            'semantic naming artifacts',
            baselineSemanticNameIndex,
            input.compare_semantic_scope,
            input.compare_semantic_session_tag
          )
        )
        selectionDiffs.semantic_explanations = buildArtifactSelectionDiff(
          'semantic_explanations',
          provenance.semantic_explanations!,
          buildSemanticArtifactProvenance(
            'semantic explanation artifacts',
            baselineSemanticExplanationIndex,
            input.compare_semantic_scope,
            input.compare_semantic_session_tag
          )
        )
      }
      const functionDefinitionMarker = pickLatestAnalysisMarker(
        analyses,
        (analysis) => analysis.stage === 'function_definition'
      )
      const ghidraExecution = buildGhidraExecutionSummary(analyses)
      const analysisMarker = JSON.stringify({
        ghidra_function_index: completedGhidraAnalysis
          ? {
              id: completedGhidraAnalysis.id,
              status: completedGhidraAnalysis.status,
              finished_at:
                completedGhidraAnalysis.finished_at || completedGhidraAnalysis.started_at || null,
            }
          : null,
        function_definition: functionDefinitionMarker,
      })

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          path: input.path,
          selected_path: selectedPath,
          topk: input.topk,
          export_name: input.export_name || null,
          validate_build: input.validate_build,
          run_harness: input.run_harness,
          compiler_path: input.compiler_path || null,
          build_timeout_ms: input.build_timeout_ms,
          run_timeout_ms: input.run_timeout_ms,
          evidence_scope: input.evidence_scope,
          evidence_session_tag: input.evidence_session_tag || null,
          semantic_scope: input.semantic_scope,
          semantic_session_tag: input.semantic_session_tag || null,
          compare_evidence_scope: input.compare_evidence_scope || null,
          compare_evidence_session_tag: input.compare_evidence_session_tag || null,
          compare_semantic_scope: input.compare_semantic_scope || null,
          compare_semantic_session_tag: input.compare_semantic_session_tag || null,
          include_preflight: input.include_preflight,
          auto_recover_function_index: input.auto_recover_function_index,
          include_plan: input.include_plan,
          include_obfuscation_fallback: input.include_obfuscation_fallback,
          fallback_on_error: input.fallback_on_error,
          allow_partial: input.allow_partial,
          runtime_is_dotnet: runtimeData?.is_dotnet ?? null,
          runtime_primary: pickPrimaryRuntime(runtimeData),
          runtime_dotnet_version: runtimeData?.dotnet_version ?? null,
          runtime_target_framework: runtimeData?.target_framework ?? null,
          analysis_marker: analysisMarker,
        },
      })

      if (input.reuse_cached) {
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

      let planSummary: PlanData | null = null
      if (input.include_plan) {
        const planResult = await planHandler({
          sample_id: input.sample_id,
          target_language: selectedPath === 'dotnet' ? 'csharp' : 'c',
          depth: 'standard',
          include_decompiler: true,
          include_strings: true,
        })

        if (planResult.ok && planResult.data) {
          const data = planResult.data as PlanData
          planSummary = {
            feasibility: data.feasibility,
            confidence: data.confidence,
            restoration_expectation: data.restoration_expectation,
            blockers: data.blockers || [],
            recommendations: data.recommendations || [],
          }
          stageStatus.plan = 'ok'
        } else {
          warnings.push(`plan unavailable: ${(planResult.errors || ['unknown error']).join('; ')}`)
          stageStatus.plan = 'failed'
        }

        if (planResult.warnings && planResult.warnings.length > 0) {
          warnings.push(...planResult.warnings.map((item) => `plan: ${item}`))
        }
        {
          const setupGuidance = collectSetupGuidanceFromWorkerResult(planResult)
          setupActions = mergeSetupActions(setupActions, setupGuidance.setupActions)
          requiredUserInputs = mergeRequiredUserInputs(
            requiredUserInputs,
            setupGuidance.requiredUserInputs
          )
        }
      }

      let exportSummary: z.infer<typeof ExportSummarySchema> | null = null
      let artifacts = [] as unknown[]
      const primaryPath = selectedPath
      const fallbackPath: 'native' | 'dotnet' = primaryPath === 'dotnet' ? 'native' : 'dotnet'

      type ExportRunSuccess = {
        ok: true
        warnings: string[]
        artifacts: unknown[]
        setupGuidance: {
          setupActions: z.infer<typeof SetupActionSchema>[]
          requiredUserInputs: z.infer<typeof RequiredUserInputSchema>[]
        }
        summary: z.infer<typeof ExportSummarySchema>
      }
      type ExportRunFailure = {
        ok: false
        errors: string[]
        warnings: string[]
        setupGuidance: {
          setupActions: z.infer<typeof SetupActionSchema>[]
          requiredUserInputs: z.infer<typeof RequiredUserInputSchema>[]
        }
      }
      type ExportRunResult = ExportRunSuccess | ExportRunFailure
      const nativeExportTuning = roleStrategy?.export_tuning || {
        topk: Math.max(input.topk, 16),
        module_limit: 8,
        min_module_size: 1,
        include_imports: true,
        include_strings: true,
      }

      const runExport = async (pathToRun: 'native' | 'dotnet'): Promise<ExportRunResult> => {
        if (pathToRun === 'dotnet') {
          const dotnetResult = await dotnetExportHandler({
            sample_id: input.sample_id,
            topk: input.topk,
            export_name: input.export_name,
            include_obfuscation_fallback: input.include_obfuscation_fallback,
            evidence_scope: input.evidence_scope,
            evidence_session_tag: input.evidence_session_tag,
            reuse_cached: input.reuse_cached && !functionIndexRecoveryApplied,
          })
          if (!dotnetResult.ok || !dotnetResult.data) {
            return {
              ok: false,
              errors: dotnetResult.errors || ['dotnet.reconstruct.export failed'],
              warnings: dotnetResult.warnings || [],
              setupGuidance: collectSetupGuidanceFromWorkerResult(dotnetResult),
            }
          }

          const data = dotnetResult.data as DotNetExportData
          return {
            ok: true,
            warnings: dotnetResult.warnings || [],
            artifacts: dotnetResult.artifacts || [],
            setupGuidance: collectSetupGuidanceFromWorkerResult(dotnetResult),
            summary: {
              tool: 'dotnet.reconstruct.export' as const,
              export_root: data.export_root,
              manifest_path: null,
              gaps_path: null,
              notes_path: data.reverse_notes_path || null,
              metadata_path: data.metadata_path || null,
              csproj_path: data.csproj_path,
              readme_path: data.readme_path,
              fallback_notes_path: data.fallback_notes_path,
              build_validation_status: data.build_validation?.status || null,
              harness_validation_status: null,
              build_log_path: null,
              harness_log_path: null,
              executable_path: null,
              degraded_mode: data.degraded_mode ?? null,
              module_count: null,
              unresolved_count: null,
              class_count: Array.isArray(data.classes) ? data.classes.length : 0,
              binary_profile: null,
              managed_profile: data.managed_profile || null,
            },
          }
        }

        const nativeResult = await nativeExportHandler({
          sample_id: input.sample_id,
          topk: Math.max(input.topk, nativeExportTuning.topk),
          module_limit: nativeExportTuning.module_limit,
          min_module_size: nativeExportTuning.min_module_size,
          include_imports: nativeExportTuning.include_imports,
          include_strings: nativeExportTuning.include_strings,
          export_name: input.export_name,
          validate_build: input.validate_build,
          run_harness: input.run_harness,
          compiler_path: input.compiler_path,
          build_timeout_ms: input.build_timeout_ms,
          run_timeout_ms: input.run_timeout_ms,
          evidence_scope: input.evidence_scope,
          evidence_session_tag: input.evidence_session_tag,
          semantic_scope: input.semantic_scope,
          semantic_session_tag: input.semantic_session_tag,
          role_target: roleStrategy?.target_role,
          role_focus_areas: roleStrategy?.focus_areas || [],
          role_priority_order: roleStrategy?.priority_order || [],
          reuse_cached: input.reuse_cached && !functionIndexRecoveryApplied,
        })

        if (!nativeResult.ok || !nativeResult.data) {
          return {
            ok: false,
            errors: nativeResult.errors || ['code.reconstruct.export failed'],
            warnings: nativeResult.warnings || [],
            setupGuidance: collectSetupGuidanceFromWorkerResult(nativeResult),
          }
        }

        const data = nativeResult.data as NativeExportData
        return {
          ok: true,
          warnings: nativeResult.warnings || [],
          artifacts: nativeResult.artifacts || [],
          setupGuidance: collectSetupGuidanceFromWorkerResult(nativeResult),
          summary: {
            tool: 'code.reconstruct.export' as const,
            export_root: data.export_root,
            manifest_path: data.manifest_path,
            gaps_path: data.gaps_path,
            notes_path: data.notes_path || null,
            metadata_path: null,
            csproj_path: null,
            readme_path: null,
            fallback_notes_path: null,
            build_validation_status: data.build_validation?.status || null,
            harness_validation_status: data.harness_validation?.status || null,
            build_log_path: data.build_validation?.log_path || null,
            harness_log_path: data.harness_validation?.log_path || null,
            executable_path: data.build_validation?.executable_path || null,
            degraded_mode: null,
            module_count: data.module_count,
            unresolved_count: data.unresolved_count,
            class_count: null,
            binary_profile: data.binary_profile || null,
            managed_profile: null,
          },
        }
      }

      const primaryExportResult = await runExport(primaryPath)
      if (primaryExportResult.ok) {
        stageStatus.export_primary = 'ok'
        exportSummary = primaryExportResult.summary
        artifacts = primaryExportResult.artifacts || []
        setupActions = mergeSetupActions(setupActions, primaryExportResult.setupGuidance.setupActions)
        requiredUserInputs = mergeRequiredUserInputs(
          requiredUserInputs,
          primaryExportResult.setupGuidance.requiredUserInputs
        )
        if (primaryExportResult.warnings.length > 0) {
          warnings.push(
            ...primaryExportResult.warnings.map((item) =>
              `${primaryPath === 'dotnet' ? 'dotnet_export' : 'native_export'}: ${item}`
            )
          )
        }
      } else {
        stageStatus.export_primary = 'failed'
        setupActions = mergeSetupActions(setupActions, primaryExportResult.setupGuidance.setupActions)
        requiredUserInputs = mergeRequiredUserInputs(
          requiredUserInputs,
          primaryExportResult.setupGuidance.requiredUserInputs
        )
        const primaryExportErrors =
          'errors' in primaryExportResult ? primaryExportResult.errors : ['unknown error']
        warnings.push(
          `primary export(${primaryPath}) failed: ${primaryExportErrors.join('; ')}`
        )
        if (primaryExportResult.warnings.length > 0) {
          warnings.push(
            ...primaryExportResult.warnings.map((item) =>
              `${primaryPath === 'dotnet' ? 'dotnet_export' : 'native_export'}: ${item}`
            )
          )
        }
      }

      if (!exportSummary && input.fallback_on_error) {
        const fallbackExportResult = await runExport(fallbackPath)
        if (fallbackExportResult.ok) {
          stageStatus.export_fallback = 'ok'
          exportSummary = fallbackExportResult.summary
          artifacts = fallbackExportResult.artifacts || []
          setupActions = mergeSetupActions(setupActions, fallbackExportResult.setupGuidance.setupActions)
          requiredUserInputs = mergeRequiredUserInputs(
            requiredUserInputs,
            fallbackExportResult.setupGuidance.requiredUserInputs
          )
          selectedPath = fallbackPath
          notes.push(`Primary export path failed; switched to fallback path: ${fallbackPath}.`)
          if (fallbackExportResult.warnings.length > 0) {
            warnings.push(
              ...fallbackExportResult.warnings.map((item) =>
                `${fallbackPath === 'dotnet' ? 'dotnet_export' : 'native_export'}: ${item}`
              )
            )
          }
        } else {
          stageStatus.export_fallback = 'failed'
          setupActions = mergeSetupActions(setupActions, fallbackExportResult.setupGuidance.setupActions)
          requiredUserInputs = mergeRequiredUserInputs(
            requiredUserInputs,
            fallbackExportResult.setupGuidance.requiredUserInputs
          )
          const fallbackExportErrors =
            'errors' in fallbackExportResult ? fallbackExportResult.errors : ['unknown error']
          warnings.push(
            `fallback export(${fallbackPath}) failed: ${fallbackExportErrors.join('; ')}`
          )
          if (fallbackExportResult.warnings.length > 0) {
            warnings.push(
              ...fallbackExportResult.warnings.map((item) =>
                `${fallbackPath === 'dotnet' ? 'dotnet_export' : 'native_export'}: ${item}`
              )
            )
          }
        }
      }

      if (!exportSummary && !input.fallback_on_error) {
        stageStatus.export_fallback = 'skipped'
      }

      if (!exportSummary && !input.allow_partial) {
        return {
          ok: false,
          errors: ['All export paths failed and allow_partial=false.'],
          warnings,
          setup_actions: setupActions.length > 0 ? setupActions : undefined,
          required_user_inputs: requiredUserInputs.length > 0 ? requiredUserInputs : undefined,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      if (planSummary?.feasibility === 'low') {
        notes.push('Feasibility is low; treat output as partial semantic reconstruction.')
      }
      if (runtimeData?.is_dotnet) {
        notes.push('Runtime signal indicates .NET metadata is available for high-fidelity recovery.')
      } else {
        notes.push('Runtime signal indicates native path; exact original source text is not recoverable.')
      }
      if (
        binaryProfileData?.export_dispatch_profile?.likely_dispatch_model &&
        binaryProfileData.export_dispatch_profile.likely_dispatch_model !== 'none'
      ) {
        notes.push(
          `Binary role preflight suggests dispatch model: ${binaryProfileData.export_dispatch_profile.likely_dispatch_model}.`
        )
      }
      if (dllProfileData?.dll_entry_hints.length) {
        notes.push(`DLL/export preflight hints: ${dllProfileData.dll_entry_hints.slice(0, 3).join(' ')}`)
      }
      if (comProfileData?.likely_com_server) {
        notes.push(`COM preflight suggests activation model: ${comProfileData.activation_model}.`)
      }
      if (binaryProfileData?.host_interaction_profile?.likely_hosted) {
        notes.push('Binary role preflight suggests the sample is likely hosted as a DLL/plugin/service component.')
      }
      if (rustProfileData?.suspected_rust) {
        notes.push(
          `Rust preflight recovered ${rustProfileData.recovered_function_count} function candidates and ${rustProfileData.recovered_symbol_count} symbol hints.`
        )
        if (rustProfileData.crate_hints.length > 0) {
          notes.push(`Rust crate hints: ${rustProfileData.crate_hints.slice(0, 4).join(', ')}.`)
        }
      }
      if (functionIndexRecoveryData?.applied) {
        notes.push(
          `Function index recovery imported ${functionIndexRecoveryData.imported_count} recovered functions before export.`
        )
      }
      if (roleStrategy) {
        notes.push(
          `Role-aware strategy selected target role ${roleStrategy.target_role}${roleStrategy.focus_areas.length ? ` with focus on ${roleStrategy.focus_areas.join(', ')}` : ''}.`
        )
        notes.push(
          `Role-aware export tuning: topk=${roleStrategy.export_tuning.topk}, module_limit=${roleStrategy.export_tuning.module_limit}, min_module_size=${roleStrategy.export_tuning.min_module_size}, imports=${roleStrategy.export_tuning.include_imports ? 'on' : 'off'}, strings=${roleStrategy.export_tuning.include_strings ? 'on' : 'off'}.`
        )
      }
      if (exportSummary?.binary_profile?.analysis_priorities?.length) {
        notes.push(
          `Binary profile priorities: ${exportSummary.binary_profile.analysis_priorities.join(', ')}.`
        )
      }
      if (exportSummary?.managed_profile?.analysis_priorities?.length) {
        notes.push(
          `Managed profile priorities: ${exportSummary.managed_profile.analysis_priorities.join(', ')}.`
        )
      }
      if (selectedPath === 'native' && exportSummary?.build_validation_status) {
        notes.push(`Native build validation: ${exportSummary.build_validation_status}.`)
      }
      if (selectedPath === 'native' && exportSummary?.harness_validation_status) {
        notes.push(`Harness validation: ${exportSummary.harness_validation_status}.`)
      }

      const routingMetadata = buildIntentBackendPlan({
        goal: 'reverse',
        depth: input.depth,
        backendPolicy: input.backend_policy,
        allowTransformations: input.allow_transformations,
        readiness: (dependencies?.resolveBackends || resolveAnalysisBackends)(),
        signals: {
          weak_function_coverage:
            selectedPath === 'native' &&
            ((!hasReadyGhidraFunctionIndex && !functionIndexRecoveryApplied) ||
              Boolean(
                functionIndexRecoveryData &&
                  functionIndexRecoveryData.recovered_function_count <
                    Math.max(input.topk, 12)
              )),
          degraded_reconstruction:
            selectedPath === 'native' &&
            (stageStatus.export_primary !== 'ok' ||
              stageStatus.plan === 'failed' ||
              !exportSummary ||
              planSummary?.feasibility === 'low' ||
              exportSummary?.degraded_mode === true),
          unresolved_control_flow:
            selectedPath === 'native' &&
            Boolean(
              rustProfileData?.suspected_rust &&
                rustProfileData.recovered_function_count < Math.max(input.topk * 2, 24)
            ),
        },
      })

      const selectedBackends = new Set(selectedBackendTools(routingMetadata))
      let alternateBackends: Record<string, unknown> | undefined

      if (selectedPath === 'native' && selectedBackends.size > 0) {
        alternateBackends = {}

        if (selectedBackends.has('rizin.analyze')) {
          const rizinResult = await rizinAnalyzeHandler({
            sample_id: input.sample_id,
            operation: 'functions',
            max_items: 20,
            timeout_sec: 45,
            persist_artifact: true,
          })
          if (rizinResult.ok && rizinResult.data) {
            alternateBackends.rizin = summarizeAlternateBackendData(rizinResult.data)
            notes.push('Rizin corroboration was used because baseline function coverage looked weak.')
          } else {
            warnings.push(
              `rizin.analyze unavailable: ${(rizinResult.errors || ['unknown error']).join('; ')}`
            )
          }
          if (rizinResult.warnings?.length) {
            warnings.push(...rizinResult.warnings.map((item) => `rizin.analyze: ${item}`))
          }
        }

        if (selectedBackends.has('angr.analyze')) {
          const angrResult = await angrAnalyzeHandler({
            sample_id: input.sample_id,
            analysis: 'cfg_fast',
            max_functions: 20,
            timeout_sec: 90,
            persist_artifact: true,
          })
          if (angrResult.ok && angrResult.data) {
            alternateBackends.angr = summarizeAlternateBackendData(angrResult.data)
            notes.push('angr CFGFast corroboration was used to cross-check weak or ambiguous function discovery.')
          } else {
            warnings.push(
              `angr.analyze unavailable: ${(angrResult.errors || ['unknown error']).join('; ')}`
            )
          }
          if (angrResult.warnings?.length) {
            warnings.push(...angrResult.warnings.map((item) => `angr.analyze: ${item}`))
          }
        }

        if (selectedBackends.has('retdec.decompile')) {
          const retdecResult = await retdecDecompileHandler({
            sample_id: input.sample_id,
            output_format: 'plain',
            timeout_sec: 180,
            persist_artifact: true,
          })
          if (retdecResult.ok && retdecResult.data) {
            alternateBackends.retdec = summarizeAlternateBackendData(retdecResult.data)
            notes.push('RetDec alternate decompilation was generated because reconstruction quality was degraded.')
          } else {
            warnings.push(
              `retdec.decompile unavailable: ${(retdecResult.errors || ['unknown error']).join('; ')}`
            )
          }
          if (retdecResult.warnings?.length) {
            warnings.push(...retdecResult.warnings.map((item) => `retdec.decompile: ${item}`))
          }
        }

        if (Object.keys(alternateBackends).length === 0) {
          alternateBackends = undefined
        }
      }

      const degraded = stageStatus.export_primary !== 'ok' || stageStatus.plan === 'failed' || !exportSummary
      const outputData = mergeRoutingMetadata(
        mergeCoverageEnvelope(
          {
            sample_id: input.sample_id,
            selected_path: selectedPath,
            degraded,
            stage_status: stageStatus,
            provenance,
            selection_diffs: Object.keys(selectionDiffs).length > 0 ? selectionDiffs : undefined,
            ghidra_execution: ghidraExecution,
            runtime: summarizeRuntime(runtimeData),
            preflight:
              input.include_preflight || stageStatus.function_index_recovery !== 'skipped'
                ? {
                    binary_profile: binaryProfileData,
                    dll_profile: dllProfileData,
                    com_profile: comProfileData,
                    rust_profile: rustProfileData ? summarizeRustPreflight(rustProfileData) : null,
                    function_index_recovery: functionIndexRecoveryData,
                    role_strategy: roleStrategy,
                  }
                : undefined,
            plan: planSummary,
            export: exportSummary,
            alternate_backends: alternateBackends,
            notes,
            result_mode: 'completed' as const,
            recommended_next_tools: [
              'artifacts.list',
              'artifact.read',
              'code.module.review',
            ],
            next_actions: [
              'Inspect export_root artifacts with artifacts.list or artifact.read.',
              'Use code.module.review or function-level review tools when you want LLM-guided refinement over reconstructed output.',
            ],
          },
          buildReconstructCoverage({
            sampleSize: sample.size || 0,
            requestedDepth: input.depth,
            queued: false,
            selectedPath,
            degraded,
            validateBuild: input.validate_build && analysisBudgetProfile === 'deep',
            runHarness: input.run_harness && analysisBudgetProfile === 'deep',
            exportSummary,
            stageStatus: {
              export_primary: stageStatus.export_primary,
              plan: stageStatus.plan,
            },
          })
        ),
        routingMetadata
      )

      await cacheManager.setCachedResult(cacheKey, outputData, CACHE_TTL_MS, sample.sha256)

      return {
        ok: true,
        data: outputData,
        warnings: warnings.length > 0 ? warnings : undefined,
        setup_actions: setupActions.length > 0 ? setupActions : undefined,
        required_user_inputs: requiredUserInputs.length > 0 ? requiredUserInputs : undefined,
        artifacts: artifacts as WorkerResult['artifacts'],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        setup_actions: undefined,
        required_user_inputs: undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
