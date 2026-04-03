/**
 * report.summarize tool implementation
 * Generates quick triage report with summary, confidence, IOCs, evidence, and recommendations.
 */

import { z } from 'zod'
import type { ArtifactRef, ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { Artifact, DatabaseManager, Function as DbFunction } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import {
  BinaryRoleProfileDataSchema,
  createBinaryRoleProfileHandler,
} from './binary-role-profile.js'
import {
  RustBinaryAnalyzeDataSchema,
  createRustBinaryAnalyzeHandler,
} from './rust-binary-analyze.js'
import { StaticCapabilityTriageDataSchema } from './static-capability-triage.js'
import { PEStructureAnalyzeDataSchema } from '../plugins/pe-analysis/tools/pe-structure-analyze.js'
import { CompilerPackerDetectDataSchema } from './compiler-packer-detect.js'
import { createTriageWorkflowHandler } from '../workflows/triage.js'
import { loadDynamicTraceEvidence, type DynamicTraceSummary } from '../dynamic-trace.js'
import {
  loadSemanticFunctionExplanationIndex,
  type SemanticFunctionExplanationIndex,
} from '../semantic-name-suggestion-artifacts.js'
import {
  loadStaticAnalysisArtifactSelection,
  STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
  PE_STRUCTURE_ANALYSIS_ARTIFACT_TYPE,
  COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE,
  type StaticArtifactScope,
} from '../static-analysis-artifacts.js'
import {
  ConfidenceSemanticsSchema,
  buildReportConfidenceSemantics,
} from '../confidence-semantics.js'
import {
  AnalysisProvenanceSchema,
  buildRuntimeArtifactProvenance,
  buildStaticArtifactProvenance,
  buildSemanticArtifactProvenance,
} from '../analysis-provenance.js'
import {
  AnalysisSelectionDiffSchema,
  buildArtifactSelectionDiff,
} from '../selection-diff.js'
import {
  GhidraExecutionSummarySchema,
  buildGhidraExecutionSummary,
} from '../ghidra-execution-summary.js'
import {
  BinaryProfileSummarySchema,
  RustProfileSummarySchema,
  StaticCapabilitySummarySchema,
  PEStructureSummaryDigestSchema,
  CompilerPackerSummaryDigestSchema,
  SemanticExplanationDigestSchema,
  ExplanationGraphSummarySchema,
  SummaryArtifactRefSchema,
  DigestTruncationSchema,
  buildArtifactRefFromParts,
  buildTriageStageDigest,
  buildStaticStageDigest,
  dedupeArtifactRefs,
  limitArray,
  truncateText,
} from '../summary-digests.js'
import {
  CoverageEnvelopeSchema,
  buildCoverageEnvelope,
  classifySampleSizeTier,
} from '../analysis-coverage.js'
import {
  ExplanationGraphDigestSchema,
  type ExplanationGraphArtifact,
  type ExplanationGraphDigest,
  attachExplanationArtifactRef,
  buildRuntimeStageExplanationGraph,
  persistExplanationGraphArtifact,
} from '../explanation-graphs.js'
import { generateCallGraph } from '../visualization/call-graph.js'
import { generateDataFlow } from '../visualization/data-flow.js'
import { generateCryptoFlow } from '../visualization/crypto-flow.js'
import {
  CRYPTO_IDENTIFICATION_ARTIFACT_TYPE,
  loadCryptoPlanningArtifactSelection,
} from '../crypto-planning-artifacts.js'
import { CryptoFindingSchema } from '../crypto-breakpoint-analysis.js'
import { ToolSurfaceRoleSchema } from '../tool-surface-guidance.js'
import {
  ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE,
  AnalysisDiffDigestSchema,
  DebugStateSchema,
  loadUnpackDebugArtifactSelection,
  PackedStateSchema,
  UnpackStateSchema,
} from '../unpack-debug-runtime.js'

const TOOL_NAME = 'report.summarize'
const REPORT_INLINE_PAYLOAD_BUDGET_CHARS = 180_000

type ReportSummarizeData = NonNullable<z.infer<typeof ReportSummarizeOutputSchema>['data']>

export const ReportSummarizeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  mode: z
    .enum(['triage', 'dotnet'])
    .default('triage')
    .describe('Report mode: triage for quick assessment, dotnet for .NET-specific analysis'),
  detail_level: z
    .enum(['compact', 'full'])
    .default('compact')
    .describe(
      'Compact is the default AI-facing digest mode and excludes heavyweight raw analysis trees. Use compact for normal and large-sample reporting; full is a bounded legacy richer mode for targeted smaller-sample review.'
    ),
  evidence_scope: z
    .enum(['all', 'latest', 'session'])
    .default('all')
    .describe('Runtime evidence scope: all artifacts, only the latest artifact window, or a specific session selector'),
  evidence_session_tag: z
    .string()
    .optional()
    .describe('Optional runtime evidence session selector used when evidence_scope=session or to narrow all/latest results'),
  static_scope: z
    .enum(['all', 'latest', 'session'])
    .default('latest')
    .describe('Static-analysis artifact scope shared by capability triage, PE structure analysis, and compiler/packer attribution selections'),
  static_session_tag: z
    .string()
    .optional()
    .describe('Optional static-analysis session selector used when static_scope=session or to narrow all/latest results'),
  semantic_scope: z
    .enum(['all', 'latest', 'session'])
    .default('all')
    .describe('Semantic explanation artifact scope: all artifacts, latest explanation window, or a specific semantic review session'),
  semantic_session_tag: z
    .string()
    .optional()
    .describe('Optional semantic review session selector used when semantic_scope=session or to narrow all/latest results'),
  compare_evidence_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .describe('Optional baseline runtime evidence scope used to compare this report against another runtime artifact selection'),
  compare_evidence_session_tag: z
    .string()
    .optional()
    .describe('Optional baseline runtime evidence session selector used when compare_evidence_scope=session'),
  compare_static_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .describe('Optional baseline static-analysis scope used to compare capability, PE structure, and compiler/packer artifact selections'),
  compare_static_session_tag: z
    .string()
    .optional()
    .describe('Optional baseline static-analysis session selector used when compare_static_scope=session'),
  compare_semantic_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .describe('Optional baseline semantic explanation scope used to compare this report against another semantic artifact selection'),
  compare_semantic_session_tag: z
    .string()
    .optional()
    .describe('Optional baseline semantic explanation session selector used when compare_semantic_scope=session'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache in downstream analysis tools'),
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
      value.compare_semantic_scope !== 'session' || Boolean(value.compare_semantic_session_tag?.trim()),
    {
      message: 'compare_semantic_session_tag is required when compare_semantic_scope=session',
      path: ['compare_semantic_session_tag'],
    }
  )

export type ReportSummarizeInput = z.infer<typeof ReportSummarizeInputSchema>

const EvidenceLineageLayerSchema = z.object({
  layer: z.enum(['static_only', 'safe_simulation', 'memory_or_hybrid', 'executed_trace']),
  confidence_band: z.enum(['baseline', 'suggestive', 'high']),
  artifact_count: z.number().int().nonnegative(),
  source_formats: z.array(z.string()),
  evidence_kinds: z.array(z.string()),
  source_names: z.array(z.string()),
  latest_imported_at: z.string().nullable(),
  summary: z.string(),
})

const EvidenceLineageSchema = z.object({
  layers: z.array(EvidenceLineageLayerSchema),
  latest_runtime_artifact_at: z.string().nullable(),
  scope_note: z.string(),
})

const ReportAssessmentConfidenceSchema = z.object({
  assessment: ConfidenceSemanticsSchema,
})

const FunctionExplanationSummarySchema = z.object({
  address: z.string().nullable(),
  function: z.string().nullable(),
  behavior: z.string(),
  summary: z.string(),
  confidence: z.number().min(0).max(1),
  rewrite_guidance: z.array(z.string()),
  source: z.string().nullable(),
})

const PersistedStateVisibilitySchema = z.object({
  persisted_only: z.boolean(),
  persisted_run_id: z.string().nullable(),
  reused_stage_names: z.array(z.string()),
  deferred_requirements: z.array(z.string()),
})

export const ReportSummarizeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      detail_level: z
        .enum(['compact', 'full'])
        .describe('The response detail level that was used to build this report payload.'),
      tool_surface_role: ToolSurfaceRoleSchema.describe(
        'Marks this report surface as primary, compatibility, or export-only for AI routing.'
      ),
      preferred_primary_tools: z.array(z.string()).describe(
        'Primary staged-runtime alternatives that should be preferred for final analyst-facing summary flows.'
      ),
      summary: z.string().describe('Natural language summary of the analysis'),
      confidence: z.number().min(0).max(1).describe('Confidence score (0-1)'),
      threat_level: z
        .enum(['clean', 'suspicious', 'malicious', 'unknown'])
        .describe('Assessed threat level'),
      iocs: z
        .object({
          suspicious_imports: z.array(z.string()).describe('Suspicious imported functions'),
          suspicious_strings: z.array(z.string()).describe('Suspicious strings found'),
          yara_matches: z.array(z.string()).describe('YARA rule matches'),
          yara_low_confidence: z.array(z.string()).optional().describe('YARA matches downgraded due to weak evidence'),
          urls: z.array(z.string()).optional().describe('URLs found in strings'),
          ip_addresses: z.array(z.string()).optional().describe('IP addresses found'),
          file_paths: z.array(z.string()).optional().describe('File paths found'),
          registry_keys: z.array(z.string()).optional().describe('Registry keys found'),
          high_value_iocs: z
            .object({
              suspicious_apis: z.array(z.string()).optional(),
              commands: z.array(z.string()).optional(),
              pipes: z.array(z.string()).optional(),
              urls: z.array(z.string()).optional(),
              network: z.array(z.string()).optional(),
            })
            .optional(),
          compiler_artifacts: z
            .object({
              cargo_paths: z.array(z.string()).optional(),
              rust_markers: z.array(z.string()).optional(),
              library_profile: z
                .object({
                  ecosystems: z.array(z.string()),
                  top_crates: z.array(z.string()),
                  notable_libraries: z.array(z.string()),
                  evidence: z.array(z.string()),
                })
                .optional(),
            })
            .optional(),
        })
        .describe('Indicators of Compromise'),
      evidence: z.array(z.string()).describe('Evidence supporting the assessment'),
      evidence_lineage: EvidenceLineageSchema.optional().describe(
        'Explicit evidence layers separating static-only, simulated, memory/hybrid, and executed runtime evidence.'
      ),
      confidence_semantics: ReportAssessmentConfidenceSchema.optional().describe(
        'Explains how to interpret confidence scores. These are heuristic evidence scores, not calibrated probabilities.'
      ),
      binary_profile_summary: BinaryProfileSummarySchema.optional().describe(
        'Compact binary role digest for AI-facing summary mode.'
      ),
      rust_profile_summary: RustProfileSummarySchema.optional().describe(
        'Compact Rust/toolchain digest for AI-facing summary mode.'
      ),
      static_capability_summary: StaticCapabilitySummarySchema.optional().describe(
        'Compact capability-triage digest that omits heavyweight capability arrays in compact mode.'
      ),
      pe_structure_summary: PEStructureSummaryDigestSchema.optional().describe(
        'Compact PE-structure digest that omits detailed import/export/resource trees in compact mode.'
      ),
      compiler_packer_summary: CompilerPackerSummaryDigestSchema.optional().describe(
        'Compact compiler/packer digest that omits raw backend payloads in compact mode.'
      ),
      semantic_explanation_summary: SemanticExplanationDigestSchema.optional().describe(
        'Compact semantic-explanation digest with behavior and explanation counts.'
      ),
      binary_profile: BinaryRoleProfileDataSchema.optional().describe(
        'Optional binary role profile summarizing EXE/DLL/COM/service/plugin/export characteristics.'
      ),
      rust_profile: RustBinaryAnalyzeDataSchema.optional().describe(
        'Optional Rust-oriented binary analysis summary, including crate hints, recovered symbols, and recovery priorities.'
      ),
      static_capabilities: StaticCapabilityTriageDataSchema.optional().describe(
        'Optional static capability findings selected from persisted capability-triage artifacts using static_scope.'
      ),
      pe_structure: PEStructureAnalyzeDataSchema.optional().describe(
        'Optional canonical PE structure analysis selected from persisted static-analysis artifacts using static_scope.'
      ),
      compiler_packer: CompilerPackerDetectDataSchema.optional().describe(
        'Optional compiler/packer/protector attribution selected from persisted static-analysis artifacts using static_scope.'
      ),
      provenance: AnalysisProvenanceSchema.optional().describe(
        'Explicit runtime/semantic artifact selection used to produce this report, including scope, session selector, and selected artifact IDs.'
      ),
      persisted_state_visibility: PersistedStateVisibilitySchema.optional().describe(
        'Machine-readable persisted-state and deferred-work explanation showing which run stages were reused and which prerequisites remain deferred.'
      ),
      packed_state: PackedStateSchema.optional().describe(
        'Explicit packed-sample state derived from persisted staged runtime metadata.'
      ),
      unpack_state: UnpackStateSchema.optional().describe(
        'Explicit unpack progression state derived from persisted unpack planning or execution artifacts.'
      ),
      unpack_confidence: z.number().min(0).max(1).optional().describe(
        'Bounded unpack confidence indicating whether packed/unpacked progression is heuristic, partial, or strongly corroborated.'
      ),
      debug_state: DebugStateSchema.optional().describe(
        'Persisted debug-session progression state, if a debug path has already been planned or executed.'
      ),
      unpack_debug_diffs: z.array(AnalysisDiffDigestSchema).optional().describe(
        'Bounded unpack/debug diff digests consumed as explanation inputs instead of reinlining raw dumps or raw traces.'
      ),
      ghidra_execution: GhidraExecutionSummarySchema.nullable().optional().describe(
        'Latest persisted Ghidra execution summary, including project/log locations, extraction status, and recorded progress stages.'
      ),
      selection_diffs: AnalysisSelectionDiffSchema.optional().describe(
        'Optional comparison between the current artifact selection and a caller-provided baseline runtime/semantic selection.'
      ),
      explanation_graphs: z
        .array(ExplanationGraphSummarySchema)
        .optional()
        .describe(
          'Bounded explanation-graph digests. These are semantic graph summaries with provenance, confidence state, and omission boundaries; use the referenced artifacts for deeper inspection.'
        ),
      artifact_refs: z
        .object({
          supporting: z.array(SummaryArtifactRefSchema),
          runtime: z.array(SummaryArtifactRefSchema).optional(),
          static_capabilities: z.array(SummaryArtifactRefSchema).optional(),
          pe_structure: z.array(SummaryArtifactRefSchema).optional(),
          compiler_packer: z.array(SummaryArtifactRefSchema).optional(),
          semantic_explanations: z.array(SummaryArtifactRefSchema).optional(),
          explanation_graphs: z.array(SummaryArtifactRefSchema).optional(),
        })
        .optional()
        .describe(
          'Artifact references backing this compact report. Fetch deeper detail with artifact.read or artifacts.list instead of relying on inline heavy payloads.'
        ),
      truncation: DigestTruncationSchema.optional().describe(
        'Deterministic top-N and truncation metadata applied to compact digest fields.'
      ),
      function_explanations: z
        .array(FunctionExplanationSummarySchema)
        .optional()
        .describe('Optional external LLM explanation summaries loaded from semantic explanation artifacts.'),
      evidence_weights: z
        .object({
          import: z.number().min(0).max(1),
          string: z.number().min(0).max(1),
          runtime: z.number().min(0).max(1),
        })
        .optional()
        .describe('Relative evidence contribution weights (import/string/runtime)'),
      inference: z
        .object({
          classification: z.enum(['benign', 'suspicious', 'malicious', 'unknown']),
          hypotheses: z.array(z.string()),
          false_positive_risks: z.array(z.string()),
          intent_assessment: z
            .object({
              label: z.enum(['dual_use_tool', 'operator_utility', 'malware_like_payload', 'unknown']),
              confidence: z.number().min(0).max(1),
              evidence: z.array(z.string()),
              counter_evidence: z.array(z.string()),
            })
            .optional(),
          tooling_assessment: z
            .object({
              help_text_detected: z.boolean(),
              cli_surface_detected: z.boolean(),
              framework_hints: z.array(z.string()),
              toolchain_markers: z.array(z.string()),
              library_profile: z
                .object({
                  ecosystems: z.array(z.string()),
                  top_crates: z.array(z.string()),
                  notable_libraries: z.array(z.string()),
                  evidence: z.array(z.string()),
                })
                .optional(),
            })
            .optional(),
        })
        .optional()
        .describe('Inference layer separated from raw evidence'),
      recommendation: z.string().describe('Recommended next steps'),
      recommended_next_tools: z
        .array(z.string())
        .optional()
        .describe('Machine-readable follow-up tool suggestions.'),
      next_actions: z
        .array(z.string())
        .optional()
        .describe('Machine-readable compact-first retrieval guidance for clients.'),
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

export type ReportSummarizeOutput = z.infer<typeof ReportSummarizeOutputSchema>

export const reportSummarizeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Generate a bounded analyst-facing summary digest from triage/runtime/static context. Default detail_level=compact is the safe AI-facing mode and excludes heavyweight raw analysis trees. This is a compatibility summary surface, not the primary staged final-report workflow. ' +
    'Prefer workflow.summarize for staged final reporting, and use artifact.read / artifacts.list for deeper supporting detail. ' +
    'Read coverage_level, completion_state, known_findings, suspected_findings, unverified_areas, and upgrade_paths before treating the report as complete. ' +
    '\n\nDecision guide:\n' +
    '- Use when: you want a deterministic compact report snapshot or compatibility with legacy report clients.\n' +
    '- Best for: small/medium samples, quick analyst snapshots, or compact restatement of persisted fast/static evidence.\n' +
    '- Large-sample pattern: keep detail_level=compact and prefer workflow.summarize for staged final output instead of requesting one large inline report.\n' +
    '- Do not use when: you want the final multi-stage report synthesis path; prefer workflow.summarize.\n' +
    '- Typical next step: call workflow.summarize for staged triage/static/deep/final digests, or artifact.read on returned artifact_refs for detail.\n' +
    '- Common mistake: expecting compact mode to inline full static capability arrays, PE trees, or raw backend payloads.',
  inputSchema: ReportSummarizeInputSchema,
  outputSchema: ReportSummarizeOutputSchema,
}

type TriageSummaryData = {
  summary: string
  confidence: number
  threat_level: 'clean' | 'suspicious' | 'malicious' | 'unknown'
  iocs: {
    suspicious_imports: string[]
    suspicious_strings: string[]
    yara_matches: string[]
    yara_low_confidence?: string[]
    urls?: string[]
    ip_addresses?: string[]
    file_paths?: string[]
    registry_keys?: string[]
    high_value_iocs?: {
      suspicious_apis?: string[]
      commands?: string[]
      pipes?: string[]
      urls?: string[]
      network?: string[]
    }
    compiler_artifacts?: {
      cargo_paths?: string[]
      rust_markers?: string[]
      library_profile?: {
        ecosystems: string[]
        top_crates: string[]
        notable_libraries: string[]
        evidence: string[]
      }
    }
  }
  evidence: string[]
  evidence_lineage?: z.infer<typeof EvidenceLineageSchema>
  confidence_semantics?: z.infer<typeof ReportAssessmentConfidenceSchema>
  binary_profile?: z.infer<typeof BinaryRoleProfileDataSchema>
  rust_profile?: z.infer<typeof RustBinaryAnalyzeDataSchema>
  static_capabilities?: z.infer<typeof StaticCapabilityTriageDataSchema>
  pe_structure?: z.infer<typeof PEStructureAnalyzeDataSchema>
  compiler_packer?: z.infer<typeof CompilerPackerDetectDataSchema>
  function_explanations?: Array<z.infer<typeof FunctionExplanationSummarySchema>>
  evidence_weights?: {
    import: number
    string: number
    runtime: number
  }
  inference?: {
    classification: 'benign' | 'suspicious' | 'malicious' | 'unknown'
    hypotheses: string[]
    false_positive_risks: string[]
    intent_assessment?: {
      label: 'dual_use_tool' | 'operator_utility' | 'malware_like_payload' | 'unknown'
      confidence: number
      evidence: string[]
      counter_evidence: string[]
    }
    tooling_assessment?: {
      help_text_detected: boolean
      cli_surface_detected: boolean
      framework_hints: string[]
      toolchain_markers: string[]
      library_profile?: {
        ecosystems: string[]
        top_crates: string[]
        notable_libraries: string[]
        evidence: string[]
      }
    }
  }
  recommendation: string
}

type LibraryProfileSummary = NonNullable<
  NonNullable<TriageSummaryData['iocs']['compiler_artifacts']>['library_profile']
>

function normalizeLibraryProfile(
  libraryProfile?:
    | z.infer<typeof RustBinaryAnalyzeDataSchema>['library_profile']
    | LibraryProfileSummary
): LibraryProfileSummary | undefined {
  if (!libraryProfile) {
    return undefined
  }

  return {
    ecosystems: libraryProfile.ecosystems || [],
    top_crates: libraryProfile.top_crates || [],
    notable_libraries: libraryProfile.notable_libraries || [],
    evidence: libraryProfile.evidence || [],
  }
}

function artifactRefFromArtifact(
  artifact: Artifact,
  metadata?: Record<string, unknown>
) {
  return buildArtifactRefFromParts({
    id: artifact.id,
    type: artifact.type,
    path: artifact.path,
    sha256: artifact.sha256,
    mime: artifact.mime,
    ...(metadata ? { metadata } : {}),
  })
}

function selectArtifactRefsByIds(
  artifacts: Artifact[],
  artifactIds: string[],
  metadata?: Record<string, unknown>
) {
  const selected = new Map(artifacts.map((item) => [item.id, item]))
  return dedupeArtifactRefs(
    artifactIds
      .map((id) => selected.get(id))
      .filter((item): item is Artifact => Boolean(item))
      .map((item) => artifactRefFromArtifact(item, metadata))
  )
}

function buildBinaryProfileDigest(
  binaryProfile?: z.infer<typeof BinaryRoleProfileDataSchema>
): z.infer<typeof BinaryProfileSummarySchema> | undefined {
  if (!binaryProfile) {
    return undefined
  }
  const notableExports = limitArray(
    'top_capabilities',
    dedupe(binaryProfile.export_surface.notable_exports || [])
  ).values
  const hostHints = limitArray(
    'top_groups',
    dedupe(binaryProfile.host_interaction_profile.host_hints || [])
  ).values
  const priorities = limitArray(
    'analysis_priorities',
    dedupe(binaryProfile.analysis_priorities || [])
  ).values
  return {
    binary_role: binaryProfile.binary_role,
    role_confidence: binaryProfile.role_confidence,
    packed: binaryProfile.packed,
    packing_confidence: binaryProfile.packing_confidence,
    export_count: binaryProfile.export_surface.total_exports,
    notable_exports: notableExports,
    dispatch_model:
      binaryProfile.export_dispatch_profile.likely_dispatch_model === 'none'
        ? null
        : binaryProfile.export_dispatch_profile.likely_dispatch_model,
    host_hints: hostHints,
    analysis_priorities: priorities,
    summary: buildBinaryProfileSummary(binaryProfile),
  }
}

function buildRustProfileDigest(
  rustProfile?: z.infer<typeof RustBinaryAnalyzeDataSchema>
): z.infer<typeof RustProfileSummarySchema> | undefined {
  if (!rustProfile) {
    return undefined
  }
  return {
    suspected_rust: rustProfile.suspected_rust,
    confidence: rustProfile.confidence,
    primary_runtime: rustProfile.primary_runtime || null,
    top_crates: limitArray('top_crates', dedupe(rustProfile.crate_hints || [])).values,
    recovered_symbol_count: rustProfile.recovered_symbol_count,
    recovered_function_count: rustProfile.recovered_function_count,
    analysis_priorities: limitArray(
      'analysis_priorities',
      dedupe(rustProfile.analysis_priorities || [])
    ).values,
    summary: buildRustProfileSummary(rustProfile),
  }
}

function buildStaticCapabilityDigest(
  data?: z.infer<typeof StaticCapabilityTriageDataSchema>
): z.infer<typeof StaticCapabilitySummarySchema> | undefined {
  if (!data) {
    return undefined
  }
  const topGroups = limitArray(
    'top_groups',
    Object.entries(data.capability_groups || {})
      .sort((left, right) => Number(right[1]) - Number(left[1]))
      .map(([name]) => name)
  ).values
  const topCapabilities = limitArray(
    'top_capabilities',
    (data.capabilities || []).map((item) => item.name || item.rule_id || 'unknown_capability')
  ).values
  return {
    status: data.status,
    capability_count: data.capability_count || 0,
    top_groups: topGroups,
    top_capabilities: topCapabilities,
    summary:
      data.status === 'ready'
        ? `Capability triage matched ${data.capability_count || 0} finding(s)${
            topGroups.length > 0 ? ` across ${topGroups.join(', ')}` : ''
          }.`
        : data.summary || 'Capability triage did not produce ready findings.',
  }
}

function buildPEStructureDigest(
  data?: z.infer<typeof PEStructureAnalyzeDataSchema>
): z.infer<typeof PEStructureSummaryDigestSchema> | undefined {
  if (!data) {
    return undefined
  }
  return {
    status: data.status,
    section_count: data.summary.section_count,
    import_function_count: data.summary.import_function_count,
    export_count: data.summary.export_count,
    resource_count: data.summary.resource_count,
    overlay_present: data.summary.overlay_present,
    parser_preference: data.summary.parser_preference || null,
    summary: `PE structure recovered ${data.summary.section_count} section(s)${
      data.summary.overlay_present ? ' with an overlay present' : ''
    }.`,
  }
}

function buildCompilerPackerDigest(
  data?: z.infer<typeof CompilerPackerDetectDataSchema>
): z.infer<typeof CompilerPackerSummaryDigestSchema> | undefined {
  if (!data) {
    return undefined
  }
  const compilerNames = limitArray(
    'top_capabilities',
    (data.compiler_findings || []).map((item) => item.name)
  ).values
  const packerNames = limitArray(
    'top_capabilities',
    (data.packer_findings || []).map((item) => item.name)
  ).values
  const protectorNames = limitArray(
    'top_capabilities',
    (data.protector_findings || []).map((item) => item.name)
  ).values
  const summary =
    data.status !== 'ready'
      ? data.backend?.error || 'Compiler/packer attribution is unavailable.'
      : packerNames.length > 0 || protectorNames.length > 0
        ? `Toolchain attribution suggests packer/protector signals (${[...packerNames, ...protectorNames].join(', ')}).`
        : compilerNames.length > 0
          ? `Toolchain attribution suggests compiler signals (${compilerNames.join(', ')}).`
          : 'Toolchain attribution surfaced no strong compiler or packer findings.'
  return {
    status: data.status,
    compiler_names: compilerNames,
    packer_names: packerNames,
    protector_names: protectorNames,
    likely_primary_file_type: data.summary.likely_primary_file_type || null,
    summary,
  }
}

function buildSemanticExplanationDigest(
  functionExplanations: Array<z.infer<typeof FunctionExplanationSummarySchema>>
): z.infer<typeof SemanticExplanationDigestSchema> | undefined {
  if (functionExplanations.length === 0) {
    return undefined
  }
  const topBehaviors = limitArray(
    'top_behaviors',
    dedupe(functionExplanations.map((item) => item.behavior))
  ).values
  const topSummaries = limitArray(
    'top_summaries',
    functionExplanations.map((item) => truncateText(item.summary, 180))
  ).values
  return {
    count: functionExplanations.length,
    top_behaviors: topBehaviors,
    top_summaries: topSummaries,
    summary: `Semantic explanations are available for ${functionExplanations.length} function(s).`,
  }
}

function buildReportArtifactRefs(
  artifacts: Artifact[],
  refs: {
    runtimeIds: string[]
    staticCapabilityIds: string[]
    peStructureIds: string[]
    compilerPackerIds: string[]
    semanticIds: string[]
  }
) {
  const runtime = selectArtifactRefsByIds(artifacts, refs.runtimeIds, {
    report_section: 'runtime',
  })
  const staticCapabilities = selectArtifactRefsByIds(artifacts, refs.staticCapabilityIds, {
    report_section: 'static_capabilities',
  })
  const peStructure = selectArtifactRefsByIds(artifacts, refs.peStructureIds, {
    report_section: 'pe_structure',
  })
  const compilerPacker = selectArtifactRefsByIds(artifacts, refs.compilerPackerIds, {
    report_section: 'compiler_packer',
  })
  const semanticExplanations = selectArtifactRefsByIds(artifacts, refs.semanticIds, {
    report_section: 'semantic_explanations',
  })
  const supporting = dedupeArtifactRefs([
    ...runtime,
    ...staticCapabilities,
    ...peStructure,
    ...compilerPacker,
    ...semanticExplanations,
  ])

  return {
    supporting,
    ...(runtime.length > 0 ? { runtime } : {}),
    ...(staticCapabilities.length > 0 ? { static_capabilities: staticCapabilities } : {}),
    ...(peStructure.length > 0 ? { pe_structure: peStructure } : {}),
    ...(compilerPacker.length > 0 ? { compiler_packer: compilerPacker } : {}),
    ...(semanticExplanations.length > 0 ? { semantic_explanations: semanticExplanations } : {}),
  }
}

function buildBinaryProfileSummary(binaryProfile: z.infer<typeof BinaryRoleProfileDataSchema>): string {
  const lifecycleSurface = binaryProfile.lifecycle_surface || []
  const classFactorySurface = binaryProfile.com_profile.class_factory_surface || []
  const callbackSurface = binaryProfile.host_interaction_profile.callback_surface || []
  const parts = [
    `Binary role profile suggests ${binaryProfile.binary_role} (confidence=${binaryProfile.role_confidence.toFixed(2)})`,
  ]
  if (binaryProfile.export_surface.total_exports > 0) {
    parts.push(`exports=${binaryProfile.export_surface.total_exports}`)
  }
  if (binaryProfile.indicators.com_server.likely) {
    parts.push('COM-like surface detected')
  }
  if (binaryProfile.indicators.service_binary.likely) {
    parts.push('service indicators detected')
  }
  if (binaryProfile.export_dispatch_profile.likely_dispatch_model !== 'none') {
    parts.push(`dispatch_model=${binaryProfile.export_dispatch_profile.likely_dispatch_model}`)
  }
  if (binaryProfile.export_dispatch_profile.registration_exports.length > 0) {
    parts.push(
      `registration_exports=${binaryProfile.export_dispatch_profile.registration_exports.slice(0, 2).join(', ')}`
    )
  }
  if (lifecycleSurface.length > 0) {
    parts.push(`dll_lifecycle=${lifecycleSurface.slice(0, 2).join(', ')}`)
  }
  if (binaryProfile.com_profile.class_factory_exports.length > 0) {
    parts.push(
      `class_factory_exports=${binaryProfile.com_profile.class_factory_exports.slice(0, 2).join(', ')}`
    )
  }
  if (classFactorySurface.length > 0) {
    parts.push(`class_factory_surface=${classFactorySurface.slice(0, 2).join(', ')}`)
  }
  if (binaryProfile.host_interaction_profile.callback_exports.length > 0) {
    parts.push(
      `callback_exports=${binaryProfile.host_interaction_profile.callback_exports.slice(0, 2).join(', ')}`
    )
  }
  if (callbackSurface.length > 0) {
    parts.push(`callback_surface=${callbackSurface.slice(0, 2).join(', ')}`)
  }
  if (binaryProfile.host_interaction_profile.likely_hosted) {
    parts.push('host/plugin interaction surface detected')
  }
  if (binaryProfile.host_interaction_profile.host_hints.length > 0) {
    parts.push(`host_hints=${binaryProfile.host_interaction_profile.host_hints.slice(0, 2).join(', ')}`)
  }
  if (binaryProfile.packed) {
    parts.push('packing signals present')
  }
  return `${parts.join(', ')}.`
}

function augmentWithBinaryProfile(
  triageData: TriageSummaryData,
  binaryProfile?: z.infer<typeof BinaryRoleProfileDataSchema>
): TriageSummaryData {
  if (!binaryProfile) {
    return triageData
  }

  const summaryLine = buildBinaryProfileSummary(binaryProfile)
  const lifecycleSurface = binaryProfile.lifecycle_surface || []
  const classFactorySurface = binaryProfile.com_profile.class_factory_surface || []
  const callbackSurface = binaryProfile.host_interaction_profile.callback_surface || []
  const evidenceLines = dedupe([
    summaryLine,
    ...binaryProfile.analysis_priorities.map((item) => `binary_profile_priority: ${item}`),
    ...binaryProfile.export_dispatch_profile.registration_exports.map(
      (item) => `binary_profile_surface: registration_export=${item}`
    ),
    ...lifecycleSurface.map((item) => `binary_profile_surface: dll_lifecycle=${item}`),
    ...binaryProfile.com_profile.class_factory_exports.map(
      (item) => `binary_profile_surface: class_factory_export=${item}`
    ),
    ...classFactorySurface.map((item) => `binary_profile_surface: class_factory_surface=${item}`),
    ...binaryProfile.host_interaction_profile.callback_exports.map(
      (item) => `binary_profile_surface: callback_export=${item}`
    ),
    ...callbackSurface.map((item) => `binary_profile_surface: callback_surface=${item}`),
    ...binaryProfile.host_interaction_profile.host_hints.map(
      (item) => `binary_profile_surface: host_hint=${item}`
    ),
  ])
  const recommendationSuffix =
    binaryProfile.analysis_priorities.length > 0
      ? ` Binary role priorities: ${binaryProfile.analysis_priorities.join(', ')}.`
      : ''

  return {
    ...triageData,
    summary: `${triageData.summary} ${summaryLine}`,
    evidence: dedupe([...triageData.evidence, ...evidenceLines]),
    binary_profile: binaryProfile,
    recommendation: `${triageData.recommendation}${recommendationSuffix}`.trim(),
    inference: triageData.inference
      ? {
          ...triageData.inference,
          hypotheses: dedupe([
            ...triageData.inference.hypotheses,
            `Binary role profile suggests ${binaryProfile.binary_role}.`,
          ]),
        }
      : triageData.inference,
  }
}

function buildRustProfileSummary(rustProfile: z.infer<typeof RustBinaryAnalyzeDataSchema>): string {
  const parts = [
    `Rust-focused analysis ${rustProfile.suspected_rust ? 'suggests a Rust-oriented binary' : 'did not strongly confirm Rust'} (confidence=${rustProfile.confidence.toFixed(2)})`,
  ]
  if (rustProfile.primary_runtime) {
    parts.push(`runtime=${rustProfile.primary_runtime}`)
  }
  if (rustProfile.crate_hints.length > 0) {
    parts.push(`crate_hints=${rustProfile.crate_hints.slice(0, 4).join(', ')}`)
  }
  if (rustProfile.recovered_function_count > 0) {
    parts.push(`recovered_functions=${rustProfile.recovered_function_count}`)
  }
  if (rustProfile.recovered_symbol_count > 0) {
    parts.push(`recovered_symbols=${rustProfile.recovered_symbol_count}`)
  }
  return `${parts.join(', ')}.`
}

function augmentWithRustProfile(
  triageData: TriageSummaryData,
  rustProfile?: z.infer<typeof RustBinaryAnalyzeDataSchema>
): TriageSummaryData {
  if (!rustProfile) {
    return triageData
  }

  const summaryLine = buildRustProfileSummary(rustProfile)
  const rustPriorityLines = rustProfile.analysis_priorities.map((item) => `rust_analysis_priority: ${item}`)
  const compilerArtifacts = {
    ...(triageData.iocs.compiler_artifacts || {}),
    cargo_paths: dedupe([
      ...(triageData.iocs.compiler_artifacts?.cargo_paths || []),
      ...rustProfile.cargo_paths,
    ]),
    rust_markers: dedupe([
      ...(triageData.iocs.compiler_artifacts?.rust_markers || []),
      ...rustProfile.rust_markers,
    ]),
    library_profile:
      normalizeLibraryProfile(rustProfile.library_profile) ||
      normalizeLibraryProfile(triageData.iocs.compiler_artifacts?.library_profile),
  }
  const recommendationSuffix =
    rustProfile.analysis_priorities.length > 0
      ? ` Rust recovery priorities: ${rustProfile.analysis_priorities.join(', ')}.`
      : ''

  return {
    ...triageData,
    summary: `${triageData.summary} ${summaryLine}`.trim(),
    iocs: {
      ...triageData.iocs,
      compiler_artifacts: compilerArtifacts,
    },
    evidence: dedupe([summaryLine, ...triageData.evidence, ...rustProfile.evidence, ...rustPriorityLines]),
    rust_profile: rustProfile,
    recommendation: `${triageData.recommendation}${recommendationSuffix}`.trim(),
    inference: triageData.inference
      ? {
          ...triageData.inference,
          hypotheses: dedupe([
            ...triageData.inference.hypotheses,
            rustProfile.suspected_rust
              ? 'Rust/toolchain evidence is strong enough to prioritize non-Ghidra function recovery paths.'
              : 'Rust/toolchain evidence remains weak; keep recovery paths heuristic.',
          ]),
          tooling_assessment: triageData.inference.tooling_assessment
            ? {
                ...triageData.inference.tooling_assessment,
                framework_hints: dedupe([
                  ...triageData.inference.tooling_assessment.framework_hints,
                  ...rustProfile.crate_hints,
                ]),
                toolchain_markers: dedupe([
                  ...triageData.inference.tooling_assessment.toolchain_markers,
                  ...rustProfile.runtime_hints,
                ]),
                library_profile:
                  normalizeLibraryProfile(triageData.inference.tooling_assessment.library_profile) ||
                  normalizeLibraryProfile(rustProfile.library_profile),
              }
            : {
                help_text_detected: false,
                cli_surface_detected: false,
                framework_hints: rustProfile.crate_hints,
                toolchain_markers: rustProfile.runtime_hints,
                library_profile: normalizeLibraryProfile(rustProfile.library_profile),
              },
        }
      : triageData.inference,
  }
}

function toolMetrics(startTime: number): { elapsed_ms: number; tool: string } {
  return {
    elapsed_ms: Date.now() - startTime,
    tool: TOOL_NAME,
  }
}

function dedupe(values: string[]): string[] {
  return Array.from(new Set(values.filter((item) => item.trim().length > 0)))
}

function buildEvidenceLineage(dynamicEvidence?: DynamicTraceSummary | null): z.infer<typeof EvidenceLineageSchema> {
  const staticLayer = {
    layer: 'static_only' as const,
    confidence_band: 'baseline' as const,
    artifact_count: 0,
    source_formats: ['static_analysis'],
    evidence_kinds: ['static'],
    source_names: [],
    latest_imported_at: null,
    summary: 'Static analysis evidence from triage, imports, strings, and reconstruction outputs.',
  }

  if (!dynamicEvidence) {
    return {
      layers: [staticLayer],
      latest_runtime_artifact_at: null,
      scope_note: 'No registered runtime artifacts were merged into this report.',
    }
  }

  const runtimeLayers = (dynamicEvidence.confidence_layers || []).map((item) => ({
    layer: item.layer,
    confidence_band: item.confidence_band,
    artifact_count: item.artifact_count,
    source_formats: item.source_formats,
    evidence_kinds: item.evidence_kinds,
    source_names: item.source_names,
    latest_imported_at: item.latest_imported_at,
    summary: item.summary,
  }))

  return {
    layers: [staticLayer, ...runtimeLayers],
    latest_runtime_artifact_at: dynamicEvidence.latest_imported_at || null,
    scope_note:
      dynamicEvidence.scope_note ||
      'Runtime evidence was merged from registered artifacts and may include historical imports.',
  }
}

function buildEvidenceLayerHeadline(lineage: z.infer<typeof EvidenceLineageSchema>): string {
  const labels = lineage.layers.map((item) => item.layer)
  return `Evidence layers: ${labels.join(' -> ')}.`
}

function buildAssessmentConfidencePayload(
  confidence: number,
  evidenceScope: 'all' | 'latest' | 'session',
  lineage?: z.infer<typeof EvidenceLineageSchema>
): z.infer<typeof ReportAssessmentConfidenceSchema> {
  return {
    assessment: buildReportConfidenceSemantics({
      score: confidence,
      evidenceScope,
      runtimeLayers: lineage?.layers.map((item) => item.layer) || ['static_only'],
      executedTracePresent:
        lineage?.layers.some((item) => item.layer === 'executed_trace') || false,
    }),
  }
}

async function loadFunctionExplanationSummaries(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  options?: { scope?: 'all' | 'latest' | 'session'; sessionTag?: string }
): Promise<{
  summaries: Array<z.infer<typeof FunctionExplanationSummarySchema>>
  index: SemanticFunctionExplanationIndex
}> {
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
  return {
    summaries: explanations.slice(0, 6).map((item) => ({
      address: item.address,
      function: item.function,
      behavior: item.behavior,
      summary: item.summary,
      confidence: item.confidence,
      rewrite_guidance: item.rewrite_guidance.slice(0, 4),
      source: item.model_name || item.client_name || null,
    })),
    index,
  }
}

async function loadStaticAnalysisSelections(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  options: { scope?: StaticArtifactScope; sessionTag?: string }
) {
  const [capabilities, peStructure, compilerPacker] = await Promise.all([
    loadStaticAnalysisArtifactSelection<z.infer<typeof StaticCapabilityTriageDataSchema>>(
      workspaceManager,
      database,
      sampleId,
      STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
      options
    ),
    loadStaticAnalysisArtifactSelection<z.infer<typeof PEStructureAnalyzeDataSchema>>(
      workspaceManager,
      database,
      sampleId,
      PE_STRUCTURE_ANALYSIS_ARTIFACT_TYPE,
      options
    ),
    loadStaticAnalysisArtifactSelection<z.infer<typeof CompilerPackerDetectDataSchema>>(
      workspaceManager,
      database,
      sampleId,
      COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE,
      options
    ),
  ])

  return {
    capabilities,
    peStructure,
    compilerPacker,
  }
}

function augmentWithStaticAnalysis(
  triageData: TriageSummaryData,
  staticArtifacts: {
    capabilities?: z.infer<typeof StaticCapabilityTriageDataSchema> | null
    peStructure?: z.infer<typeof PEStructureAnalyzeDataSchema> | null
    compilerPacker?: z.infer<typeof CompilerPackerDetectDataSchema> | null
  }
): TriageSummaryData {
  const evidence = [...triageData.evidence]
  const summaryParts = [triageData.summary]
  const recommendationParts = [triageData.recommendation]
  let threatLevel = triageData.threat_level
  let confidence = triageData.confidence

  if (staticArtifacts.capabilities?.status === 'ready' && staticArtifacts.capabilities.capability_count > 0) {
    const topGroups = Object.entries(staticArtifacts.capabilities.capability_groups || {})
      .sort((left, right) => Number(right[1]) - Number(left[1]))
      .slice(0, 4)
      .map(([key]) => key)
    summaryParts.push(
      `Capability triage matched ${staticArtifacts.capabilities.capability_count} finding(s)${
        topGroups.length > 0 ? ` across ${topGroups.join(', ')}` : ''
      }.`
    )
    evidence.push(
      `Static capability triage matched ${staticArtifacts.capabilities.capability_count} finding(s).`,
      ...(topGroups.length > 0 ? [`Capability groups: ${topGroups.join(', ')}.`] : [])
    )
    recommendationParts.push(
      'Correlate capability groups with code.functions.search, code.functions.reconstruct, or workflow.reconstruct.'
    )
    if (
      threatLevel === 'clean' &&
      topGroups.some((item) =>
        ['network', 'service', 'persistence', 'execution', 'injection', 'command-and-control', 'c2'].includes(
          item.toLowerCase()
        )
      )
    ) {
      threatLevel = 'suspicious'
      confidence = Math.max(confidence, 0.58)
    }
  }

  if (staticArtifacts.peStructure && staticArtifacts.peStructure.status !== 'setup_required') {
    const peSummary = staticArtifacts.peStructure.summary
    summaryParts.push(
      `PE structure recovered ${peSummary.section_count} section(s)${
        peSummary.overlay_present ? ' with an overlay present' : ''
      }.`
    )
    evidence.push(
      `PE structure analysis: sections=${peSummary.section_count}, imports=${peSummary.import_function_count}, exports=${peSummary.export_count}, resources=${peSummary.resource_count}.`,
      ...(peSummary.overlay_present ? ['PE structure analysis detected an overlay.'] : [])
    )
    if (peSummary.overlay_present) {
      recommendationParts.push(
        'Inspect overlay and recovered resources before assuming the file layout is benign or complete.'
      )
      if (threatLevel === 'clean') {
        threatLevel = 'suspicious'
        confidence = Math.max(confidence, 0.56)
      }
    }
  }

  if (staticArtifacts.compilerPacker?.status === 'ready') {
    const summary = staticArtifacts.compilerPacker.summary
    const compilerNames = staticArtifacts.compilerPacker.compiler_findings.slice(0, 3).map((item) => item.name)
    const packerNames = [
      ...staticArtifacts.compilerPacker.packer_findings.slice(0, 3).map((item) => item.name),
      ...staticArtifacts.compilerPacker.protector_findings.slice(0, 3).map((item) => item.name),
    ]
    if (summary.compiler_count + summary.packer_count + summary.protector_count > 0) {
      summaryParts.push(
        packerNames.length > 0
          ? `Toolchain attribution suggests packer/protector signals (${packerNames.join(', ')}).`
          : compilerNames.length > 0
            ? `Toolchain attribution suggests compiler signals (${compilerNames.join(', ')}).`
            : 'Toolchain attribution surfaced additional compiler or packer hints.'
      )
      evidence.push(
        `Compiler/packer attribution: compiler=${summary.compiler_count}, packer=${summary.packer_count}, protector=${summary.protector_count}.`,
        ...(summary.likely_primary_file_type ? [`Attributed primary file type: ${summary.likely_primary_file_type}.`] : [])
      )
    }
    if (summary.packer_count > 0 || summary.protector_count > 0) {
      recommendationParts.push(
        'Treat compiler/packer attribution as a routing hint and verify packed/protected regions with deeper static or runtime analysis.'
      )
      if (threatLevel === 'clean') {
        threatLevel = 'suspicious'
        confidence = Math.max(confidence, 0.6)
      }
    }
  }

  return {
    ...triageData,
    summary: dedupe(summaryParts).join(' '),
    confidence,
    threat_level: threatLevel,
    evidence: dedupe(evidence),
    recommendation: dedupe(recommendationParts).join(' '),
    static_capabilities: staticArtifacts.capabilities || undefined,
    pe_structure: staticArtifacts.peStructure || undefined,
    compiler_packer: staticArtifacts.compilerPacker || undefined,
  }
}

function augmentWithFunctionExplanations(
  triageData: TriageSummaryData,
  functionExplanations: Array<z.infer<typeof FunctionExplanationSummarySchema>>
): TriageSummaryData {
  if (functionExplanations.length === 0) {
    return triageData
  }

  return {
    ...triageData,
    evidence: dedupe([
      ...triageData.evidence,
      `External semantic explanations are available for ${functionExplanations.length} function(s).`,
    ]),
    function_explanations: functionExplanations,
    recommendation: `${triageData.recommendation} Cross-check the attached function explanations before treating rewrite output as source-equivalent.`,
  }
}

function augmentWithDynamicEvidence(
  triageData: TriageSummaryData,
  dynamicEvidence: DynamicTraceSummary
): TriageSummaryData {
  const evidenceLineage = buildEvidenceLineage(dynamicEvidence)
  const suspiciousApis = dedupe([
    ...(triageData.iocs.high_value_iocs?.suspicious_apis || []),
    ...dynamicEvidence.high_signal_apis,
  ])

  const updatedThreatLevel =
    dynamicEvidence.executed && dynamicEvidence.high_signal_apis.length > 0 && triageData.threat_level === 'clean'
      ? 'suspicious'
      : triageData.threat_level

  const updatedClassification =
    dynamicEvidence.executed &&
    dynamicEvidence.high_signal_apis.length > 0 &&
    triageData.inference?.classification === 'benign'
      ? 'suspicious'
      : triageData.inference?.classification

  return {
    ...triageData,
    summary: `${triageData.summary} ${buildEvidenceLayerHeadline(evidenceLineage)} Runtime evidence: ${dynamicEvidence.summary}`,
    threat_level: updatedThreatLevel,
    iocs: {
      ...triageData.iocs,
      high_value_iocs: {
        ...(triageData.iocs.high_value_iocs || {}),
        suspicious_apis: suspiciousApis,
      },
    },
    evidence: dedupe([
      buildEvidenceLayerHeadline(evidenceLineage),
      ...triageData.evidence,
      ...dynamicEvidence.evidence,
      ...(dynamicEvidence.protections || []).length > 0
        ? [`Runtime protections: ${(dynamicEvidence.protections || []).slice(0, 4).join(', ')}.`]
        : [],
      ...(dynamicEvidence.region_owners || []).length > 0
        ? [`Runtime region owners: ${(dynamicEvidence.region_owners || []).slice(0, 4).join(', ')}.`]
        : [],
      ...(dynamicEvidence.observed_modules || []).length > 0
        ? [`Runtime observed modules: ${(dynamicEvidence.observed_modules || []).slice(0, 4).join(', ')}.`]
        : [],
      ...(dynamicEvidence.segment_names || []).length > 0
        ? [`Runtime segment names: ${(dynamicEvidence.segment_names || []).slice(0, 4).join(', ')}.`]
        : [],
    ]),
    evidence_lineage: evidenceLineage,
    evidence_weights: {
      import: triageData.evidence_weights?.import ?? 0.33,
      string: triageData.evidence_weights?.string ?? 0.33,
      runtime: Math.max(
        triageData.evidence_weights?.runtime ?? 0.2,
        dynamicEvidence.executed ? 0.78 : 0.58
      ),
    },
    inference: triageData.inference
      ? {
          ...triageData.inference,
          classification: updatedClassification || triageData.inference.classification,
          hypotheses: dedupe([
            ...triageData.inference.hypotheses,
            ...dynamicEvidence.stages.map(
              (item) => `Imported runtime evidence indicates stage: ${item}.`
            ),
            ...(dynamicEvidence.observed_modules || [])
              .slice(0, 3)
              .map((item) => `Imported runtime evidence observed module: ${item}.`),
            ...(dynamicEvidence.segment_names || [])
              .slice(0, 3)
              .map((item) => `Imported runtime evidence observed segment: ${item}.`),
          ]),
          false_positive_risks: dedupe([
            ...triageData.inference.false_positive_risks,
            dynamicEvidence.executed
              ? 'Imported runtime evidence reduces uncertainty from string-only indicators.'
              : 'Imported memory/hybrid evidence still requires correlation with execution trace or function-level analysis.',
          ]),
        }
      : {
          classification: dynamicEvidence.high_signal_apis.length > 0 ? 'suspicious' : 'unknown',
          hypotheses: dynamicEvidence.stages.map(
            (item) => `Imported runtime evidence indicates stage: ${item}.`
          ),
          false_positive_risks: [
            dynamicEvidence.executed
              ? 'Imported runtime evidence should still be correlated with static function ownership.'
              : 'Memory snapshot evidence alone can overstate execution confidence without trace correlation.',
          ],
        },
  }
}

function createMinimalDotnetFallback(
  triageResult: WorkerResult,
  startTime: number,
  functionExplanations: Array<z.infer<typeof FunctionExplanationSummarySchema>> = [],
  provenance?: z.infer<typeof AnalysisProvenanceSchema>,
  ghidraExecution?: z.infer<typeof GhidraExecutionSummarySchema> | null,
  evidenceScope: 'all' | 'latest' | 'session' = 'all',
  detailLevel: 'compact' | 'full' = 'compact',
  binaryProfile?: z.infer<typeof BinaryRoleProfileDataSchema>,
  rustProfile?: z.infer<typeof RustBinaryAnalyzeDataSchema>
): WorkerResult {
  const triageErrors = triageResult.errors || []
  const warnings = [
    'report.summarize(mode=dotnet) is not fully implemented; returned degraded fallback output.',
    ...(triageResult.warnings || []),
  ]

  if (triageErrors.length > 0) {
    warnings.push(`dotnet fallback triage failed: ${triageErrors.join('; ')}`)
  }

  return {
    ok: true,
    data: {
      detail_level: detailLevel,
      ...buildCoverageEnvelope({
        coverageLevel: 'quick',
        completionState: 'degraded',
        sampleSizeTier: 'small',
        analysisBudgetProfile: 'balanced',
        coverageGaps: [
          {
            domain: 'triage',
            status: 'degraded',
            reason: 'Dotnet-specific summarize path is unavailable and triage fallback failed.',
          },
          {
            domain: 'dotnet_structure',
            status: 'missing',
            reason: 'No .NET-specific reconstruction or export data is present in this fallback result.',
          },
        ],
        knownFindings: ['Dotnet-specific summarize mode is currently unavailable.'],
        unverifiedAreas: ['Behavior, structure, and validation remain largely unverified in this minimal fallback.'],
        upgradePaths: [
          {
            tool: 'workflow.reconstruct',
            purpose: 'Recover structure through the main reconstruction workflow.',
            closes_gaps: ['dotnet_structure'],
            expected_coverage_gain: 'Adds managed export artifacts and deeper structure than the placeholder fallback.',
            cost_tier: 'high',
          },
        ],
      }),
      summary:
        '[dotnet fallback] Dotnet-specific summarize pipeline is unavailable and triage fallback failed. Returning minimal placeholder report.',
      confidence: 0.2,
      threat_level: 'unknown',
      iocs: {
        suspicious_imports: [],
        suspicious_strings: [],
        yara_matches: [],
      },
      evidence: [
        'Dotnet mode unavailable; triage fallback failed.',
        ...triageErrors.map((item) => `triage_error: ${item}`),
        ...(binaryProfile ? [buildBinaryProfileSummary(binaryProfile)] : []),
        ...(rustProfile ? [buildRustProfileSummary(rustProfile)] : []),
      ],
      confidence_semantics: buildAssessmentConfidencePayload(0.2, evidenceScope),
      binary_profile: binaryProfile,
      rust_profile: rustProfile,
      provenance,
      ghidra_execution: ghidraExecution,
      function_explanations: functionExplanations.length > 0 ? functionExplanations : undefined,
      inference: {
        classification: 'unknown',
        hypotheses: [
          'Insufficient evidence to infer behavior because dotnet mode is unavailable and triage fallback failed.',
        ],
        false_positive_risks: ['No triage evidence is available in this degraded fallback result.'],
      },
      recommendation:
        `Re-run after ensuring workspace/original sample file exists, then use workflow.reconstruct or dotnet.reconstruct.export for .NET-specific structure.${binaryProfile?.analysis_priorities?.length ? ` Binary role priorities: ${binaryProfile.analysis_priorities.join(', ')}.` : ''}${rustProfile?.analysis_priorities?.length ? ` Rust recovery priorities: ${rustProfile.analysis_priorities.join(', ')}.` : ''}`,
      recommended_next_tools: ['workflow.summarize', 'artifact.read', 'workflow.reconstruct'],
      next_actions: [
        'Use workflow.summarize for staged reporting once deeper analysis artifacts exist.',
        'Use workflow.reconstruct or dotnet.reconstruct.export for .NET-specific structure.',
      ],
    },
    warnings,
    errors: triageErrors.length > 0 ? triageErrors : undefined,
    metrics: toolMetrics(startTime),
  }
}

function createDynamicEvidenceFallback(
  dynamicEvidence: DynamicTraceSummary,
  triageResult: WorkerResult,
  startTime: number,
  functionExplanations: Array<z.infer<typeof FunctionExplanationSummarySchema>> = [],
  provenance?: z.infer<typeof AnalysisProvenanceSchema>,
  ghidraExecution?: z.infer<typeof GhidraExecutionSummarySchema> | null,
  evidenceScope: 'all' | 'latest' | 'session' = 'all',
  detailLevel: 'compact' | 'full' = 'compact',
  binaryProfile?: z.infer<typeof BinaryRoleProfileDataSchema>,
  rustProfile?: z.infer<typeof RustBinaryAnalyzeDataSchema>
): WorkerResult {
  const evidenceLineage = buildEvidenceLineage(dynamicEvidence)
  const threatLevel =
    dynamicEvidence.high_signal_apis.length > 0 ? 'suspicious' : dynamicEvidence.executed ? 'suspicious' : 'unknown'

  return {
    ok: true,
    data: {
      detail_level: detailLevel,
      ...buildCoverageEnvelope({
        coverageLevel: 'quick',
        completionState: 'degraded',
        sampleSizeTier: 'small',
        analysisBudgetProfile: 'balanced',
        coverageGaps: [
          {
            domain: 'static_triage',
            status: 'degraded',
            reason: 'Static triage failed, so this report is driven by imported runtime evidence only.',
          },
          {
            domain: 'function_attribution',
            status: 'missing',
            reason: 'Runtime evidence has not yet been mapped to precise function ownership.',
          },
        ],
        knownFindings: dynamicEvidence.evidence.slice(0, 4),
        suspectedFindings: dynamicEvidence.stages.map((item) => `Runtime stage observed: ${item}`),
        unverifiedAreas: ['Full static attribution and code-level ownership remain unverified in the runtime-evidence fallback.'],
        upgradePaths: [
          {
            tool: 'workflow.reconstruct',
            purpose: 'Correlate imported runtime evidence with reconstructed ownership.',
            closes_gaps: ['function_attribution'],
            expected_coverage_gain: 'Adds plan and export artifacts that tie runtime signals back to concrete code locations.',
            cost_tier: 'high',
          },
        ],
      }),
      summary:
        `Triage pipeline failed, but imported runtime evidence is available. ${buildEvidenceLayerHeadline(evidenceLineage)} ${dynamicEvidence.summary}${binaryProfile ? ` ${buildBinaryProfileSummary(binaryProfile)}` : ''}${rustProfile ? ` ${buildRustProfileSummary(rustProfile)}` : ''}`,
      confidence: dynamicEvidence.executed ? 0.66 : 0.5,
      threat_level: threatLevel,
      iocs: {
        suspicious_imports: [],
        suspicious_strings: [],
        yara_matches: [],
        high_value_iocs: {
          suspicious_apis: dynamicEvidence.high_signal_apis,
        },
      },
      evidence: dedupe([
        buildEvidenceLayerHeadline(evidenceLineage),
        ...dynamicEvidence.evidence,
        ...(binaryProfile ? [buildBinaryProfileSummary(binaryProfile)] : []),
        ...(rustProfile ? [buildRustProfileSummary(rustProfile)] : []),
      ]),
      evidence_lineage: evidenceLineage,
      confidence_semantics: buildAssessmentConfidencePayload(
        dynamicEvidence.executed ? 0.66 : 0.5,
        evidenceScope,
        evidenceLineage
      ),
      binary_profile: binaryProfile,
      rust_profile: rustProfile,
      provenance,
      ghidra_execution: ghidraExecution,
      function_explanations: functionExplanations.length > 0 ? functionExplanations : undefined,
      evidence_weights: {
        import: 0.05,
        string: 0.1,
        runtime: dynamicEvidence.executed ? 0.85 : 0.68,
      },
      inference: {
        classification: threatLevel === 'unknown' ? 'unknown' : 'suspicious',
        hypotheses: dynamicEvidence.stages.map(
          (item) => `Imported runtime evidence indicates stage: ${item}.`
        ),
        false_positive_risks: [
          dynamicEvidence.executed
            ? 'Runtime evidence is imported and should still be correlated with static ownership.'
            : 'Memory/hybrid evidence is suggestive but not equivalent to a fully executed trace.',
        ],
      },
      recommendation:
        `Correlate imported runtime evidence with code.functions.search, code.functions.reconstruct, and code.reconstruct.export to assign concrete function ownership.${binaryProfile?.analysis_priorities?.length ? ` Binary role priorities: ${binaryProfile.analysis_priorities.join(', ')}.` : ''}${rustProfile?.analysis_priorities?.length ? ` Rust recovery priorities: ${rustProfile.analysis_priorities.join(', ')}.` : ''}`,
      recommended_next_tools: ['workflow.summarize', 'artifact.read', 'workflow.reconstruct'],
      next_actions: [
        'Use workflow.summarize for staged reporting once deeper analysis artifacts are available.',
        'Correlate imported runtime evidence with reconstruct/export tooling for concrete ownership.',
      ],
    },
    warnings: [
      'Triage pipeline failed; returned imported runtime-evidence fallback.',
      ...(triageResult.warnings || []),
    ],
    errors: triageResult.errors,
    metrics: toolMetrics(startTime),
  }
}

function parseDbCallees(raw: string | null): string[] {
  if (!raw) {
    return []
  }
  try {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed)
      ? parsed.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
      : []
  } catch {
    return []
  }
}

function normalizeFunctionsForExplanationGraphs(functions: DbFunction[]) {
  return functions
    .slice()
    .sort((left, right) => (right.score || 0) - (left.score || 0))
    .map((func) => ({
      address: func.address,
      name: func.name || func.address,
      size: func.size || 0,
      score: func.score || 0,
      callerCount: func.caller_count || 0,
      calleeCount: func.callee_count || 0,
      callees: parseDbCallees(func.callees),
      calledApis: parseDbCallees(func.callees),
      referencedStrings: [],
    }))
}

async function buildPersistedExplanationGraphs(params: {
  workspaceManager: WorkspaceManager
  database: DatabaseManager
  sampleId: string
  sessionTag?: string | null
  functions: DbFunction[]
  persistedStateVisibility?: {
    persisted_run_id?: string | null
    loaded_run_stages?: string[]
    deferred_requirements?: string[]
  }
  coverage: z.infer<typeof CoverageEnvelopeSchema>
}): Promise<{
  graphs: ExplanationGraphDigest[]
  artifactRefs: ArtifactRef[]
}> {
  const graphs: ExplanationGraphDigest[] = []
  const artifactRefs: ArtifactRef[] = []
  const normalizedFunctions = normalizeFunctionsForExplanationGraphs(params.functions)

  if (normalizedFunctions.length > 0) {
    const callGraph = generateCallGraph(normalizedFunctions, {
      sampleId: params.sampleId,
      maxNodes: 12,
    })
    const callGraphArtifact = await persistExplanationGraphArtifact(
      params.workspaceManager,
      params.database,
      params.sampleId,
      {
        schema_version: 1,
        sample_id: params.sampleId,
        created_at: new Date().toISOString(),
        ...callGraph.explanation,
        nodes: callGraph.nodes.map((node) => ({
          id: node.id,
          label: `${node.name} (${node.address})`,
          kind: node.isSuspicious ? 'suspicious_function' : 'function',
          confidence_state: node.confidence_state,
        })),
        edges: callGraph.edges.map((edge) => ({
          source: edge.source,
          target: edge.target,
          relation: 'calls',
          label: String(edge.callCount),
          confidence_state: edge.confidence_state,
        })),
        serializers: {
          json: true,
        },
      },
      {
        sessionTag: params.sessionTag,
        filePrefix: 'call_graph',
      }
    )
    graphs.push(attachExplanationArtifactRef(callGraph.explanation, callGraphArtifact))
    artifactRefs.push(callGraphArtifact)

    const dataFlow = generateDataFlow(normalizedFunctions, {
      sampleId: params.sampleId,
      maxNodes: 8,
    })
    const dataFlowArtifact = await persistExplanationGraphArtifact(
      params.workspaceManager,
      params.database,
      params.sampleId,
      {
        schema_version: 1,
        sample_id: params.sampleId,
        created_at: new Date().toISOString(),
        ...dataFlow.explanation,
        nodes: dataFlow.nodes.map((node) => ({
          id: node.id,
          label: node.dataType ? `${node.name} (${node.dataType})` : node.name,
          kind: node.type,
          confidence_state: node.confidence_state,
        })),
        edges: dataFlow.edges.map((edge) => ({
          source: edge.source,
          target: edge.target,
          relation: edge.dataType,
          label: edge.label,
          confidence_state: edge.confidence_state,
        })),
        serializers: {
          json: true,
        },
      },
      {
        sessionTag: params.sessionTag,
        filePrefix: 'data_flow',
      }
    )
    graphs.push(attachExplanationArtifactRef(dataFlow.explanation, dataFlowArtifact))
    artifactRefs.push(dataFlowArtifact)
  }

  const cryptoSelection = await loadCryptoPlanningArtifactSelection<{
    algorithms?: unknown[]
  }>(
    params.workspaceManager,
    params.database,
    params.sampleId,
    CRYPTO_IDENTIFICATION_ARTIFACT_TYPE,
    {
      scope: 'latest',
      sessionTag: params.sessionTag || undefined,
    }
  )
  const cryptoAlgorithms = Array.isArray(cryptoSelection.latest_payload?.algorithms)
    ? cryptoSelection.latest_payload.algorithms
        .map((item) => CryptoFindingSchema.safeParse(item))
        .filter((item) => item.success)
        .map((item) => item.data)
    : []
  if (cryptoAlgorithms.length > 0) {
    const cryptoGraph = generateCryptoFlow(
      cryptoAlgorithms.map((item) => ({
        algorithm: item.algorithm_name || item.algorithm_family,
        confidence: item.confidence,
        functions:
          item.function || item.address
            ? [
                {
                  address: item.address || 'unknown',
                  name: item.function || item.address || 'unknown',
                  apis: item.source_apis,
                },
              ]
            : [],
      })),
      {
        sampleId: params.sampleId,
        maxNodes: 6,
      }
    )
    const cryptoGraphArtifact = await persistExplanationGraphArtifact(
      params.workspaceManager,
      params.database,
      params.sampleId,
      {
        schema_version: 1,
        sample_id: params.sampleId,
        created_at: new Date().toISOString(),
        ...cryptoGraph.explanation,
        provenance: [
          ...cryptoGraph.explanation.provenance,
          ...(cryptoSelection.latest_artifact
            ? [
                {
                  kind: 'artifact' as const,
                  label: 'latest_crypto_identification_artifact',
                  detail: cryptoSelection.scope_note,
                  artifact_ref: cryptoSelection.latest_artifact,
                },
              ]
            : []),
        ],
        nodes: cryptoGraph.nodes.map((node) => ({
          id: node.id,
          label: node.label,
          kind: node.type,
          confidence_state: node.confidence_state,
        })),
        edges: cryptoGraph.edges.map((edge) => ({
          source: edge.source,
          target: edge.target,
          relation: edge.type,
          label: edge.label,
          confidence_state: edge.confidence_state,
        })),
        serializers: {
          json: true,
        },
      },
      {
        sessionTag: params.sessionTag,
        filePrefix: 'crypto_flow',
      }
    )
    graphs.push(attachExplanationArtifactRef(cryptoGraph.explanation, cryptoGraphArtifact))
    artifactRefs.push(cryptoGraphArtifact)
  }

  const runtimeGraph = buildRuntimeStageExplanationGraph({
    sample_id: params.sampleId,
    completed_stages: params.persistedStateVisibility?.loaded_run_stages || [],
    deferred_requirements: params.persistedStateVisibility?.deferred_requirements || [],
    recommended_next_tools: ['workflow.analyze.status', 'workflow.analyze.promote', 'workflow.summarize'],
    coverage_gaps: (params.coverage.coverage_gaps || []).reduce<
      Array<{ domain: string; status: string; reason: string }>
    >((acc, item) => {
      if (
        item &&
        typeof item.domain === 'string' &&
        typeof item.status === 'string' &&
        typeof item.reason === 'string'
      ) {
        acc.push({
          domain: item.domain,
          status: item.status,
          reason: item.reason,
        })
      }
      return acc
    }, []),
  })
  const runtimeArtifact = await persistExplanationGraphArtifact(
    params.workspaceManager,
    params.database,
    params.sampleId,
    runtimeGraph,
    {
      sessionTag: params.sessionTag,
      filePrefix: 'runtime_stage',
    }
  )
  graphs.push(attachExplanationArtifactRef(runtimeGraph, runtimeArtifact))
  artifactRefs.push(runtimeArtifact)

  return {
    graphs,
    artifactRefs,
  }
}

function buildCompactReportData(params: {
  sampleId: string
  detailLevel: 'compact' | 'full'
  triageData: TriageSummaryData
  evidenceScope: 'all' | 'latest' | 'session'
  provenance?: z.infer<typeof AnalysisProvenanceSchema>
  ghidraExecution?: z.infer<typeof GhidraExecutionSummarySchema> | null
  selectionDiffs?: z.infer<typeof AnalysisSelectionDiffSchema>
  functionExplanations: Array<z.infer<typeof FunctionExplanationSummarySchema>>
  explanationGraphs: ExplanationGraphDigest[]
  artifactRefs: {
    supporting: ArtifactRef[]
    runtime?: ArtifactRef[]
    static_capabilities?: ArtifactRef[]
    pe_structure?: ArtifactRef[]
    compiler_packer?: ArtifactRef[]
    semantic_explanations?: ArtifactRef[]
    explanation_graphs?: ArtifactRef[]
  }
}) {
  const evidenceLineage =
    params.triageData.evidence_lineage || buildEvidenceLineage(undefined)
  const confidenceSemantics =
    params.triageData.confidence_semantics ||
    buildAssessmentConfidencePayload(params.triageData.confidence, params.evidenceScope, evidenceLineage)
  const triageCoverageCandidate = CoverageEnvelopeSchema.safeParse(params.triageData)
  const triageCoverage = triageCoverageCandidate.success ? triageCoverageCandidate.data : undefined
  const triageDigest = buildTriageStageDigest({
    sample_id: params.sampleId,
    summary: params.triageData.summary,
    confidence: params.triageData.confidence,
    threat_level: params.triageData.threat_level,
    iocs: params.triageData.iocs,
    evidence: params.triageData.evidence,
    evidence_lineage: evidenceLineage,
    confidence_semantics: confidenceSemantics,
    recommendation: params.triageData.recommendation,
    source_artifact_refs: params.artifactRefs.supporting,
    coverage: triageCoverage,
  })

  const staticDigest = buildStaticStageDigest({
    sample_id: params.sampleId,
    binary_profile_summary: buildBinaryProfileDigest(params.triageData.binary_profile),
    rust_profile_summary: buildRustProfileDigest(params.triageData.rust_profile),
    static_capability_summary: buildStaticCapabilityDigest(params.triageData.static_capabilities),
    pe_structure_summary: buildPEStructureDigest(params.triageData.pe_structure),
    compiler_packer_summary: buildCompilerPackerDigest(params.triageData.compiler_packer),
    semantic_explanation_summary: buildSemanticExplanationDigest(params.functionExplanations),
    key_findings: dedupe([
      buildBinaryProfileDigest(params.triageData.binary_profile)?.summary || '',
      buildRustProfileDigest(params.triageData.rust_profile)?.summary || '',
      buildStaticCapabilityDigest(params.triageData.static_capabilities)?.summary || '',
      buildPEStructureDigest(params.triageData.pe_structure)?.summary || '',
      buildCompilerPackerDigest(params.triageData.compiler_packer)?.summary || '',
      buildSemanticExplanationDigest(params.functionExplanations)?.summary || '',
    ]),
    recommendation: params.triageData.recommendation,
    source_artifact_refs: params.artifactRefs.supporting,
    coverage: triageCoverage
      ? buildCoverageEnvelope({
          coverageLevel: 'static_core',
          completionState: triageCoverage.completion_state === 'completed' ? 'bounded' : triageCoverage.completion_state,
          sampleSizeTier: triageCoverage.sample_size_tier,
          analysisBudgetProfile: triageCoverage.analysis_budget_profile,
          downgradeReasons: triageCoverage.downgrade_reasons,
          coverageGaps: [
            ...triageCoverage.coverage_gaps,
            {
              domain: 'reconstruction_export',
              status: 'missing',
              reason: 'Compact report mode stops before source-like reconstruction export.',
            },
          ],
          confidenceByDomain: triageCoverage.confidence_by_domain,
          knownFindings: triageCoverage.known_findings,
          suspectedFindings: triageCoverage.suspected_findings,
          unverifiedAreas: triageCoverage.unverified_areas,
          upgradePaths: triageCoverage.upgrade_paths,
        })
      : undefined,
  })
  const coverage = buildCoverageEnvelope({
    coverageLevel: staticDigest.coverage_level,
    completionState: staticDigest.completion_state,
    sampleSizeTier: staticDigest.sample_size_tier,
    analysisBudgetProfile: staticDigest.analysis_budget_profile,
    downgradeReasons: [
      ...triageDigest.downgrade_reasons,
      ...staticDigest.downgrade_reasons,
    ],
    coverageGaps: [
      ...triageDigest.coverage_gaps,
      ...staticDigest.coverage_gaps,
    ],
    confidenceByDomain: {
      ...triageDigest.confidence_by_domain,
      ...staticDigest.confidence_by_domain,
    },
    knownFindings: [
      ...triageDigest.known_findings,
      ...staticDigest.known_findings,
    ],
    suspectedFindings: [
      ...triageDigest.suspected_findings,
      ...staticDigest.suspected_findings,
    ],
    unverifiedAreas: [
      ...triageDigest.unverified_areas,
      ...staticDigest.unverified_areas,
    ],
    upgradePaths: [
      ...triageDigest.upgrade_paths,
      ...staticDigest.upgrade_paths,
    ],
  })

  const recommendedNextTools = [
    'workflow.summarize',
    'artifact.read',
    'artifacts.list',
    'ghidra.analyze',
    'workflow.reconstruct',
  ]
  const nextActions = [
    'Use workflow.summarize for staged triage/static/deep/final reporting instead of requesting one monolithic final payload.',
    'Use artifact.read or artifacts.list on artifact_refs when you need deeper supporting detail, including persisted explanation graph artifacts.',
    'Continue with ghidra.analyze and workflow.reconstruct when you need code-level reverse engineering instead of a bounded report digest.',
  ]

  return {
    detail_level: params.detailLevel,
    ...coverage,
    summary: triageDigest.summary,
    confidence: triageDigest.confidence,
    threat_level: triageDigest.threat_level,
    iocs: triageDigest.iocs,
    evidence: triageDigest.evidence,
    evidence_lineage: triageDigest.evidence_lineage,
    confidence_semantics: triageDigest.confidence_semantics,
    binary_profile_summary: staticDigest.binary_profile_summary,
    rust_profile_summary: staticDigest.rust_profile_summary,
    static_capability_summary: staticDigest.static_capability_summary,
    pe_structure_summary: staticDigest.pe_structure_summary,
    compiler_packer_summary: staticDigest.compiler_packer_summary,
    semantic_explanation_summary: staticDigest.semantic_explanation_summary,
    provenance: params.provenance,
    ghidra_execution: params.ghidraExecution,
    selection_diffs:
      params.selectionDiffs && Object.keys(params.selectionDiffs).length > 0
        ? params.selectionDiffs
        : undefined,
    explanation_graphs: params.explanationGraphs,
    artifact_refs: params.artifactRefs,
    truncation: {
      ...(triageDigest.truncation || {}),
      ...(staticDigest.truncation || {}),
    },
    recommendation: triageDigest.recommendation,
    recommended_next_tools: recommendedNextTools,
    next_actions: nextActions,
  }
}

function estimateJsonChars(value: unknown): number {
  try {
    return JSON.stringify(value).length
  } catch {
    return Number.MAX_SAFE_INTEGER
  }
}

function stripArtifactRefMetadata(ref: z.infer<typeof SummaryArtifactRefSchema>) {
  return {
    id: ref.id,
    type: ref.type,
    path: ref.path,
    sha256: ref.sha256,
    mime: ref.mime,
  }
}

function boundArtifactRefGroup(
  refs: z.infer<typeof SummaryArtifactRefSchema>[] | undefined
): {
  refs?: z.infer<typeof SummaryArtifactRefSchema>[]
  budget?: z.infer<typeof DigestTruncationSchema>[string]
} {
  if (!refs || refs.length === 0) {
    return {}
  }
  const limited = limitArray('stage_artifacts', refs, (ref) => stripArtifactRefMetadata(ref))
  return {
    refs: limited.values,
    budget: limited.budget,
  }
}

function boundInlineReportPayload(data: ReportSummarizeData): {
  data: ReportSummarizeData
  warnings: string[]
} {
  let bounded: ReportSummarizeData = { ...data }
  if (estimateJsonChars(bounded) <= REPORT_INLINE_PAYLOAD_BUDGET_CHARS) {
    return { data: bounded, warnings: [] }
  }

  const warnings: string[] = []
  const omittedFields: string[] = []
  const heavyFieldOrder: Array<keyof ReportSummarizeData> = [
    'static_capabilities',
    'pe_structure',
    'compiler_packer',
    'function_explanations',
    'selection_diffs',
    'ghidra_execution',
    'binary_profile',
    'rust_profile',
    'provenance',
  ]

  for (const field of heavyFieldOrder) {
    if (bounded[field] === undefined) {
      continue
    }
    if (estimateJsonChars(bounded) <= REPORT_INLINE_PAYLOAD_BUDGET_CHARS) {
      break
    }
    omittedFields.push(String(field))
    delete bounded[field]
  }

  if (bounded.artifact_refs) {
    const artifactBudgets: Array<[string, z.infer<typeof DigestTruncationSchema>[string] | undefined]> = []
    const supporting = boundArtifactRefGroup(bounded.artifact_refs.supporting)
    const runtime = boundArtifactRefGroup(bounded.artifact_refs.runtime)
    const staticCapabilities = boundArtifactRefGroup(bounded.artifact_refs.static_capabilities)
    const peStructure = boundArtifactRefGroup(bounded.artifact_refs.pe_structure)
    const compilerPacker = boundArtifactRefGroup(bounded.artifact_refs.compiler_packer)
    const semanticExplanations = boundArtifactRefGroup(bounded.artifact_refs.semantic_explanations)
    const explanationGraphs = boundArtifactRefGroup(bounded.artifact_refs.explanation_graphs)
    bounded = {
      ...bounded,
      artifact_refs: {
        supporting: supporting.refs || [],
        runtime: runtime.refs,
        static_capabilities: staticCapabilities.refs,
        pe_structure: peStructure.refs,
        compiler_packer: compilerPacker.refs,
        semantic_explanations: semanticExplanations.refs,
        explanation_graphs: explanationGraphs.refs,
      },
    }
    artifactBudgets.push(['artifact_refs_supporting', supporting.budget])
    artifactBudgets.push(['artifact_refs_runtime', runtime.budget])
    artifactBudgets.push(['artifact_refs_static_capabilities', staticCapabilities.budget])
    artifactBudgets.push(['artifact_refs_pe_structure', peStructure.budget])
    artifactBudgets.push(['artifact_refs_compiler_packer', compilerPacker.budget])
    artifactBudgets.push(['artifact_refs_semantic_explanations', semanticExplanations.budget])
    artifactBudgets.push(['artifact_refs_explanation_graphs', explanationGraphs.budget])
    const truncation = {
      ...(bounded.truncation || {}),
      ...Object.fromEntries(artifactBudgets.filter(([, value]) => Boolean(value))),
    }
    bounded.truncation = Object.keys(truncation).length > 0 ? truncation : bounded.truncation
  }

  if (omittedFields.length > 0 || estimateJsonChars(bounded) > REPORT_INLINE_PAYLOAD_BUDGET_CHARS) {
    bounded.truncation = {
      ...(bounded.truncation || {}),
      inline_payload_budget: {
        total: heavyFieldOrder.length,
        kept: heavyFieldOrder.length - omittedFields.length,
        limit: heavyFieldOrder.length,
        truncated: omittedFields.length > 0,
        omitted: omittedFields.length,
      },
    }
    warnings.push(
      `Inline report payload was bounded to stay within transport limits. ${omittedFields.length > 0 ? `Omitted heavy fields: ${omittedFields.join(', ')}. ` : ''}Use artifact.read on artifact_refs or workflow.summarize for staged detail.`
    )
  }

  return { data: bounded, warnings }
}

export function createReportSummarizeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  deps?: {
    triageHandler?: (args: ToolArgs) => Promise<WorkerResult>
    binaryRoleProfileHandler?: (args: ToolArgs) => Promise<WorkerResult>
    rustBinaryAnalyzeHandler?: (args: ToolArgs) => Promise<WorkerResult>
  }
) {
  const triageHandler =
    deps?.triageHandler || createTriageWorkflowHandler(workspaceManager, database, cacheManager)
  const binaryRoleProfileHandler =
    deps?.binaryRoleProfileHandler ||
    createBinaryRoleProfileHandler(workspaceManager, database, cacheManager)
  const rustBinaryAnalyzeHandler =
    deps?.rustBinaryAnalyzeHandler ||
    createRustBinaryAnalyzeHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const parsedInput = ReportSummarizeInputSchema.parse(args)
      const sample = database.findSample(parsedInput.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${parsedInput.sample_id}`],
        }
      }
      const sampleSizeTier = classifySampleSizeTier(sample.size)
      const effectiveDetailLevel =
        parsedInput.detail_level === 'full' &&
        (sampleSizeTier === 'large' || sampleSizeTier === 'oversized')
          ? 'compact'
          : parsedInput.detail_level
      const input =
        effectiveDetailLevel === parsedInput.detail_level
          ? parsedInput
          : {
              ...parsedInput,
              detail_level: effectiveDetailLevel,
            }
      const warnings: string[] = []
      if (effectiveDetailLevel !== parsedInput.detail_level) {
        warnings.push(
          `detail_level=${parsedInput.detail_level} was downgraded to compact because sample_size_tier=${sampleSizeTier} should stay artifact-first and bounded.`
        )
      }
      const analyses = database.findAnalysesBySample(input.sample_id)
      const latestRun = database
        .findAnalysisRunsBySample(input.sample_id)
        .sort((left, right) => right.updated_at.localeCompare(left.updated_at))[0] || null
      const parseRunStagePayload = (stageName: string): Record<string, unknown> | null => {
        if (!latestRun) {
          return null
        }
        const stage = database.findAnalysisRunStage(latestRun.id, stageName)
        if (!stage?.result_json) {
          return null
        }
        try {
          const parsed = JSON.parse(stage.result_json) as Record<string, unknown>
          return parsed && typeof parsed === 'object' ? parsed : null
        } catch {
          return null
        }
      }

      const dynamicEvidence = await loadDynamicTraceEvidence(workspaceManager, database, input.sample_id, {
        evidenceScope: input.evidence_scope,
        sessionTag: input.evidence_session_tag,
      })
      if (input.force_refresh) {
        warnings.push(
          'report.summarize is persisted-state only in the converged runtime; force_refresh does not trigger fresh heavy analysis.'
        )
      }
      const fastProfilePayload = parseRunStagePayload('fast_profile')
      const enrichStaticPayload = parseRunStagePayload('enrich_static')
      const reusedStageNames = [
        fastProfilePayload ? 'fast_profile' : null,
        enrichStaticPayload ? 'enrich_static' : null,
      ].filter((item): item is string => Boolean(item))
      const persistedStateVisibility = PersistedStateVisibilitySchema.parse({
        persisted_only: true,
        persisted_run_id: latestRun?.id || null,
        reused_stage_names: reusedStageNames,
        deferred_requirements: [
          ...(enrichStaticPayload ? [] : ['enrich_static: persisted static enrichment is not available yet.']),
          ...(parseRunStagePayload('function_map') ? [] : ['function_map: function-level attribution has not been persisted yet.']),
          ...(parseRunStagePayload('reconstruct') ? [] : ['reconstruct: source-like reconstruction/export remains deferred.']),
        ],
      })
      const stageStatePayloads = [
        fastProfilePayload,
        enrichStaticPayload,
        parseRunStagePayload('function_map'),
        parseRunStagePayload('reconstruct'),
        parseRunStagePayload('dynamic_plan'),
        parseRunStagePayload('dynamic_execute'),
        parseRunStagePayload('summarize'),
      ].filter((item): item is Record<string, unknown> => Boolean(item))
      const latestStatePayloads = stageStatePayloads.slice().reverse()
      const packedState = latestStatePayloads
        .map((payload) => PackedStateSchema.safeParse(payload.packed_state))
        .find((parsed) => parsed.success)?.data
      const unpackState = latestStatePayloads
        .map((payload) => UnpackStateSchema.safeParse(payload.unpack_state))
        .find((parsed) => parsed.success)?.data
      const unpackConfidence = latestStatePayloads
        .map((payload) => payload.unpack_confidence)
        .find((value): value is number => typeof value === 'number')
      const debugState = latestStatePayloads
        .map((payload) => DebugStateSchema.safeParse(payload.debug_state))
        .find((parsed) => parsed.success)?.data
      const unpackDebugDiffSelection = await loadUnpackDebugArtifactSelection<unknown>(
        workspaceManager,
        database,
        input.sample_id,
        ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE,
        {
          scope: input.evidence_session_tag ? 'session' : 'latest',
          sessionTag: input.evidence_session_tag,
        }
      )
      const unpackDebugDiffs = unpackDebugDiffSelection.artifacts
        .map((item) => AnalysisDiffDigestSchema.safeParse(item.payload))
        .filter((parsed): parsed is z.SafeParseSuccess<z.infer<typeof AnalysisDiffDigestSchema>> => parsed.success)
        .map((parsed) => parsed.data)
        .slice(0, 4)
      const enrichStageOutputs =
        enrichStaticPayload?.stage_outputs && typeof enrichStaticPayload.stage_outputs === 'object'
          ? (enrichStaticPayload.stage_outputs as Record<string, unknown>)
          : {}
      const fastRawResults =
        fastProfilePayload?.raw_results && typeof fastProfilePayload.raw_results === 'object'
          ? (fastProfilePayload.raw_results as Record<string, unknown>)
          : {}
      const binaryProfile =
        (enrichStageOutputs.binary_role as z.infer<typeof BinaryRoleProfileDataSchema> | undefined) ||
        (fastRawResults.binary_role as z.infer<typeof BinaryRoleProfileDataSchema> | undefined)
      const rustProfile =
        (enrichStageOutputs.rust as z.infer<typeof RustBinaryAnalyzeDataSchema> | undefined) ||
        undefined
      if (!binaryProfile) {
        warnings.push('No persisted binary role profile was available for this sample.')
      }
      if (!rustProfile) {
        warnings.push('No persisted Rust-aware analysis state was available for this sample.')
      }
      const functionExplanationBundle = await loadFunctionExplanationSummaries(
        workspaceManager,
        database,
        input.sample_id,
        {
          scope: input.semantic_scope,
          sessionTag: input.semantic_session_tag,
        }
      )
      const functionExplanations = functionExplanationBundle.summaries
      const triageResult: WorkerResult = fastProfilePayload
        ? {
            ok: true,
            data: fastProfilePayload,
            warnings: ['Reused persisted fast_profile stage from analysis run state.'],
          }
        : {
            ok: false,
            errors: [
              `No persisted fast_profile stage is available for ${input.sample_id}. Start analysis with workflow.analyze.start or workflow.triage before requesting report.summarize.`,
            ],
          }
      const staticSelections = await loadStaticAnalysisSelections(
        workspaceManager,
        database,
        input.sample_id,
        {
          scope: input.static_scope,
          sessionTag: input.static_session_tag,
        }
      )
      const provenance = {
        runtime: buildRuntimeArtifactProvenance(
          dynamicEvidence,
          input.evidence_scope,
          input.evidence_session_tag
        ),
        static_capabilities: buildStaticArtifactProvenance(
          'static capability artifacts',
          staticSelections.capabilities,
          input.static_scope,
          input.static_session_tag
        ),
        pe_structure: buildStaticArtifactProvenance(
          'pe structure artifacts',
          staticSelections.peStructure,
          input.static_scope,
          input.static_session_tag
        ),
        compiler_packer: buildStaticArtifactProvenance(
          'compiler/packer attribution artifacts',
          staticSelections.compilerPacker,
          input.static_scope,
          input.static_session_tag
        ),
        semantic_explanations: buildSemanticArtifactProvenance(
          'semantic explanation artifacts',
          functionExplanationBundle.index,
          input.semantic_scope,
          input.semantic_session_tag
        ),
      }
      const ghidraExecution = buildGhidraExecutionSummary(analyses)
      const persistedCoverage = CoverageEnvelopeSchema.safeParse(fastProfilePayload || {})
      const explanationGraphSelection = await buildPersistedExplanationGraphs({
        workspaceManager,
        database,
        sampleId: input.sample_id,
        sessionTag: input.semantic_session_tag || input.static_session_tag || input.evidence_session_tag || null,
        functions: database.findFunctions(input.sample_id),
        persistedStateVisibility: {
          persisted_run_id: persistedStateVisibility.persisted_run_id,
          loaded_run_stages: persistedStateVisibility.reused_stage_names,
          deferred_requirements: persistedStateVisibility.deferred_requirements,
        },
        coverage: persistedCoverage.success
          ? persistedCoverage.data
          : buildCoverageEnvelope({
              coverageLevel: 'quick',
              completionState: 'bounded',
              sampleSizeTier,
              analysisBudgetProfile:
                sampleSizeTier === 'large' || sampleSizeTier === 'oversized' ? 'quick' : 'balanced',
            }),
      })
      const allArtifacts = database.findArtifacts(input.sample_id)
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
        const baselineSemanticIndex = await loadSemanticFunctionExplanationIndex(
          workspaceManager,
          database,
          input.sample_id,
          {
            scope: input.compare_semantic_scope,
            sessionTag: input.compare_semantic_session_tag,
          }
        )
        selectionDiffs.semantic_explanations = buildArtifactSelectionDiff(
          'semantic_explanations',
          provenance.semantic_explanations!,
          buildSemanticArtifactProvenance(
            'semantic explanation artifacts',
            baselineSemanticIndex,
            input.compare_semantic_scope,
            input.compare_semantic_session_tag
          )
        )
      }
      if (input.compare_static_scope) {
        const baselineStaticSelections = await loadStaticAnalysisSelections(
          workspaceManager,
          database,
          input.sample_id,
          {
            scope: input.compare_static_scope,
            sessionTag: input.compare_static_session_tag,
          }
        )
        selectionDiffs.static_capabilities = buildArtifactSelectionDiff(
          'static_capabilities',
          provenance.static_capabilities!,
          buildStaticArtifactProvenance(
            'static capability artifacts',
            baselineStaticSelections.capabilities,
            input.compare_static_scope,
            input.compare_static_session_tag
          )
        )
        selectionDiffs.pe_structure = buildArtifactSelectionDiff(
          'pe_structure',
          provenance.pe_structure!,
          buildStaticArtifactProvenance(
            'pe structure artifacts',
            baselineStaticSelections.peStructure,
            input.compare_static_scope,
            input.compare_static_session_tag
          )
        )
        selectionDiffs.compiler_packer = buildArtifactSelectionDiff(
          'compiler_packer',
          provenance.compiler_packer!,
          buildStaticArtifactProvenance(
            'compiler/packer attribution artifacts',
            baselineStaticSelections.compilerPacker,
            input.compare_static_scope,
            input.compare_static_session_tag
          )
        )
      }

      if (input.mode === 'triage') {
        if (!triageResult.ok || !triageResult.data) {
          if (dynamicEvidence) {
            return createDynamicEvidenceFallback(
              dynamicEvidence,
              triageResult,
              startTime,
              functionExplanations,
              provenance,
              ghidraExecution,
              input.evidence_scope,
              input.detail_level,
              binaryProfile,
              rustProfile
            )
          }
          return {
            ok: false,
            errors: triageResult.errors,
            warnings: triageResult.warnings,
            metrics: toolMetrics(startTime),
          }
        }

        const triageDataBase = triageResult.data as TriageSummaryData
        const triageData = dynamicEvidence
          ? augmentWithDynamicEvidence(triageDataBase, dynamicEvidence)
          : triageDataBase
        const staticEnrichedTriageData = augmentWithStaticAnalysis(triageData, {
          capabilities:
            staticSelections.capabilities.latest_payload ||
            ((triageDataBase as { raw_results?: Record<string, unknown> }).raw_results?.static_capability as
              | z.infer<typeof StaticCapabilityTriageDataSchema>
              | undefined),
          peStructure:
            staticSelections.peStructure.latest_payload ||
            ((triageDataBase as { raw_results?: Record<string, unknown> }).raw_results?.pe_structure as
              | z.infer<typeof PEStructureAnalyzeDataSchema>
              | undefined),
          compilerPacker:
            staticSelections.compilerPacker.latest_payload ||
            ((triageDataBase as { raw_results?: Record<string, unknown> }).raw_results?.compiler_packer as
              | z.infer<typeof CompilerPackerDetectDataSchema>
              | undefined),
        })
        const binaryEnrichedTriageData = augmentWithBinaryProfile(staticEnrichedTriageData, binaryProfile)
        const rustEnrichedTriageData = augmentWithRustProfile(binaryEnrichedTriageData, rustProfile)
        const enrichedTriageData = augmentWithFunctionExplanations(
          rustEnrichedTriageData,
          functionExplanations
        )
        const artifactRefs = buildReportArtifactRefs(allArtifacts, {
          runtimeIds: provenance.runtime.artifact_ids,
          staticCapabilityIds: provenance.static_capabilities.artifact_ids,
          peStructureIds: provenance.pe_structure.artifact_ids,
          compilerPackerIds: provenance.compiler_packer.artifact_ids,
          semanticIds: provenance.semantic_explanations.artifact_ids,
        })
        const unpackDebugArtifactRefs = unpackDebugDiffSelection.artifact_refs.map((ref) =>
          buildArtifactRefFromParts({
            id: ref.id,
            type: ref.type,
            path: ref.path,
            sha256: ref.sha256,
            mime: ref.mime,
            metadata: ref.metadata,
          })
        )
        const compactReportData = buildCompactReportData({
          sampleId: input.sample_id,
          detailLevel: input.detail_level,
          triageData: enrichedTriageData,
          evidenceScope: input.evidence_scope,
          provenance,
          ghidraExecution,
          selectionDiffs,
          functionExplanations,
          explanationGraphs: explanationGraphSelection.graphs,
          artifactRefs: {
            ...artifactRefs,
            supporting: dedupeArtifactRefs([
              ...artifactRefs.supporting,
              ...unpackDebugArtifactRefs,
            ]),
            ...(explanationGraphSelection.artifactRefs.length > 0
              ? { explanation_graphs: explanationGraphSelection.artifactRefs }
              : {}),
          },
        })
        const fullCompatibleData =
          input.detail_level === 'full'
            ? {
                detail_level: input.detail_level,
                tool_surface_role: 'compatibility',
                preferred_primary_tools: ['workflow.summarize'],
                coverage_level: compactReportData.coverage_level,
                completion_state: compactReportData.completion_state,
                sample_size_tier: compactReportData.sample_size_tier,
                analysis_budget_profile: compactReportData.analysis_budget_profile,
                downgrade_reasons: compactReportData.downgrade_reasons,
                coverage_gaps: compactReportData.coverage_gaps,
                confidence_by_domain: compactReportData.confidence_by_domain,
                known_findings: compactReportData.known_findings,
                suspected_findings: compactReportData.suspected_findings,
                unverified_areas: compactReportData.unverified_areas,
                upgrade_paths: compactReportData.upgrade_paths,
                summary: compactReportData.summary,
                confidence: compactReportData.confidence,
                threat_level: compactReportData.threat_level,
                iocs: compactReportData.iocs,
                evidence: compactReportData.evidence,
                evidence_lineage: compactReportData.evidence_lineage,
                confidence_semantics: compactReportData.confidence_semantics,
                binary_profile_summary: compactReportData.binary_profile_summary,
                rust_profile_summary: compactReportData.rust_profile_summary,
                static_capability_summary: compactReportData.static_capability_summary,
                pe_structure_summary: compactReportData.pe_structure_summary,
                compiler_packer_summary: compactReportData.compiler_packer_summary,
                semantic_explanation_summary: compactReportData.semantic_explanation_summary,
                provenance: compactReportData.provenance,
                persisted_state_visibility: persistedStateVisibility,
                packed_state: packedState,
                unpack_state: unpackState,
                unpack_confidence: unpackConfidence,
                debug_state: debugState,
                unpack_debug_diffs: unpackDebugDiffs.length > 0 ? unpackDebugDiffs : undefined,
                ghidra_execution: compactReportData.ghidra_execution,
                selection_diffs: compactReportData.selection_diffs,
                explanation_graphs: compactReportData.explanation_graphs,
                artifact_refs: compactReportData.artifact_refs,
                truncation: compactReportData.truncation,
                recommendation: enrichedTriageData.recommendation,
                recommended_next_tools: compactReportData.recommended_next_tools,
                next_actions: compactReportData.next_actions,
              }
            : compactReportData
        const fullDetailFields =
          input.detail_level === 'full'
            ? {
                binary_profile: enrichedTriageData.binary_profile,
                rust_profile: enrichedTriageData.rust_profile,
                static_capabilities: enrichedTriageData.static_capabilities,
                pe_structure: enrichedTriageData.pe_structure,
                compiler_packer: enrichedTriageData.compiler_packer,
                function_explanations: enrichedTriageData.function_explanations,
                evidence_weights: enrichedTriageData.evidence_weights,
                inference: enrichedTriageData.inference,
              }
            : {
                evidence_weights: enrichedTriageData.evidence_weights,
                inference: enrichedTriageData.inference,
              }
        const inlinePayload = boundInlineReportPayload({
          ...fullCompatibleData,
          persisted_state_visibility: persistedStateVisibility,
          packed_state: packedState,
          unpack_state: unpackState,
          unpack_confidence: unpackConfidence,
          debug_state: debugState,
          unpack_debug_diffs: unpackDebugDiffs.length > 0 ? unpackDebugDiffs : undefined,
          ...fullDetailFields,
        } as ReportSummarizeData)
        return {
          ok: true,
          data: {
            ...inlinePayload.data,
            tool_surface_role: 'compatibility',
            preferred_primary_tools: ['workflow.summarize'],
          },
          warnings: dynamicEvidence
            ? dedupe([
              ...warnings,
              ...(triageResult.warnings || []),
                ...inlinePayload.warnings,
                `Merged imported runtime evidence from ${dynamicEvidence.artifact_count} artifact(s) using scope=${input.evidence_scope}${input.evidence_session_tag ? ` selector=${input.evidence_session_tag}` : ''}.`,
                dynamicEvidence.scope_note || '',
              ])
            : dedupe([...warnings, ...(triageResult.warnings || []), ...inlinePayload.warnings]),
          errors: triageResult.errors,
          metrics: toolMetrics(startTime),
        }
      }

      if (input.mode === 'dotnet') {
        if (!triageResult.ok || !triageResult.data) {
          return createMinimalDotnetFallback(
            triageResult,
            startTime,
            functionExplanations,
            provenance,
            ghidraExecution,
            input.evidence_scope,
            input.detail_level,
            binaryProfile,
            rustProfile
          )
        }

        const triageData = triageResult.data as TriageSummaryData

        return {
          ok: true,
          data: {
            detail_level: input.detail_level,
            tool_surface_role: 'compatibility',
            preferred_primary_tools: ['workflow.summarize'],
            ...buildCoverageEnvelope({
              coverageLevel: 'quick',
              completionState: 'degraded',
              sampleSizeTier: 'small',
              analysisBudgetProfile: 'balanced',
              coverageGaps: [
                {
                  domain: 'dotnet_structure',
                  status: 'missing',
                  reason: 'Dotnet-specific summarize mode is not implemented, so this path falls back to triage-compatible output.',
                },
              ],
              knownFindings: triageData.evidence.slice(0, 4),
              suspectedFindings: triageData.inference?.hypotheses || [],
              unverifiedAreas: ['Managed-code structure remains unverified until workflow.reconstruct or dotnet.reconstruct.export runs.'],
              upgradePaths: [
                {
                  tool: 'workflow.reconstruct',
                  purpose: 'Recover .NET-aware structure through the main reconstruction workflow.',
                  closes_gaps: ['dotnet_structure'],
                  expected_coverage_gain: 'Adds managed export artifacts and structure beyond the triage-compatible fallback.',
                  cost_tier: 'high',
                },
              ],
            }),
            summary:
              `[dotnet fallback] ${triageData.summary}. ` +
              'Dotnet-specific summarize pipeline is not implemented yet; returning triage-compatible summary.',
            confidence: Math.max(0.05, Math.min(0.95, triageData.confidence * 0.92)),
            threat_level: triageData.threat_level,
            iocs: triageData.iocs,
            evidence: [
              ...triageData.evidence,
              'Dotnet-specific mode unavailable; downgraded to triage-compatible summary.',
            ],
            evidence_lineage: triageData.evidence_lineage || buildEvidenceLineage(dynamicEvidence),
            confidence_semantics: buildAssessmentConfidencePayload(
              Math.max(0.05, Math.min(0.95, triageData.confidence * 0.92)),
              input.evidence_scope,
              triageData.evidence_lineage || buildEvidenceLineage(dynamicEvidence)
            ),
            binary_profile: binaryProfile,
            rust_profile: rustProfile,
            provenance,
            persisted_state_visibility: persistedStateVisibility,
            ghidra_execution: ghidraExecution,
            selection_diffs:
              Object.keys(selectionDiffs).length > 0 ? selectionDiffs : undefined,
            function_explanations: functionExplanations.length > 0 ? functionExplanations : undefined,
            evidence_weights: triageData.evidence_weights,
            inference: triageData.inference,
            recommendation:
              `${triageData.recommendation}; additionally run runtime.detect plus ` +
              'dotnet.reconstruct.export / workflow.reconstruct for .NET-specific structure.',
            recommended_next_tools: ['workflow.summarize', 'artifact.read', 'workflow.reconstruct'],
            next_actions: [
              'Use workflow.summarize for staged compact reporting.',
              'Use runtime.detect plus dotnet.reconstruct.export or workflow.reconstruct for .NET-specific structure.',
            ],
          },
          warnings: [
            ...warnings,
            'report.summarize(mode=dotnet) not fully implemented; returned triage fallback.',
            ...(triageResult.warnings || []),
          ],
          metrics: toolMetrics(startTime),
        }
      }

      return {
        ok: false,
        errors: [`Unsupported mode: ${(input as { mode?: string }).mode}`],
        metrics: toolMetrics(startTime),
      }
    } catch (error) {
      if (error instanceof z.ZodError) {
        const invalidMode = error.issues.find(
          (issue) => issue.path[0] === 'mode' && issue.code === z.ZodIssueCode.invalid_enum_value
        )
        if (invalidMode) {
          return {
            ok: false,
            errors: [`Unsupported mode: ${(args as { mode?: unknown }).mode}`],
            metrics: toolMetrics(startTime),
          }
        }
      }
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: toolMetrics(startTime),
      }
    }
  }
}
