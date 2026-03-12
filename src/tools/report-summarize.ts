/**
 * report.summarize tool implementation
 * Generates quick triage report with summary, confidence, IOCs, evidence, and recommendations.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import {
  BinaryRoleProfileDataSchema,
  createBinaryRoleProfileHandler,
} from './binary-role-profile.js'
import {
  RustBinaryAnalyzeDataSchema,
  createRustBinaryAnalyzeHandler,
} from './rust-binary-analyze.js'
import { createTriageWorkflowHandler } from '../workflows/triage.js'
import { loadDynamicTraceEvidence, type DynamicTraceSummary } from '../dynamic-trace.js'
import {
  loadSemanticFunctionExplanationIndex,
  type SemanticFunctionExplanationIndex,
} from '../semantic-name-suggestion-artifacts.js'
import {
  ConfidenceSemanticsSchema,
  buildReportConfidenceSemantics,
} from '../confidence-semantics.js'
import {
  AnalysisProvenanceSchema,
  buildRuntimeArtifactProvenance,
  buildSemanticArtifactProvenance,
} from '../analysis-provenance.js'
import {
  AnalysisSelectionDiffSchema,
  buildArtifactSelectionDiff,
} from '../selection-diff.js'

const TOOL_NAME = 'report.summarize'

export const ReportSummarizeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  mode: z
    .enum(['triage', 'dotnet'])
    .default('triage')
    .describe('Report mode: triage for quick assessment, dotnet for .NET-specific analysis'),
  evidence_scope: z
    .enum(['all', 'latest', 'session'])
    .default('all')
    .describe('Runtime evidence scope: all artifacts, only the latest artifact window, or a specific session selector'),
  evidence_session_tag: z
    .string()
    .optional()
    .describe('Optional runtime evidence session selector used when evidence_scope=session or to narrow all/latest results'),
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

export const ReportSummarizeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
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
      binary_profile: BinaryRoleProfileDataSchema.optional().describe(
        'Optional binary role profile summarizing EXE/DLL/COM/service/plugin/export characteristics.'
      ),
      rust_profile: RustBinaryAnalyzeDataSchema.optional().describe(
        'Optional Rust-oriented binary analysis summary, including crate hints, recovered symbols, and recovery priorities.'
      ),
      provenance: AnalysisProvenanceSchema.optional().describe(
        'Explicit runtime/semantic artifact selection used to produce this report, including scope, session selector, and selected artifact IDs.'
      ),
      selection_diffs: AnalysisSelectionDiffSchema.optional().describe(
        'Optional comparison between the current artifact selection and a caller-provided baseline runtime/semantic selection.'
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
    })
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
    'Generate a quick triage report with summary, confidence, IOC, evidence, and recommendations. Supports triage mode and dotnet fallback mode.',
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

function buildBinaryProfileSummary(binaryProfile: z.infer<typeof BinaryRoleProfileDataSchema>): string {
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
  if (binaryProfile.host_interaction_profile.likely_hosted) {
    parts.push('host/plugin interaction surface detected')
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
  const evidenceLines = dedupe([
    summaryLine,
    ...binaryProfile.analysis_priorities.map((item) => `binary_profile_priority: ${item}`),
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
      rustProfile.library_profile || triageData.iocs.compiler_artifacts?.library_profile,
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
                  triageData.inference.tooling_assessment.library_profile ||
                  rustProfile.library_profile,
              }
            : {
                help_text_detected: false,
                cli_surface_detected: false,
                framework_hints: rustProfile.crate_hints,
                toolchain_markers: rustProfile.runtime_hints,
                library_profile: rustProfile.library_profile,
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
  evidenceScope: 'all' | 'latest' | 'session' = 'all',
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
  evidenceScope: 'all' | 'latest' | 'session' = 'all',
  binaryProfile?: z.infer<typeof BinaryRoleProfileDataSchema>,
  rustProfile?: z.infer<typeof RustBinaryAnalyzeDataSchema>
): WorkerResult {
  const evidenceLineage = buildEvidenceLineage(dynamicEvidence)
  const threatLevel =
    dynamicEvidence.high_signal_apis.length > 0 ? 'suspicious' : dynamicEvidence.executed ? 'suspicious' : 'unknown'

  return {
    ok: true,
    data: {
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
    },
    warnings: [
      'Triage pipeline failed; returned imported runtime-evidence fallback.',
      ...(triageResult.warnings || []),
    ],
    errors: triageResult.errors,
    metrics: toolMetrics(startTime),
  }
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
      const input = ReportSummarizeInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }
      const warnings: string[] = []

      const dynamicEvidence = await loadDynamicTraceEvidence(workspaceManager, database, input.sample_id, {
        evidenceScope: input.evidence_scope,
        sessionTag: input.evidence_session_tag,
      })
      const binaryRoleProfileResult = await binaryRoleProfileHandler({ sample_id: input.sample_id })
      const binaryProfile =
        binaryRoleProfileResult.ok && binaryRoleProfileResult.data
          ? (binaryRoleProfileResult.data as z.infer<typeof BinaryRoleProfileDataSchema>)
          : undefined
      if (!binaryRoleProfileResult.ok) {
        warnings.push(
          `binary.role.profile unavailable: ${(binaryRoleProfileResult.errors || ['unknown error']).join('; ')}`
        )
      } else if (binaryRoleProfileResult.warnings?.length) {
        warnings.push(...binaryRoleProfileResult.warnings.map((item) => `binary.role.profile: ${item}`))
      }
      const rustBinaryAnalyzeResult = await rustBinaryAnalyzeHandler({ sample_id: input.sample_id })
      const rustProfile =
        rustBinaryAnalyzeResult.ok && rustBinaryAnalyzeResult.data
          ? (rustBinaryAnalyzeResult.data as z.infer<typeof RustBinaryAnalyzeDataSchema>)
          : undefined
      if (!rustBinaryAnalyzeResult.ok) {
        warnings.push(
          `rust_binary.analyze unavailable: ${(rustBinaryAnalyzeResult.errors || ['unknown error']).join('; ')}`
        )
      } else if (rustBinaryAnalyzeResult.warnings?.length) {
        warnings.push(...rustBinaryAnalyzeResult.warnings.map((item) => `rust_binary.analyze: ${item}`))
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
      const provenance = {
        runtime: buildRuntimeArtifactProvenance(
          dynamicEvidence,
          input.evidence_scope,
          input.evidence_session_tag
        ),
        semantic_explanations: buildSemanticArtifactProvenance(
          'semantic explanation artifacts',
          functionExplanationBundle.index,
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
      const triageResult = await triageHandler({
        sample_id: input.sample_id,
        force_refresh: input.force_refresh,
      })

      if (input.mode === 'triage') {
        if (!triageResult.ok || !triageResult.data) {
          if (dynamicEvidence) {
            return createDynamicEvidenceFallback(
              dynamicEvidence,
              triageResult,
              startTime,
              functionExplanations,
              provenance,
              input.evidence_scope,
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
        const binaryEnrichedTriageData = augmentWithBinaryProfile(triageData, binaryProfile)
        const rustEnrichedTriageData = augmentWithRustProfile(binaryEnrichedTriageData, rustProfile)
        const enrichedTriageData = augmentWithFunctionExplanations(
          rustEnrichedTriageData,
          functionExplanations
        )
        return {
          ok: true,
          data: {
            summary: enrichedTriageData.summary,
            confidence: enrichedTriageData.confidence,
            threat_level: enrichedTriageData.threat_level,
            iocs: enrichedTriageData.iocs,
            evidence: enrichedTriageData.evidence,
            evidence_lineage: enrichedTriageData.evidence_lineage || buildEvidenceLineage(dynamicEvidence),
            confidence_semantics: buildAssessmentConfidencePayload(
              enrichedTriageData.confidence,
              input.evidence_scope,
              enrichedTriageData.evidence_lineage || buildEvidenceLineage(dynamicEvidence)
            ),
            binary_profile: enrichedTriageData.binary_profile,
            rust_profile: enrichedTriageData.rust_profile,
            provenance,
            selection_diffs:
              Object.keys(selectionDiffs).length > 0 ? selectionDiffs : undefined,
            function_explanations: enrichedTriageData.function_explanations,
            evidence_weights: enrichedTriageData.evidence_weights,
            inference: enrichedTriageData.inference,
            recommendation: enrichedTriageData.recommendation,
          },
          warnings: dynamicEvidence
            ? dedupe([
              ...warnings,
              ...(triageResult.warnings || []),
                `Merged imported runtime evidence from ${dynamicEvidence.artifact_count} artifact(s) using scope=${input.evidence_scope}${input.evidence_session_tag ? ` selector=${input.evidence_session_tag}` : ''}.`,
                dynamicEvidence.scope_note || '',
              ])
            : dedupe([...warnings, ...(triageResult.warnings || [])]),
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
            input.evidence_scope,
            binaryProfile,
            rustProfile
          )
        }

        const triageData = triageResult.data as TriageSummaryData

        return {
          ok: true,
          data: {
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
            selection_diffs:
              Object.keys(selectionDiffs).length > 0 ? selectionDiffs : undefined,
            function_explanations: functionExplanations.length > 0 ? functionExplanations : undefined,
            evidence_weights: triageData.evidence_weights,
            inference: triageData.inference,
            recommendation:
              `${triageData.recommendation}; additionally run runtime.detect plus ` +
              'dotnet.reconstruct.export / workflow.reconstruct for .NET-specific structure.',
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
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: toolMetrics(startTime),
      }
    }
  }
}
