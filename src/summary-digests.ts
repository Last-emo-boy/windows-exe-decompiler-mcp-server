import { z } from 'zod'
import type { ArtifactRef } from './types.js'
import { GhidraExecutionSummarySchema } from './ghidra-execution-summary.js'
import { SUMMARY_STAGE_VALUES, type SummaryStage } from './summary-artifacts.js'
import {
  CoverageEnvelopeSchema,
  type CoverageEnvelope,
  buildCoverageEnvelope,
  normalizeCoverageGaps,
  normalizeUpgradePaths,
} from './analysis-coverage.js'
import {
  ExplanationConfidenceStateSchema,
  ExplanationGraphTypeSchema,
  ExplanationSurfaceRoleSchema,
} from './explanation-graphs.js'

export const SummaryArtifactRefSchema = z.object({
  id: z.string(),
  type: z.string(),
  path: z.string(),
  sha256: z.string(),
  mime: z.string().optional(),
  metadata: z.record(z.any()).optional(),
})

export const DigestBudgetSchema = z.object({
  total: z.number().int().nonnegative(),
  kept: z.number().int().nonnegative(),
  limit: z.number().int().positive(),
  truncated: z.boolean(),
  omitted: z.number().int().nonnegative(),
})

export const DigestTruncationSchema = z.record(DigestBudgetSchema)

const DetailLevelSchema = z.enum(['compact', 'full'])

const ThreatLevelSchema = z.enum(['clean', 'suspicious', 'malicious', 'unknown'])

const IOCBucketSchema = z.object({
  suspicious_imports: z.array(z.string()),
  suspicious_strings: z.array(z.string()),
  yara_matches: z.array(z.string()),
  yara_low_confidence: z.array(z.string()).optional(),
  urls: z.array(z.string()).optional(),
  ip_addresses: z.array(z.string()).optional(),
  file_paths: z.array(z.string()).optional(),
  registry_keys: z.array(z.string()).optional(),
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

export const BinaryProfileSummarySchema = z.object({
  binary_role: z.string(),
  role_confidence: z.number().min(0).max(1),
  packed: z.boolean(),
  packing_confidence: z.number().min(0).max(1).optional(),
  export_count: z.number().int().nonnegative(),
  notable_exports: z.array(z.string()),
  dispatch_model: z.string().nullable(),
  host_hints: z.array(z.string()),
  analysis_priorities: z.array(z.string()),
  summary: z.string(),
})

export const RustProfileSummarySchema = z.object({
  suspected_rust: z.boolean(),
  confidence: z.number().min(0).max(1),
  primary_runtime: z.string().nullable(),
  top_crates: z.array(z.string()),
  recovered_symbol_count: z.number().int().nonnegative(),
  recovered_function_count: z.number().int().nonnegative(),
  analysis_priorities: z.array(z.string()),
  summary: z.string(),
})

export const StaticCapabilitySummarySchema = z.object({
  status: z.string(),
  capability_count: z.number().int().nonnegative(),
  top_groups: z.array(z.string()),
  top_capabilities: z.array(z.string()),
  summary: z.string(),
})

export const PEStructureSummaryDigestSchema = z.object({
  status: z.string(),
  section_count: z.number().int().nonnegative(),
  import_function_count: z.number().int().nonnegative(),
  export_count: z.number().int().nonnegative(),
  resource_count: z.number().int().nonnegative(),
  overlay_present: z.boolean(),
  parser_preference: z.string().nullable(),
  summary: z.string(),
})

export const CompilerPackerSummaryDigestSchema = z.object({
  status: z.string(),
  compiler_names: z.array(z.string()),
  packer_names: z.array(z.string()),
  protector_names: z.array(z.string()),
  likely_primary_file_type: z.string().nullable(),
  summary: z.string(),
})

export const SemanticExplanationDigestSchema = z.object({
  count: z.number().int().nonnegative(),
  top_behaviors: z.array(z.string()),
  top_summaries: z.array(z.string()),
  summary: z.string(),
})

export const TopFunctionDigestSchema = z.object({
  address: z.string(),
  name: z.string().nullable(),
  score: z.number().nullable(),
  summary: z.string().nullable(),
})

export const FunctionExplanationPreviewSchema = z.object({
  address: z.string().nullable(),
  function: z.string().nullable(),
  behavior: z.string(),
  summary: z.string(),
  confidence: z.number().min(0).max(1),
  rewrite_guidance: z.array(z.string()),
  source: z.string().nullable(),
})

export const ExplanationGraphSummarySchema = z.object({
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
  recommended_next_tools: z.array(z.string()),
  omissions: z
    .array(
      z.object({
        code: z.string(),
        reason: z.string(),
      })
    )
    .optional(),
  artifact_ref: SummaryArtifactRefSchema.optional(),
})

const DigestBaseSchema = z.object({
  schema_version: z.literal(1),
  sample_id: z.string(),
  stage: z.enum(SUMMARY_STAGE_VALUES),
  detail_level: DetailLevelSchema.default('compact'),
  created_at: z.string(),
  session_tag: z.string().nullable().optional(),
  source_artifact_refs: z.array(SummaryArtifactRefSchema),
  truncation: DigestTruncationSchema.optional(),
}).extend(CoverageEnvelopeSchema.shape)

export const TriageStageDigestSchema = DigestBaseSchema.extend({
  stage: z.literal('triage'),
  summary: z.string(),
  confidence: z.number().min(0).max(1),
  threat_level: ThreatLevelSchema,
  iocs: IOCBucketSchema,
  evidence: z.array(z.string()),
  evidence_lineage: z.any().optional(),
  confidence_semantics: z.any().optional(),
  recommendation: z.string(),
})

export const StaticStageDigestSchema = DigestBaseSchema.extend({
  stage: z.literal('static'),
  binary_profile_summary: BinaryProfileSummarySchema.nullable().optional(),
  rust_profile_summary: RustProfileSummarySchema.nullable().optional(),
  static_capability_summary: StaticCapabilitySummarySchema.nullable().optional(),
  pe_structure_summary: PEStructureSummaryDigestSchema.nullable().optional(),
  compiler_packer_summary: CompilerPackerSummaryDigestSchema.nullable().optional(),
  semantic_explanation_summary: SemanticExplanationDigestSchema.nullable().optional(),
  key_findings: z.array(z.string()),
  recommendation: z.string(),
})

export const DeepStageDigestSchema = DigestBaseSchema.extend({
  stage: z.literal('deep'),
  summary: z.string(),
  ghidra_execution: GhidraExecutionSummarySchema.nullable().optional(),
  top_functions: z.array(TopFunctionDigestSchema),
  function_explanations: z.array(FunctionExplanationPreviewSchema),
  analysis_gaps: z.array(z.string()),
  recommendation: z.string(),
})

export const FinalStageDigestSchema = DigestBaseSchema.extend({
  stage: z.literal('final'),
  synthesis_mode: z.enum(['deterministic', 'sampling']),
  model_name: z.string().nullable().optional(),
  executive_summary: z.string(),
  analyst_summary: z.string(),
  threat_level: ThreatLevelSchema,
  confidence: z.number().min(0).max(1),
  key_findings: z.array(z.string()),
  next_steps: z.array(z.string()),
  unresolved_unknowns: z.array(z.string()),
  stage_artifact_refs: z.array(SummaryArtifactRefSchema),
  explanation_graphs: z.array(ExplanationGraphSummarySchema).optional(),
  explanation_artifact_refs: z.array(SummaryArtifactRefSchema).optional(),
})

export type TriageStageDigest = z.infer<typeof TriageStageDigestSchema>
export type StaticStageDigest = z.infer<typeof StaticStageDigestSchema>
export type DeepStageDigest = z.infer<typeof DeepStageDigestSchema>
export type FinalStageDigest = z.infer<typeof FinalStageDigestSchema>

const DIGEST_LIST_LIMITS = {
  evidence: 12,
  suspicious_imports: 12,
  suspicious_strings: 12,
  yara_matches: 8,
  yara_low_confidence: 8,
  urls: 8,
  ip_addresses: 8,
  file_paths: 8,
  registry_keys: 8,
  suspicious_apis: 12,
  commands: 8,
  pipes: 8,
  network: 8,
  cargo_paths: 8,
  rust_markers: 8,
  top_crates: 6,
  notable_libraries: 6,
  library_evidence: 6,
  analysis_priorities: 4,
  top_groups: 4,
  top_capabilities: 6,
  top_behaviors: 6,
  top_summaries: 4,
  key_findings: 8,
  top_functions: 5,
  function_explanations: 3,
  rewrite_guidance: 2,
  next_steps: 5,
  unresolved_unknowns: 5,
  stage_artifacts: 4,
} as const

type DigestBudgetKey = keyof typeof DIGEST_LIST_LIMITS

export function dedupeStrings(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values
        .filter((item): item is string => typeof item === 'string')
        .map((item) => item.trim())
        .filter((item) => item.length > 0)
    )
  )
}

export function truncateText(value: string | null | undefined, limit: number): string {
  const normalized = (value || '').trim()
  if (normalized.length <= limit) {
    return normalized
  }
  return `${normalized.slice(0, limit - 24)}... (truncated ${normalized.length - limit + 24} chars)`
}

export function limitArray<T>(
  key: DigestBudgetKey,
  values: T[],
  map?: (value: T) => string | T
): { values: T[]; budget?: z.infer<typeof DigestBudgetSchema> } {
  const limit = DIGEST_LIST_LIMITS[key]
  const normalized = values
    .map((item) => {
      if (!map) {
        return item
      }
      return map(item) as T
    })
    .filter((item) => item !== null && item !== undefined) as T[]
  const kept = normalized.slice(0, limit)
  return {
    values: kept,
    budget:
      normalized.length > limit
        ? {
            total: normalized.length,
            kept: kept.length,
            limit,
            truncated: true,
            omitted: normalized.length - kept.length,
          }
        : undefined,
  }
}

export function collectTruncationEntries(
  entries: Array<[string, z.infer<typeof DigestBudgetSchema> | undefined]>
): z.infer<typeof DigestTruncationSchema> | undefined {
  const filtered = Object.fromEntries(entries.filter(([, value]) => Boolean(value))) as z.infer<
    typeof DigestTruncationSchema
  >
  return Object.keys(filtered).length > 0 ? filtered : undefined
}

export function dedupeArtifactRefs(refs: ArtifactRef[]): ArtifactRef[] {
  const seen = new Set<string>()
  const ordered: ArtifactRef[] = []
  for (const ref of refs) {
    if (!ref?.id || seen.has(ref.id)) {
      continue
    }
    seen.add(ref.id)
    ordered.push(ref)
  }
  return ordered
}

export interface BuildTriageStageDigestInput {
  sample_id: string
  created_at?: string
  session_tag?: string | null
  summary: string
  confidence: number
  threat_level: TriageStageDigest['threat_level']
  iocs: TriageStageDigest['iocs']
  evidence: string[]
  evidence_lineage?: unknown
  confidence_semantics?: unknown
  recommendation: string
  source_artifact_refs?: ArtifactRef[]
  coverage?: CoverageEnvelope
}

export interface BuildStaticStageDigestInput {
  sample_id: string
  created_at?: string
  session_tag?: string | null
  binary_profile_summary?: StaticStageDigest['binary_profile_summary']
  rust_profile_summary?: StaticStageDigest['rust_profile_summary']
  static_capability_summary?: StaticStageDigest['static_capability_summary']
  pe_structure_summary?: StaticStageDigest['pe_structure_summary']
  compiler_packer_summary?: StaticStageDigest['compiler_packer_summary']
  semantic_explanation_summary?: StaticStageDigest['semantic_explanation_summary']
  key_findings?: string[]
  recommendation: string
  source_artifact_refs?: ArtifactRef[]
  coverage?: CoverageEnvelope
}

export interface BuildDeepStageDigestInput {
  sample_id: string
  created_at?: string
  session_tag?: string | null
  summary: string
  ghidra_execution?: DeepStageDigest['ghidra_execution']
  top_functions: DeepStageDigest['top_functions']
  function_explanations: DeepStageDigest['function_explanations']
  analysis_gaps: string[]
  recommendation: string
  source_artifact_refs?: ArtifactRef[]
  coverage?: CoverageEnvelope
}

export interface BuildFinalStageDigestInput {
  sample_id: string
  created_at?: string
  session_tag?: string | null
  triage: TriageStageDigest
  staticDigest?: StaticStageDigest | null
  deepDigest?: DeepStageDigest | null
  stage_artifact_refs?: ArtifactRef[]
  synthesis_mode: FinalStageDigest['synthesis_mode']
  model_name?: string | null
  source_artifact_refs?: ArtifactRef[]
  explanation_graphs?: z.infer<typeof ExplanationGraphSummarySchema>[]
  explanation_artifact_refs?: ArtifactRef[]
  coverage?: CoverageEnvelope
}

export function buildTriageStageDigest(
  input: BuildTriageStageDigestInput
): TriageStageDigest {
  const evidence = limitArray('evidence', dedupeStrings(input.evidence))
  const suspiciousImports = limitArray(
    'suspicious_imports',
    dedupeStrings(input.iocs.suspicious_imports || [])
  )
  const suspiciousStrings = limitArray(
    'suspicious_strings',
    dedupeStrings(input.iocs.suspicious_strings || [])
  )
  const yaraMatches = limitArray('yara_matches', dedupeStrings(input.iocs.yara_matches || []))
  const yaraLowConfidence = limitArray(
    'yara_low_confidence',
    dedupeStrings(input.iocs.yara_low_confidence || [])
  )
  const urls = limitArray('urls', dedupeStrings(input.iocs.urls || []))
  const ipAddresses = limitArray('ip_addresses', dedupeStrings(input.iocs.ip_addresses || []))
  const filePaths = limitArray('file_paths', dedupeStrings(input.iocs.file_paths || []))
  const registryKeys = limitArray('registry_keys', dedupeStrings(input.iocs.registry_keys || []))
  const suspiciousApis = limitArray(
    'suspicious_apis',
    dedupeStrings(input.iocs.high_value_iocs?.suspicious_apis || [])
  )
  const commands = limitArray('commands', dedupeStrings(input.iocs.high_value_iocs?.commands || []))
  const pipes = limitArray('pipes', dedupeStrings(input.iocs.high_value_iocs?.pipes || []))
  const network = limitArray('network', dedupeStrings(input.iocs.high_value_iocs?.network || []))
  const cargoPaths = limitArray(
    'cargo_paths',
    dedupeStrings(input.iocs.compiler_artifacts?.cargo_paths || [])
  )
  const rustMarkers = limitArray(
    'rust_markers',
    dedupeStrings(input.iocs.compiler_artifacts?.rust_markers || [])
  )
  const topCrates = limitArray(
    'top_crates',
    dedupeStrings(input.iocs.compiler_artifacts?.library_profile?.top_crates || [])
  )
  const notableLibraries = limitArray(
    'notable_libraries',
    dedupeStrings(input.iocs.compiler_artifacts?.library_profile?.notable_libraries || [])
  )
  const libraryEvidence = limitArray(
    'library_evidence',
    dedupeStrings(input.iocs.compiler_artifacts?.library_profile?.evidence || [])
  )

  const coverage =
    input.coverage ||
    buildCoverageEnvelope({
      coverageLevel: 'quick',
      completionState: 'bounded',
      sampleSizeTier: 'small',
      analysisBudgetProfile: 'balanced',
      coverageGaps: [
        {
          domain: 'ghidra_analysis',
          status: 'missing',
          reason: 'Quick triage digest does not include deep static decompilation.',
        },
      ],
      knownFindings: input.evidence.slice(0, 3),
      unverifiedAreas: ['Function-level attribution remains outside the triage digest.'],
      upgradePaths: [
        {
          tool: 'ghidra.analyze',
          purpose: 'Recover function-level decompilation.',
          closes_gaps: ['ghidra_analysis'],
          expected_coverage_gain: 'Adds decompiler-backed function context beyond triage.',
          cost_tier: 'high',
        },
      ],
    })

  return {
    schema_version: 1,
    sample_id: input.sample_id,
    stage: 'triage',
    detail_level: 'compact',
    created_at: input.created_at || new Date().toISOString(),
    session_tag: input.session_tag || null,
    source_artifact_refs: dedupeArtifactRefs(input.source_artifact_refs || []),
    ...coverage,
    summary: truncateText(input.summary, 900),
    confidence: input.confidence,
    threat_level: input.threat_level,
    iocs: {
      suspicious_imports: suspiciousImports.values,
      suspicious_strings: suspiciousStrings.values,
      yara_matches: yaraMatches.values,
      ...(yaraLowConfidence.values.length > 0 ? { yara_low_confidence: yaraLowConfidence.values } : {}),
      ...(urls.values.length > 0 ? { urls: urls.values } : {}),
      ...(ipAddresses.values.length > 0 ? { ip_addresses: ipAddresses.values } : {}),
      ...(filePaths.values.length > 0 ? { file_paths: filePaths.values } : {}),
      ...(registryKeys.values.length > 0 ? { registry_keys: registryKeys.values } : {}),
      ...((suspiciousApis.values.length > 0 ||
        commands.values.length > 0 ||
        pipes.values.length > 0 ||
        network.values.length > 0) && {
        high_value_iocs: {
          ...(suspiciousApis.values.length > 0 ? { suspicious_apis: suspiciousApis.values } : {}),
          ...(commands.values.length > 0 ? { commands: commands.values } : {}),
          ...(pipes.values.length > 0 ? { pipes: pipes.values } : {}),
          ...(network.values.length > 0 ? { network: network.values } : {}),
        },
      }),
      ...((cargoPaths.values.length > 0 ||
        rustMarkers.values.length > 0 ||
        topCrates.values.length > 0 ||
        notableLibraries.values.length > 0 ||
        libraryEvidence.values.length > 0) && {
        compiler_artifacts: {
          ...(cargoPaths.values.length > 0 ? { cargo_paths: cargoPaths.values } : {}),
          ...(rustMarkers.values.length > 0 ? { rust_markers: rustMarkers.values } : {}),
          ...((topCrates.values.length > 0 ||
            notableLibraries.values.length > 0 ||
            libraryEvidence.values.length > 0) && {
            library_profile: {
              ecosystems: dedupeStrings(
                input.iocs.compiler_artifacts?.library_profile?.ecosystems || []
              ),
              top_crates: topCrates.values,
              notable_libraries: notableLibraries.values,
              evidence: libraryEvidence.values,
            },
          }),
        },
      }),
    },
    evidence: evidence.values,
    ...(input.evidence_lineage ? { evidence_lineage: input.evidence_lineage } : {}),
    ...(input.confidence_semantics ? { confidence_semantics: input.confidence_semantics } : {}),
    recommendation: truncateText(input.recommendation, 600),
    truncation: collectTruncationEntries([
      ['evidence', evidence.budget],
      ['suspicious_imports', suspiciousImports.budget],
      ['suspicious_strings', suspiciousStrings.budget],
      ['yara_matches', yaraMatches.budget],
      ['yara_low_confidence', yaraLowConfidence.budget],
      ['urls', urls.budget],
      ['ip_addresses', ipAddresses.budget],
      ['file_paths', filePaths.budget],
      ['registry_keys', registryKeys.budget],
      ['high_value_iocs.suspicious_apis', suspiciousApis.budget],
      ['high_value_iocs.commands', commands.budget],
      ['high_value_iocs.pipes', pipes.budget],
      ['high_value_iocs.network', network.budget],
      ['compiler_artifacts.cargo_paths', cargoPaths.budget],
      ['compiler_artifacts.rust_markers', rustMarkers.budget],
      ['compiler_artifacts.library_profile.top_crates', topCrates.budget],
      ['compiler_artifacts.library_profile.notable_libraries', notableLibraries.budget],
      ['compiler_artifacts.library_profile.evidence', libraryEvidence.budget],
    ]),
  }
}

export function buildStaticStageDigest(
  input: BuildStaticStageDigestInput
): StaticStageDigest {
  const keyFindings = limitArray('key_findings', dedupeStrings(input.key_findings || []))
  const coverage =
    input.coverage ||
    buildCoverageEnvelope({
      coverageLevel: 'static_core',
      completionState: 'bounded',
      sampleSizeTier: 'small',
      analysisBudgetProfile: 'balanced',
      coverageGaps: [
        {
          domain: 'reconstruction_export',
          status: 'missing',
          reason: 'Static digest stops before export or validation artifacts.',
        },
      ],
      knownFindings: keyFindings.values,
      unverifiedAreas: ['Source-like reconstruction and dynamic verification remain outside the static digest.'],
      upgradePaths: [
        {
          tool: 'workflow.reconstruct',
          purpose: 'Continue from static context into reconstruction.',
          closes_gaps: ['reconstruction_export'],
          expected_coverage_gain: 'Adds export artifacts and deeper corroboration.',
          cost_tier: 'high',
        },
      ],
    })
  return {
    schema_version: 1,
    sample_id: input.sample_id,
    stage: 'static',
    detail_level: 'compact',
    created_at: input.created_at || new Date().toISOString(),
    session_tag: input.session_tag || null,
    source_artifact_refs: dedupeArtifactRefs(input.source_artifact_refs || []),
    ...coverage,
    ...(input.binary_profile_summary ? { binary_profile_summary: input.binary_profile_summary } : {}),
    ...(input.rust_profile_summary ? { rust_profile_summary: input.rust_profile_summary } : {}),
    ...(input.static_capability_summary
      ? { static_capability_summary: input.static_capability_summary }
      : {}),
    ...(input.pe_structure_summary ? { pe_structure_summary: input.pe_structure_summary } : {}),
    ...(input.compiler_packer_summary
      ? { compiler_packer_summary: input.compiler_packer_summary }
      : {}),
    ...(input.semantic_explanation_summary
      ? { semantic_explanation_summary: input.semantic_explanation_summary }
      : {}),
    key_findings: keyFindings.values,
    recommendation: truncateText(input.recommendation, 600),
    truncation: collectTruncationEntries([['key_findings', keyFindings.budget]]),
  }
}

export function buildDeepStageDigest(
  input: BuildDeepStageDigestInput
): DeepStageDigest {
  const topFunctions = limitArray('top_functions', input.top_functions)
  const functionExplanations = limitArray('function_explanations', input.function_explanations)
  const trimmedExplanations = functionExplanations.values.map((item) => {
    const guidance = limitArray('rewrite_guidance', dedupeStrings(item.rewrite_guidance || []))
    return {
      ...item,
      summary: truncateText(item.summary, 300),
      rewrite_guidance: guidance.values,
    }
  })
  const analysisGaps = limitArray('unresolved_unknowns', dedupeStrings(input.analysis_gaps))
  const coverage =
    input.coverage ||
    buildCoverageEnvelope({
      coverageLevel: 'deep_static',
      completionState: 'completed',
      sampleSizeTier: 'small',
      analysisBudgetProfile: 'deep',
      coverageGaps: analysisGaps.values.map((item) => ({
        domain: 'deep_analysis_gap',
        status: 'degraded' as const,
        reason: item,
      })),
      knownFindings: topFunctions.values.map((item) => `${item.address}: ${item.name || 'function'} retained in deep digest.`),
      unverifiedAreas: ['Source-like reconstruction export remains outside the deep digest.'],
      upgradePaths: [
        {
          tool: 'workflow.reconstruct',
          purpose: 'Continue from deep static findings into reconstruction export.',
          closes_gaps: ['reconstruction_export'],
          expected_coverage_gain: 'Adds export artifacts and validation notes beyond the deep digest.',
          cost_tier: 'high',
        },
      ],
    })

  return {
    schema_version: 1,
    sample_id: input.sample_id,
    stage: 'deep',
    detail_level: 'compact',
    created_at: input.created_at || new Date().toISOString(),
    session_tag: input.session_tag || null,
    source_artifact_refs: dedupeArtifactRefs(input.source_artifact_refs || []),
    ...coverage,
    summary: truncateText(input.summary, 900),
    ...(input.ghidra_execution ? { ghidra_execution: input.ghidra_execution } : {}),
    top_functions: topFunctions.values,
    function_explanations: trimmedExplanations,
    analysis_gaps: analysisGaps.values,
    recommendation: truncateText(input.recommendation, 600),
    truncation: collectTruncationEntries([
      ['top_functions', topFunctions.budget],
      ['function_explanations', functionExplanations.budget],
      ['analysis_gaps', analysisGaps.budget],
    ]),
  }
}

function buildExecutiveSummary(
  triage: TriageStageDigest,
  staticDigest?: StaticStageDigest | null,
  deepDigest?: DeepStageDigest | null
): string {
  const parts = [triage.summary]
  if (staticDigest?.key_findings?.length) {
    parts.push(`Static/toolchain digest highlights: ${staticDigest.key_findings.slice(0, 3).join('; ')}.`)
  }
  if (deepDigest?.summary) {
    parts.push(deepDigest.summary)
  }
  return truncateText(parts.filter(Boolean).join(' '), 1400)
}

function buildAnalystSummary(
  triage: TriageStageDigest,
  staticDigest?: StaticStageDigest | null,
  deepDigest?: DeepStageDigest | null
): string {
  const sections = [
    `Threat posture: ${triage.threat_level} (confidence=${triage.confidence.toFixed(2)}).`,
    triage.recommendation,
    staticDigest?.recommendation || '',
    deepDigest?.recommendation || '',
  ].filter(Boolean)
  return truncateText(sections.join(' '), 1600)
}

export function buildFinalStageDigest(
  input: BuildFinalStageDigestInput
): FinalStageDigest {
  const keyFindings = limitArray(
    'key_findings',
    dedupeStrings([
      ...input.triage.evidence.slice(0, 4),
      ...(input.staticDigest?.key_findings || []),
      ...(input.deepDigest?.analysis_gaps.length
        ? input.deepDigest.analysis_gaps.map((item) => `Gap: ${item}`)
        : []),
    ])
  )
  const nextSteps = limitArray(
    'next_steps',
    dedupeStrings([
      input.triage.recommendation,
      input.staticDigest?.recommendation || null,
      input.deepDigest?.recommendation || null,
      'Use artifact.read or artifacts.list on referenced summary artifacts for deeper supporting detail.',
    ])
  )
  const unresolved = limitArray(
    'unresolved_unknowns',
    dedupeStrings([
      ...(input.deepDigest?.analysis_gaps || []),
      ...(input.triage.iocs.yara_low_confidence || []).map((item) => `Low-confidence YARA: ${item}`),
    ])
  )
  const mergedCoverage =
    input.coverage ||
    buildCoverageEnvelope({
      coverageLevel: input.deepDigest?.coverage_level || input.staticDigest?.coverage_level || input.triage.coverage_level,
      completionState:
        input.deepDigest?.completion_state ||
        input.staticDigest?.completion_state ||
        input.triage.completion_state,
      sampleSizeTier:
        input.deepDigest?.sample_size_tier ||
        input.staticDigest?.sample_size_tier ||
        input.triage.sample_size_tier,
      analysisBudgetProfile:
        input.deepDigest?.analysis_budget_profile ||
        input.staticDigest?.analysis_budget_profile ||
        input.triage.analysis_budget_profile,
      downgradeReasons: dedupeStrings([
        ...(input.triage.downgrade_reasons || []),
        ...(input.staticDigest?.downgrade_reasons || []),
        ...(input.deepDigest?.downgrade_reasons || []),
      ]),
      coverageGaps: normalizeCoverageGaps([
        ...input.triage.coverage_gaps,
        ...(input.staticDigest?.coverage_gaps || []),
        ...(input.deepDigest?.coverage_gaps || []),
      ]),
      confidenceByDomain: {
        ...input.triage.confidence_by_domain,
        ...(input.staticDigest?.confidence_by_domain || {}),
        ...(input.deepDigest?.confidence_by_domain || {}),
      },
      knownFindings: dedupeStrings([
        ...input.triage.known_findings,
        ...(input.staticDigest?.known_findings || []),
        ...(input.deepDigest?.known_findings || []),
      ]),
      suspectedFindings: dedupeStrings([
        ...input.triage.suspected_findings,
        ...(input.staticDigest?.suspected_findings || []),
        ...(input.deepDigest?.suspected_findings || []),
      ]),
      unverifiedAreas: dedupeStrings([
        ...input.triage.unverified_areas,
        ...(input.staticDigest?.unverified_areas || []),
        ...(input.deepDigest?.unverified_areas || []),
      ]),
      upgradePaths: normalizeUpgradePaths([
        ...input.triage.upgrade_paths,
        ...(input.staticDigest?.upgrade_paths || []),
        ...(input.deepDigest?.upgrade_paths || []),
      ]),
    })

  return {
    schema_version: 1,
    sample_id: input.sample_id,
    stage: 'final',
    detail_level: 'compact',
    created_at: input.created_at || new Date().toISOString(),
    session_tag: input.session_tag || null,
    source_artifact_refs: dedupeArtifactRefs(input.source_artifact_refs || []),
    ...mergedCoverage,
    stage_artifact_refs: dedupeArtifactRefs(input.stage_artifact_refs || []).slice(
      0,
      DIGEST_LIST_LIMITS.stage_artifacts
    ),
    synthesis_mode: input.synthesis_mode,
    ...(input.model_name ? { model_name: input.model_name } : {}),
    executive_summary: buildExecutiveSummary(input.triage, input.staticDigest, input.deepDigest),
    analyst_summary: buildAnalystSummary(input.triage, input.staticDigest, input.deepDigest),
    threat_level: input.triage.threat_level,
    confidence: input.triage.confidence,
    key_findings: keyFindings.values,
    next_steps: nextSteps.values,
    unresolved_unknowns: unresolved.values,
    ...(input.explanation_graphs?.length
      ? {
          explanation_graphs: input.explanation_graphs.slice(0, 4),
        }
      : {}),
    ...(input.explanation_artifact_refs?.length
      ? {
          explanation_artifact_refs: dedupeArtifactRefs(input.explanation_artifact_refs).slice(0, 4),
        }
      : {}),
    truncation: collectTruncationEntries([
      ['key_findings', keyFindings.budget],
      ['next_steps', nextSteps.budget],
      ['unresolved_unknowns', unresolved.budget],
    ]),
  }
}

export function buildArtifactRefFromParts(ref: {
  id: string
  type: string
  path: string
  sha256: string
  mime?: string | null
  metadata?: Record<string, unknown>
}): ArtifactRef {
  return {
    id: ref.id,
    type: ref.type,
    path: ref.path,
    sha256: ref.sha256,
    ...(ref.mime ? { mime: ref.mime } : {}),
    ...(ref.metadata ? { metadata: ref.metadata } : {}),
  }
}

export function isSummaryStage(value: string): value is SummaryStage {
  return (SUMMARY_STAGE_VALUES as readonly string[]).includes(value)
}
