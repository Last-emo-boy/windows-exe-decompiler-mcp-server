import { z } from 'zod'

export const CoverageLevelSchema = z.enum([
  'quick',
  'static_core',
  'deep_static',
  'reconstruction',
  'dynamic_verified',
])

export const CompletionStateSchema = z.enum([
  'queued',
  'partial',
  'bounded',
  'completed',
  'degraded',
])

export const SampleSizeTierSchema = z.enum(['small', 'medium', 'large', 'oversized'])

export const AnalysisBudgetProfileSchema = z.enum(['quick', 'balanced', 'deep'])

export const CoverageGapStatusSchema = z.enum(['missing', 'skipped', 'queued', 'degraded', 'blocked'])

export const UpgradeCostTierSchema = z.enum(['low', 'medium', 'high'])

export const UpgradeAvailabilitySchema = z.enum(['ready', 'blocked', 'manual_only'])

export const CoverageGapSchema = z.object({
  domain: z.string().min(1),
  status: CoverageGapStatusSchema,
  reason: z.string().min(1),
})

export const ConfidenceByDomainSchema = z.object({
  imports: z.number().min(0).max(1).optional(),
  strings: z.number().min(0).max(1).optional(),
  iocs: z.number().min(0).max(1).optional(),
  packer: z.number().min(0).max(1).optional(),
  capabilities: z.number().min(0).max(1).optional(),
  function_index: z.number().min(0).max(1).optional(),
  decompilation: z.number().min(0).max(1).optional(),
  graph_context: z.number().min(0).max(1).optional(),
  reconstruction: z.number().min(0).max(1).optional(),
  dynamic_behavior: z.number().min(0).max(1).optional(),
  crypto: z.number().min(0).max(1).optional(),
})

export const UpgradePathSchema = z.object({
  tool: z.string().min(1),
  purpose: z.string().min(1),
  closes_gaps: z.array(z.string().min(1)),
  expected_coverage_gain: z.string().min(1),
  cost_tier: UpgradeCostTierSchema,
  availability: UpgradeAvailabilitySchema,
  prerequisites: z.array(z.string()),
  blockers: z.array(z.string()),
  requires_approval: z.boolean().default(false),
})

export const CoverageEnvelopeSchema = z.object({
  coverage_level: CoverageLevelSchema,
  completion_state: CompletionStateSchema,
  sample_size_tier: SampleSizeTierSchema,
  analysis_budget_profile: AnalysisBudgetProfileSchema,
  downgrade_reasons: z.array(z.string()),
  coverage_gaps: z.array(CoverageGapSchema),
  confidence_by_domain: ConfidenceByDomainSchema,
  known_findings: z.array(z.string()),
  suspected_findings: z.array(z.string()),
  unverified_areas: z.array(z.string()),
  upgrade_paths: z.array(UpgradePathSchema),
})

export type CoverageLevel = z.infer<typeof CoverageLevelSchema>
export type CompletionState = z.infer<typeof CompletionStateSchema>
export type SampleSizeTier = z.infer<typeof SampleSizeTierSchema>
export type AnalysisBudgetProfile = z.infer<typeof AnalysisBudgetProfileSchema>
export type CoverageGap = z.infer<typeof CoverageGapSchema>
export type ConfidenceByDomain = z.infer<typeof ConfidenceByDomainSchema>
export type UpgradePath = z.infer<typeof UpgradePathSchema>
export type CoverageEnvelope = z.infer<typeof CoverageEnvelopeSchema>

const FINDING_LIMIT = 8
const UPGRADE_LIMIT = 6

function dedupeStrings(values: Array<string | null | undefined>, limit = FINDING_LIMIT): string[] {
  return Array.from(
    new Set(
      values
        .filter((value): value is string => Boolean(value && value.trim().length > 0))
        .map((value) => value.trim())
    )
  ).slice(0, limit)
}

export function classifySampleSizeTier(sizeBytes: number): SampleSizeTier {
  if (!Number.isFinite(sizeBytes) || sizeBytes <= 0) {
    return 'small'
  }
  if (sizeBytes <= 1 * 1024 * 1024) {
    return 'small'
  }
  if (sizeBytes <= 5 * 1024 * 1024) {
    return 'medium'
  }
  if (sizeBytes <= 20 * 1024 * 1024) {
    return 'large'
  }
  return 'oversized'
}

export function deriveAnalysisBudgetProfile(
  requestedDepth: 'safe' | 'balanced' | 'deep',
  sampleSizeTier: SampleSizeTier
): AnalysisBudgetProfile {
  if (requestedDepth === 'safe') {
    return 'quick'
  }
  if (requestedDepth === 'balanced') {
    return sampleSizeTier === 'oversized' ? 'quick' : 'balanced'
  }
  if (sampleSizeTier === 'large' || sampleSizeTier === 'oversized') {
    return 'balanced'
  }
  return 'deep'
}

export function buildBudgetDowngradeReasons(input: {
  requestedDepth: 'safe' | 'balanced' | 'deep'
  sampleSizeTier: SampleSizeTier
  analysisBudgetProfile: AnalysisBudgetProfile
  extraReasons?: Array<string | null | undefined>
}): string[] {
  const reasons: Array<string | null | undefined> = [...(input.extraReasons || [])]
  if (input.analysisBudgetProfile === 'quick' && input.requestedDepth !== 'safe') {
    reasons.push(
      `Sample size tier ${input.sampleSizeTier} triggered a quick budget profile instead of requested depth ${input.requestedDepth}.`
    )
  } else if (input.analysisBudgetProfile === 'balanced' && input.requestedDepth === 'deep') {
    reasons.push(
      `Sample size tier ${input.sampleSizeTier} downgraded requested deep analysis to a balanced budget profile.`
    )
  }
  return dedupeStrings(reasons, UPGRADE_LIMIT)
}

export function normalizeCoverageGaps(
  gaps: Array<Partial<CoverageGap> | null | undefined>
): CoverageGap[] {
  const seen = new Set<string>()
  const normalized: CoverageGap[] = []
  for (const gap of gaps) {
    if (!gap?.domain || !gap?.reason) {
      continue
    }
    const record: CoverageGap = {
      domain: gap.domain,
      status: gap.status || 'missing',
      reason: gap.reason,
    }
    const key = `${record.domain}:${record.status}:${record.reason}`
    if (seen.has(key)) {
      continue
    }
    seen.add(key)
    normalized.push(record)
  }
  return normalized
}

export function normalizeUpgradePaths(
  paths: Array<Partial<UpgradePath> | null | undefined>
): UpgradePath[] {
  const seen = new Set<string>()
  const normalized: UpgradePath[] = []
  for (const path of paths) {
    if (!path?.tool || !path.purpose || !path.expected_coverage_gain) {
      continue
    }
    const record: UpgradePath = {
      tool: path.tool,
      purpose: path.purpose,
      closes_gaps: dedupeStrings(path.closes_gaps || [], FINDING_LIMIT),
      expected_coverage_gain: path.expected_coverage_gain,
      cost_tier: path.cost_tier || 'medium',
      availability: path.availability || 'ready',
      prerequisites: dedupeStrings(path.prerequisites || [], FINDING_LIMIT),
      blockers: dedupeStrings(path.blockers || [], FINDING_LIMIT),
      requires_approval: Boolean(path.requires_approval),
    }
    const key = `${record.tool}:${record.purpose}:${record.expected_coverage_gain}`
    if (seen.has(key)) {
      continue
    }
    seen.add(key)
    normalized.push(record)
  }
  return normalized.slice(0, UPGRADE_LIMIT)
}

export interface BuildCoverageEnvelopeInput {
  coverageLevel: CoverageLevel
  completionState: CompletionState
  sampleSizeTier: SampleSizeTier
  analysisBudgetProfile: AnalysisBudgetProfile
  downgradeReasons?: Array<string | null | undefined>
  coverageGaps?: Array<Partial<CoverageGap> | null | undefined>
  confidenceByDomain?: Partial<ConfidenceByDomain>
  knownFindings?: Array<string | null | undefined>
  suspectedFindings?: Array<string | null | undefined>
  unverifiedAreas?: Array<string | null | undefined>
  upgradePaths?: Array<Partial<UpgradePath> | null | undefined>
}

export function buildCoverageEnvelope(input: BuildCoverageEnvelopeInput): CoverageEnvelope {
  return {
    coverage_level: input.coverageLevel,
    completion_state: input.completionState,
    sample_size_tier: input.sampleSizeTier,
    analysis_budget_profile: input.analysisBudgetProfile,
    downgrade_reasons: dedupeStrings(input.downgradeReasons || [], UPGRADE_LIMIT),
    coverage_gaps: normalizeCoverageGaps(input.coverageGaps || []),
    confidence_by_domain: {
      ...(input.confidenceByDomain || {}),
    },
    known_findings: dedupeStrings(input.knownFindings || []),
    suspected_findings: dedupeStrings(input.suspectedFindings || []),
    unverified_areas: dedupeStrings(input.unverifiedAreas || []),
    upgrade_paths: normalizeUpgradePaths(input.upgradePaths || []),
  }
}

export function mergeCoverageEnvelope<T extends Record<string, unknown>>(
  data: T,
  coverage: CoverageEnvelope
): T & CoverageEnvelope {
  return {
    ...data,
    ...coverage,
  }
}
