import { describe, expect, test } from '@jest/globals'
import {
  buildBudgetDowngradeReasons,
  buildCoverageEnvelope,
  classifySampleSizeTier,
  deriveAnalysisBudgetProfile,
  normalizeCoverageGaps,
  normalizeUpgradePaths,
} from '../../src/analysis-coverage.js'

describe('analysis coverage helpers', () => {
  test('should classify sample size tiers deterministically', () => {
    expect(classifySampleSizeTier(0)).toBe('small')
    expect(classifySampleSizeTier(1024 * 1024)).toBe('small')
    expect(classifySampleSizeTier(2 * 1024 * 1024)).toBe('medium')
    expect(classifySampleSizeTier(10 * 1024 * 1024)).toBe('large')
    expect(classifySampleSizeTier(50 * 1024 * 1024)).toBe('oversized')
  })

  test('should downshift deep requests for large samples', () => {
    expect(deriveAnalysisBudgetProfile('deep', 'small')).toBe('deep')
    expect(deriveAnalysisBudgetProfile('deep', 'large')).toBe('balanced')
    expect(deriveAnalysisBudgetProfile('balanced', 'oversized')).toBe('quick')
  })

  test('should normalize coverage gaps and upgrade paths', () => {
    const gaps = normalizeCoverageGaps([
      { domain: 'ghidra_analysis', status: 'missing', reason: 'Not started yet.' },
      { domain: 'ghidra_analysis', status: 'missing', reason: 'Not started yet.' },
      { domain: 'dynamic_behavior', reason: 'No runtime execution was performed.' },
    ])
    const upgrades = normalizeUpgradePaths([
      {
        tool: 'ghidra.analyze',
        purpose: 'Recover function-level evidence.',
        closes_gaps: ['ghidra_analysis', 'function_attribution'],
        expected_coverage_gain: 'Adds decompiler-backed function context.',
      },
      {
        tool: 'ghidra.analyze',
        purpose: 'Recover function-level evidence.',
        closes_gaps: ['ghidra_analysis'],
        expected_coverage_gain: 'Adds decompiler-backed function context.',
      },
    ])

    expect(gaps).toHaveLength(2)
    expect(gaps[1].status).toBe('missing')
    expect(upgrades).toHaveLength(1)
    expect(upgrades[0].availability).toBe('ready')
    expect(upgrades[0].cost_tier).toBe('medium')
  })

  test('should build a compact coverage envelope', () => {
    const coverage = buildCoverageEnvelope({
      coverageLevel: 'quick',
      completionState: 'bounded',
      sampleSizeTier: 'large',
      analysisBudgetProfile: 'balanced',
      downgradeReasons: buildBudgetDowngradeReasons({
        requestedDepth: 'deep',
        sampleSizeTier: 'large',
        analysisBudgetProfile: 'balanced',
      }),
      coverageGaps: [
        { domain: 'ghidra_analysis', status: 'missing', reason: 'No queued decompiler pass was started.' },
      ],
      confidenceByDomain: {
        imports: 0.9,
        strings: 0.8,
      },
      knownFindings: ['Observed suspicious import cluster.'],
      suspectedFindings: ['Possible packing based on overlay signal.'],
      unverifiedAreas: ['Function-level attribution remains unverified.'],
      upgradePaths: [
        {
          tool: 'ghidra.analyze',
          purpose: 'Recover function-level evidence.',
          closes_gaps: ['ghidra_analysis'],
          expected_coverage_gain: 'Adds decompiler-backed function context.',
          cost_tier: 'high',
        },
      ],
    })

    expect(coverage.coverage_level).toBe('quick')
    expect(coverage.completion_state).toBe('bounded')
    expect(coverage.sample_size_tier).toBe('large')
    expect(coverage.analysis_budget_profile).toBe('balanced')
    expect(coverage.downgrade_reasons[0]).toContain('downgraded requested deep analysis')
    expect(coverage.known_findings).toEqual(['Observed suspicious import cluster.'])
    expect(coverage.upgrade_paths[0].tool).toBe('ghidra.analyze')
  })
})
