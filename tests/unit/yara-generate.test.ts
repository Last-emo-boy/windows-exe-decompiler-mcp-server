/**
 * Unit tests for yara-rule-builder
 */

import {
  buildStringRule,
  buildImportRule,
  buildBytePatternRule,
  buildHybridRule,
  extractRuleEvidence,
  scoreRule,
  type RuleMeta,
  type RuleEvidence,
} from '../../src/yara-rule-builder.js'

const baseMeta: RuleMeta = {
  sample_id: 'sha256:abcd1234',
  description: 'Test rule',
  author: 'test',
  date: '2025-01-01',
}

describe('yara-rule-builder', () => {
  describe('buildStringRule', () => {
    it('generates valid YARA rule with string conditions', () => {
      const rule = buildStringRule(
        ['malware_payload', 'cmd.exe /c', 'HKEY_LOCAL_MACHINE'],
        baseMeta
      )
      expect(rule).toContain('rule ')
      expect(rule).toContain('strings:')
      expect(rule).toContain('malware_payload')
      expect(rule).toContain('condition:')
    })

    it('returns empty string for empty strings array', () => {
      const rule = buildStringRule([], baseMeta)
      expect(rule).toBe('')
    })
  })

  describe('buildImportRule', () => {
    it('generates rule with PE import conditions', () => {
      const rule = buildImportRule(
        ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
        baseMeta
      )
      expect(rule).toContain('rule ')
      expect(rule).toContain('VirtualAllocEx')
      expect(rule).toContain('condition:')
    })
  })

  describe('buildBytePatternRule', () => {
    it('generates rule with hex byte patterns', () => {
      const rule = buildBytePatternRule(
        [
          { offset: 0, hex: '4D5A', description: 'MZ header' },
          { offset: 0x80, hex: 'FF15', description: 'indirect call' },
        ],
        baseMeta
      )
      expect(rule).toContain('4D5A')
      expect(rule).toContain('FF15')
      expect(rule).toContain('condition:')
    })
  })

  describe('buildHybridRule', () => {
    const evidence: RuleEvidence = {
      unique_strings: ['malware_c2', 'beacon_config'],
      suspicious_imports: ['VirtualAllocEx', 'WriteProcessMemory'],
      all_imports: ['VirtualAllocEx', 'WriteProcessMemory', 'GetProcAddress', 'LoadLibraryA'],
      byte_patterns: [],
      pe_imphash: 'aabbccdd',
      file_size: 102400,
    }

    it('generates hybrid rule with tight strictness', () => {
      const rule = buildHybridRule(evidence, 'tight', baseMeta)
      expect(rule).toContain('rule ')
      expect(rule).toContain('condition:')
    })

    it('generates hybrid rule with balanced strictness', () => {
      const rule = buildHybridRule(evidence, 'balanced', baseMeta)
      expect(rule).toContain('rule ')
    })

    it('generates hybrid rule with loose strictness', () => {
      const rule = buildHybridRule(evidence, 'loose', baseMeta)
      expect(rule).toContain('rule ')
    })
  })

  describe('extractRuleEvidence', () => {
    it('extracts evidence from artifact data', () => {
      const data = {
        strings: ['Hello', 'cmd.exe', 'calc.exe'],
        imports: ['CreateFileA', 'VirtualAlloc'],
        imphash: 'deadbeef',
        file_size: 50000,
      }
      const evidence = extractRuleEvidence(data)
      expect(evidence.all_imports.length).toBeGreaterThan(0)
      expect(evidence).toHaveProperty('unique_strings')
      expect(evidence).toHaveProperty('suspicious_imports')
    })

    it('handles empty artifact data', () => {
      const evidence = extractRuleEvidence({})
      expect(evidence.unique_strings).toEqual([])
      expect(evidence.all_imports).toEqual([])
    })
  })

  describe('scoreRule', () => {
    it('scores a rule with good evidence higher', () => {
      const evidence: RuleEvidence = {
        unique_strings: ['custom_mutex_name', 'rare_encryption_key'],
        suspicious_imports: ['VirtualAllocEx', 'NtCreateThread'],
        all_imports: ['VirtualAllocEx', 'NtCreateThread', 'GetProcAddress'],
        byte_patterns: [{ offset: 0, hex: 'DEADBEEF' }],
        pe_imphash: 'aabb',
        file_size: 100000,
      }
      const rule = buildHybridRule(evidence, 'balanced', baseMeta)
      const { score } = scoreRule(rule, evidence)
      expect(score).toBeGreaterThan(0)
      expect(score).toBeLessThanOrEqual(100)
    })

    it('scores a rule with minimal evidence lower', () => {
      const evidence: RuleEvidence = {
        unique_strings: [],
        suspicious_imports: [],
        all_imports: [],
        byte_patterns: [],
      }
      const rule = buildStringRule(['kernel32.dll'], baseMeta)
      const { score } = scoreRule(rule, evidence)
      expect(score).toBeLessThan(50)
    })
  })
})
