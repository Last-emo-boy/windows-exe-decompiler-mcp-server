import { describe, expect, test } from '@jest/globals'
import {
  buildBreakpointCandidates,
  buildCryptoFindings,
  buildNormalizedTracePlan,
  extractConstantCandidates,
  summarizeNormalizedTracePlan,
} from '../../src/crypto-breakpoint-analysis.js'

describe('crypto-breakpoint-analysis helpers', () => {
  test('should extract crypto constant candidates from S-box and encoded material', () => {
    const candidates = extractConstantCandidates(
      [
        { value: '637c777bf26b6fc53001672bfed7ab76ca82c97d' },
        { value: '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF', labels: ['encoded_candidate'] },
      ],
      80,
      8
    )

    expect(candidates.some((item) => item.kind === 'sbox' && item.label.includes('AES'))).toBe(true)
    expect(candidates.some((item) => item.kind === 'key_material')).toBe(true)
  })

  test('should localize AES findings from function context and runtime evidence', () => {
    const built = buildCryptoFindings({
      functionContexts: [
        {
          function: 'FUN_140023A50',
          address: '0x140023a50',
          top_strings: ['AES-256', 'CBC mode'],
          sensitive_apis: ['AES_encrypt'],
          rationale: ['string:AES-256'],
        },
      ],
      stringRecords: [
        {
          value: '637c777bf26b6fc53001672bfed7ab76ca82c97d',
          function_refs: [{ address: '0x140023a50', name: 'FUN_140023A50' }],
        },
      ],
      imports: {
        'custom.dll': ['AES_encrypt'],
      },
      dynamicEvidence: {
        observed_apis: ['AES_encrypt'],
      } as any,
      hasCryptoCapability: true,
      xrefAvailable: true,
    })

    expect(built.findings.length).toBeGreaterThan(0)
    expect(built.findings[0].algorithm_family).toBe('aes')
    expect(built.findings[0].algorithm_name).toContain('AES')
    expect(built.findings[0].mode).toBe('CBC')
    expect(built.findings[0].function).toBe('FUN_140023A50')
    expect(built.findings[0].dynamic_support).toBe(true)
  })

  test('should create API-call breakpoint candidates even without localized function boundaries', () => {
    const candidates = buildBreakpointCandidates({
      findings: [
        {
          algorithm_family: 'windows_cryptoapi',
          algorithm_name: 'Windows CryptoAPI',
          mode: null,
          confidence: 0.82,
          function: null,
          address: null,
          source_apis: ['CryptEncrypt'],
          evidence: [
            {
              kind: 'import',
              value: 'CryptEncrypt',
              source_tool: 'pe.imports.extract',
              confidence: 0.7,
            },
          ],
          candidate_constants: [],
          dynamic_support: true,
          xref_available: false,
        },
      ] as any,
      dynamicEvidence: {
        observed_apis: ['CryptEncrypt'],
      } as any,
    })

    expect(candidates.some((item) => item.kind === 'api_call' && item.api === 'CryptEncrypt')).toBe(true)
  })

  test('should build normalized trace plans with Frida-oriented runtime mapping', () => {
    const plan = buildNormalizedTracePlan({
      breakpoint: {
        kind: 'api_call',
        api: 'BCryptEncrypt',
        module: 'bcrypt.dll',
        reason: 'BCryptEncrypt is a likely crypto transition point',
        confidence: 0.88,
        context_capture: ['rcx', 'rdx', 'return_value'],
        evidence_sources: ['dynamic.trace:observed_api'],
        dynamic_support: true,
      },
      condition: {
        logic: 'all',
        predicates: [
          {
            source: 'hit_count',
            operator: 'gte',
            value: 2,
          },
        ],
      },
      runtimeReady: false,
    })

    expect(plan.runtime_mapping.recommended_tool).toBe('frida.runtime.instrument')
    expect(plan.runtime_mapping.suggested_script_name).toBe('crypto_finder')
    expect(plan.capture.registers).toContain('rcx')
    expect(summarizeNormalizedTracePlan(plan)).toContain('BCryptEncrypt')
  })
})
