import { describe, expect, test } from '@jest/globals'
import {
  attachFunctionReferencesToBundle,
  buildEnrichedStringBundle,
  buildFunctionContextSummaries,
  compactStringBundleForContext,
  extractSuspiciousApiCandidates,
} from '../../src/string-xref-analysis.js'

describe('string-xref-analysis helpers', () => {
  test('should merge extracted and decoded strings with runtime-noise and encoded-candidate labels', () => {
    const bundle = buildEnrichedStringBundle(
      [
        { offset: 0x1000, string: 'http://evil.example/c2', encoding: 'ascii' },
        { offset: 0x1200, string: 'api-ms-win-core-file-l1-1-0.dll', encoding: 'ascii' },
        { offset: 0x1400, string: 'QWxhZGRpbjpvcGVuIHNlc2FtZQ==', encoding: 'ascii' },
        { offset: 0x1500, string: 'CreateRemoteThread', encoding: 'ascii' },
      ],
      [
        { offset: 0x2000, string: 'http://evil.example/c2', type: 'decoded', decoding_method: 'xor' },
        { offset: 0x2200, string: 'campaign_id=42', type: 'stack', decoding_method: 'stack' },
      ],
      { maxRecords: 16, maxHighlights: 8 }
    )

    expect(bundle.merged_sources).toBe(true)
    expect(bundle.total_records).toBe(5)
    expect(bundle.analyst_relevant_count).toBeGreaterThanOrEqual(4)
    expect(bundle.runtime_noise_count).toBeGreaterThanOrEqual(1)
    expect(bundle.encoded_candidate_count).toBeGreaterThanOrEqual(1)

    const mergedUrl = bundle.records.find((item) => item.value === 'http://evil.example/c2')
    expect(mergedUrl?.sources).toHaveLength(2)
    expect(mergedUrl?.labels).toContain('analyst_relevant')

    const runtimeNoise = bundle.records.find((item) => item.value.includes('api-ms-win-core-file'))
    expect(runtimeNoise?.labels).toContain('runtime_noise')

    const encodedCandidate = bundle.records.find((item) => item.value === 'QWxhZGRpbjpvcGVuIHNlc2FtZQ==')
    expect(encodedCandidate?.labels).toContain('encoded_candidate')

    const suspiciousApis = extractSuspiciousApiCandidates(bundle, 4)
    expect(suspiciousApis).toContain('CreateRemoteThread')

    const compact = compactStringBundleForContext(bundle)
    expect(compact.top_suspicious.length).toBeGreaterThan(0)
    expect(compact.top_iocs.some((item) => item.value === 'http://evil.example/c2')).toBe(true)
  })

  test('should attach function references and build compact function context summaries', () => {
    const bundle = buildEnrichedStringBundle(
      [{ offset: 0x1000, string: 'http://evil.example/c2', encoding: 'ascii' }],
      [{ offset: 0x2000, string: 'CreateRemoteThread', type: 'decoded', decoding_method: 'xor' }],
      { maxRecords: 8, maxHighlights: 6 }
    )

    const inboundNode = {
      function: 'FUN_140010000',
      address: '0x140010000',
      depth: 1,
      relation: 'string_ref',
      reference_types: ['data_read'],
      reference_addresses: ['0x140020000'],
      matched_values: ['http://evil.example/c2'],
    }

    const outboundNode = {
      function: 'FUN_140010000',
      address: '0x140010000',
      depth: 1,
      relation: 'calls',
      reference_types: ['call'],
      reference_addresses: ['0x140030000'],
      matched_values: ['CreateRemoteThread'],
    }

    const withRefs = attachFunctionReferencesToBundle(bundle, [
      {
        target_type: 'string',
        query: 'http://evil.example/c2',
        inbound: [inboundNode],
      },
    ])

    const urlRecord = withRefs.records.find((item) => item.value === 'http://evil.example/c2')
    expect(urlRecord?.function_refs?.[0]?.address).toBe('0x140010000')

    const contexts = buildFunctionContextSummaries(
      withRefs,
      [
        {
          target_type: 'string',
          query: 'http://evil.example/c2',
          inbound: [inboundNode],
          outbound: [],
        },
        {
          target_type: 'api',
          query: 'CreateRemoteThread',
          inbound: [inboundNode],
          outbound: [outboundNode],
        },
      ],
      {
        maxFunctions: 4,
        maxStringsPerFunction: 3,
      }
    )

    expect(contexts).toHaveLength(1)
    expect(contexts[0].function).toBe('FUN_140010000')
    expect(contexts[0].top_strings).toContain('http://evil.example/c2')
    expect(contexts[0].sensitive_apis).toContain('CreateRemoteThread')
    expect(contexts[0].outbound_refs).toContain('call')
  })
})
