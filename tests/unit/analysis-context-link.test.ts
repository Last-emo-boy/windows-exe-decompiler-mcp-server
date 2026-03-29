import { beforeEach, describe, expect, jest, test } from '@jest/globals'
import { createAnalysisContextLinkHandler } from '../../src/tools/analysis-context-link.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'

describe('analysis.context.link tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockCacheManager: jest.Mocked<CacheManager>

  beforeEach(() => {
    mockWorkspaceManager = {} as unknown as jest.Mocked<WorkspaceManager>
    mockDatabase = {
      findSample: jest.fn(),
      findAnalysesBySample: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>
    mockCacheManager = {
      getCachedResult: jest.fn(),
      setCachedResult: jest.fn(),
    } as unknown as jest.Mocked<CacheManager>

    mockDatabase.findSample.mockReturnValue({
      id: 'sha256:' + 'c'.repeat(64),
      sha256: 'c'.repeat(64),
      md5: 'd'.repeat(32),
      size: 2222,
      file_type: 'PE32+',
      created_at: '2026-03-23T00:00:00.000Z',
      source: 'test',
    })
    mockDatabase.findAnalysesBySample.mockReturnValue([
      {
        id: 'analysis-1',
        backend: 'ghidra',
        status: 'completed',
        started_at: '2026-03-23T00:00:00.000Z',
        finished_at: '2026-03-23T00:10:00.000Z',
      },
    ] as any)
    mockCacheManager.getCachedResult.mockResolvedValue(null)
    mockCacheManager.setCachedResult.mockResolvedValue(undefined)
  })

  test('should merge strings and return compact function contexts when xrefs are available', async () => {
    const stringsExtract = jest.fn(async () => ({
      ok: true,
      data: {
        strings: [
          { offset: 0x1000, string: 'http://evil.example/c2', encoding: 'ascii' },
          { offset: 0x1200, string: 'CreateRemoteThread', encoding: 'ascii' },
        ],
        summary: {
          context_windows: [],
        },
      },
      artifacts: [{ id: 'artifact-extract', type: 'enriched_string_analysis', path: 'a.json', sha256: '1' }],
    }))
    const stringsFlossDecode = jest.fn(async () => ({
      ok: true,
      data: {
        decoded_strings: [
          { offset: 0x2000, string: 'campaign_id=42', type: 'stack', decoding_method: 'stack' },
        ],
      },
      artifacts: [{ id: 'artifact-floss', type: 'enriched_string_analysis', path: 'b.json', sha256: '2' }],
    }))
    const analyzeCrossReferences = jest.fn(async (_sampleId: string, options: any) => ({
      target_type: options.targetType,
      target: {
        query: options.query,
        resolved_name: options.targetType === 'api' ? options.query : undefined,
        resolved_address: '0x140010000',
      },
      inbound: [
        {
          function: 'FUN_140010000',
          address: '0x140010000',
          depth: 1,
          relation: options.targetType === 'api' ? 'calls_api' : 'string_ref',
          reference_types: ['call'],
          reference_addresses: ['0x140010111'],
          matched_values: [options.query],
        },
      ],
      outbound: [],
      direct_xrefs: [],
      truncated: false,
      limits: {
        depth: options.depth || 1,
        limit: options.limit || 8,
      },
    }))

    const handler = createAnalysisContextLinkHandler(
      mockWorkspaceManager,
      mockDatabase,
      mockCacheManager,
      {
        stringsExtract,
        stringsFlossDecode,
        analyzeCrossReferences,
      }
    )

    const result = await handler({
      sample_id: 'sha256:' + 'c'.repeat(64),
      reuse_cached: false,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('ready')
    expect(data.xref_status).toBe('available')
    expect(data.function_contexts).toHaveLength(1)
    expect(data.function_contexts[0].function).toBe('FUN_140010000')
    expect(data.source_artifact_refs).toHaveLength(2)
    expect(data.merged_strings.top_suspicious.length).toBeGreaterThan(0)
    expect(data.recommended_next_tools).toContain('workflow.reconstruct')
    expect(analyzeCrossReferences).toHaveBeenCalled()
    expect(mockCacheManager.setCachedResult).toHaveBeenCalled()
  })

  test('should return partial string-only context when Ghidra prerequisites are missing', async () => {
    const handler = createAnalysisContextLinkHandler(
      mockWorkspaceManager,
      mockDatabase,
      mockCacheManager,
      {
        stringsExtract: async () => ({
          ok: true,
          data: {
            strings: [{ offset: 0x1000, string: 'http://evil.example/c2', encoding: 'ascii' }],
            summary: { context_windows: [] },
          },
        }),
        stringsFlossDecode: async () => ({
          ok: true,
          data: {
            decoded_strings: [],
          },
        }),
        analyzeCrossReferences: async () => {
          throw new Error('Please run ghidra.analyze first; function index readiness is unavailable')
        },
      }
    )

    const result = await handler({
      sample_id: 'sha256:' + 'c'.repeat(64),
      reuse_cached: false,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('partial')
    expect(data.xref_status).toBe('unavailable')
    expect(data.function_contexts).toHaveLength(0)
    expect(data.next_actions[0]).toContain('ghidra.analyze')
    expect(result.warnings?.some((item) => item.includes('ghidra.analyze'))).toBe(true)
  })
})
