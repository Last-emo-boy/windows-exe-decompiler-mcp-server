import { beforeEach, describe, expect, jest, test } from '@jest/globals'
import { createCodeXrefsAnalyzeHandler } from '../../src/tools/code-xrefs-analyze.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'

describe('code.xrefs.analyze tool', () => {
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
      id: 'sha256:' + 'a'.repeat(64),
      sha256: 'a'.repeat(64),
      md5: 'b'.repeat(32),
      size: 1234,
      file_type: 'PE32+',
      created_at: '2026-03-23T00:00:00.000Z',
      source: 'test',
    })
    mockDatabase.findAnalysesBySample.mockReturnValue([])
    mockCacheManager.getCachedResult.mockResolvedValue(null)
    mockCacheManager.setCachedResult.mockResolvedValue(undefined)
  })

  test('should return setup_required when Ghidra-backed prerequisites are missing', async () => {
    const handler = createCodeXrefsAnalyzeHandler(
      mockWorkspaceManager,
      mockDatabase,
      mockCacheManager,
      {
        analyzeCrossReferences: async () => {
          throw new Error('Please run ghidra.analyze first; function index readiness is unavailable')
        },
      }
    )

    const result = await handler({
      sample_id: 'sha256:' + 'a'.repeat(64),
      target_type: 'string',
      query: 'http://evil.example/c2',
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('setup_required')
    expect(data.recommended_next_tools).toContain('ghidra.analyze')
    expect(result.warnings?.[0]).toContain('ghidra.analyze')
  })

  test('should return bounded ready results and cache them', async () => {
    const handler = createCodeXrefsAnalyzeHandler(
      mockWorkspaceManager,
      mockDatabase,
      mockCacheManager,
      {
        analyzeCrossReferences: async () => ({
          target_type: 'api',
          target: {
            query: 'WriteProcessMemory',
            resolved_name: 'WriteProcessMemory',
            resolved_address: '0x180012340',
          },
          inbound: [
            {
              function: 'FUN_180001000',
              address: '0x180001000',
              depth: 1,
              relation: 'calls_api',
              reference_types: ['call'],
              reference_addresses: ['0x180001111'],
              matched_values: ['WriteProcessMemory'],
            },
          ],
          outbound: [],
          direct_xrefs: [],
          truncated: true,
          limits: {
            depth: 1,
            limit: 5,
          },
        }),
      }
    )

    const result = await handler({
      sample_id: 'sha256:' + 'a'.repeat(64),
      target_type: 'api',
      query: 'WriteProcessMemory',
      limit: 5,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('ready')
    expect(data.target.resolved_name).toBe('WriteProcessMemory')
    expect(data.truncated).toBe(true)
    expect(data.recommended_next_tools).toContain('analysis.context.link')
    expect(mockCacheManager.setCachedResult).toHaveBeenCalled()
  })
})
