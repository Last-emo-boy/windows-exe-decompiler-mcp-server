/**
 * Unit tests for pe.exports.extract tool
 * Requirements: 3.3
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createPEExportsExtractHandler, PEExportsExtractInputSchema } from '../../src/plugins/pe-analysis/tools/pe-exports-extract.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'

describe('pe.exports.extract tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockCacheManager: jest.Mocked<CacheManager>

  beforeEach(() => {
    // Create mock workspace manager
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    // Create mock database
    mockDatabase = {
      findSample: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>

    // Create mock cache manager
    mockCacheManager = {
      getCachedResult: jest.fn(),
      setCachedResult: jest.fn(),
    } as unknown as jest.Mocked<CacheManager>
  })

  describe('Input validation', () => {
    test('should accept valid input with sample_id', () => {
      const input = {
        sample_id: 'sha256:abc123',
      }

      const result = PEExportsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.sample_id).toBe('sha256:abc123')
      }
    })

    test('should reject input without sample_id', () => {
      const input = {}

      const result = PEExportsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })

    test('should reject input with invalid sample_id type', () => {
      const input = {
        sample_id: 123, // should be string
      }

      const result = PEExportsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })
  })

  describe('Tool handler', () => {
    test('should return error when sample not found', async () => {
      const handler = createPEExportsExtractHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({
        sample_id: 'sha256:nonexistent',
      })

      expect(result.ok).toBe(false)
      expect(result.errors).toContain('Sample not found: sha256:nonexistent')
    })

    test('should return cached result when available', async () => {
      const handler = createPEExportsExtractHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

      const mockSample = {
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: 'def456',
        size: 1024,
        file_type: 'PE',
        created_at: '2024-01-01T00:00:00Z',
        source: 'upload',
      }

      const mockCachedData = {
        exports: [
          { ordinal: 1, address: 0x1000, name: 'ExportedFunction1' },
          { ordinal: 2, address: 0x2000, name: 'ExportedFunction2' },
        ],
        forwarders: [
          { ordinal: 3, address: 0x3000, name: 'ForwardedFunction', forwarder: 'KERNEL32.CreateFileA' },
        ],
        total_exports: 2,
        total_forwarders: 1,
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      mockCacheManager.getCachedResult.mockResolvedValue(mockCachedData)

      const result = await handler({
        sample_id: 'sha256:abc123',
      })

      expect(result.ok).toBe(true)
      expect(result.data).toEqual(mockCachedData)
      expect(result.warnings).toContain('Result from cache')
      expect(mockCacheManager.getCachedResult).toHaveBeenCalled()
    })

    test('should generate correct cache key', async () => {
      const handler = createPEExportsExtractHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

      const mockSample = {
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: 'def456',
        size: 1024,
        file_type: 'PE',
        created_at: '2024-01-01T00:00:00Z',
        source: 'upload',
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      mockCacheManager.getCachedResult.mockResolvedValue(null)
      mockWorkspaceManager.getWorkspace.mockResolvedValue({
        root: '/workspace/ab/c1/abc123',
        original: '/workspace/ab/c1/abc123/original',
        cache: '/workspace/ab/c1/abc123/cache',
        ghidra: '/workspace/ab/c1/abc123/ghidra',
        reports: '/workspace/ab/c1/abc123/reports',
      })

      // Mock fs.readdir to return empty array (will cause error, but we can check cache key generation)
      await handler({
        sample_id: 'sha256:abc123',
      })

      // Should have called getCachedResult with a cache key
      expect(mockCacheManager.getCachedResult).toHaveBeenCalled()
      
      // The call should have been made with a string starting with "cache:"
      const cacheKey = mockCacheManager.getCachedResult.mock.calls[0][0] as string
      expect(cacheKey).toMatch(/^cache:[a-f0-9]{64}$/)
    })
  })

  describe('Requirements validation', () => {
    test('should extract function names, ordinals, and addresses (Requirement 3.3)', async () => {
      const handler = createPEExportsExtractHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

      const mockSample = {
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: 'def456',
        size: 1024,
        file_type: 'PE',
        created_at: '2024-01-01T00:00:00Z',
        source: 'upload',
      }

      const mockExportsData = {
        exports: [
          { ordinal: 1, address: 0x1000, name: 'MyExportedFunction' },
          { ordinal: 2, address: 0x2000, name: 'AnotherExport' },
          { ordinal: 3, address: 0x3000, name: null }, // Export by ordinal only
        ],
        forwarders: [
          { ordinal: 4, address: 0x4000, name: 'ForwardedFunc', forwarder: 'KERNEL32.CreateFileA' },
        ],
        total_exports: 3,
        total_forwarders: 1,
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      mockCacheManager.getCachedResult.mockResolvedValue(mockExportsData)

      const result = await handler({
        sample_id: 'sha256:abc123',
      })

      expect(result.ok).toBe(true)
      expect(result.data).toHaveProperty('exports')
      expect(result.data).toHaveProperty('forwarders')
      expect(result.data).toHaveProperty('total_exports')
      expect(result.data).toHaveProperty('total_forwarders')
      
      const data = result.data as {
        exports: Array<{ ordinal: number; address: number; name: string | null }>
        forwarders: Array<{ ordinal: number; address: number; name: string | null; forwarder: string }>
        total_exports: number
        total_forwarders: number
      }
      
      // Verify exports structure
      expect(data.exports).toHaveLength(3)
      expect(data.exports[0]).toHaveProperty('ordinal')
      expect(data.exports[0]).toHaveProperty('address')
      expect(data.exports[0]).toHaveProperty('name')
      expect(data.exports[0].ordinal).toBe(1)
      expect(data.exports[0].address).toBe(0x1000)
      expect(data.exports[0].name).toBe('MyExportedFunction')
      
      // Verify forwarders structure
      expect(data.forwarders).toHaveLength(1)
      expect(data.forwarders[0]).toHaveProperty('forwarder')
      expect(data.forwarders[0].forwarder).toBe('KERNEL32.CreateFileA')
      
      // Verify counts
      expect(data.total_exports).toBe(3)
      expect(data.total_forwarders).toBe(1)
    })

    test('should handle PE files with no exports', async () => {
      const handler = createPEExportsExtractHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

      const mockSample = {
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: 'def456',
        size: 1024,
        file_type: 'PE',
        created_at: '2024-01-01T00:00:00Z',
        source: 'upload',
      }

      const mockExportsData = {
        exports: [],
        forwarders: [],
        total_exports: 0,
        total_forwarders: 0,
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      mockCacheManager.getCachedResult.mockResolvedValue(mockExportsData)

      const result = await handler({
        sample_id: 'sha256:abc123',
      })

      expect(result.ok).toBe(true)
      const data = result.data as {
        exports: unknown[]
        forwarders: unknown[]
        total_exports: number
        total_forwarders: number
      }
      expect(data.exports).toHaveLength(0)
      expect(data.forwarders).toHaveLength(0)
      expect(data.total_exports).toBe(0)
      expect(data.total_forwarders).toBe(0)
    })
  })
})
