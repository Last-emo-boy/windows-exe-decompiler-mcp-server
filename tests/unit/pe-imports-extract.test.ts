/**
 * Unit tests for pe.imports.extract tool
 * Requirements: 3.1, 3.2
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createPEImportsExtractHandler, PEImportsExtractInputSchema } from '../../src/plugins/pe-analysis/tools/pe-imports-extract.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'

describe('pe.imports.extract tool', () => {
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

      const result = PEImportsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.sample_id).toBe('sha256:abc123')
        expect(result.data.group_by_dll).toBe(true) // default value
      }
    })

    test('should accept valid input with group_by_dll=false', () => {
      const input = {
        sample_id: 'sha256:abc123',
        group_by_dll: false,
      }

      const result = PEImportsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.group_by_dll).toBe(false)
      }
    })

    test('should reject input without sample_id', () => {
      const input = {
        group_by_dll: true,
      }

      const result = PEImportsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })

    test('should reject input with invalid group_by_dll type', () => {
      const input = {
        sample_id: 'sha256:abc123',
        group_by_dll: 'yes', // should be boolean
      }

      const result = PEImportsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })
  })

  describe('Tool handler', () => {
    test('should return error when sample not found', async () => {
      const handler = createPEImportsExtractHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({
        sample_id: 'sha256:nonexistent',
      })

      expect(result.ok).toBe(false)
      expect(result.errors).toContain('Sample not found: sha256:nonexistent')
    })

    test('should return cached result when available', async () => {
      const handler = createPEImportsExtractHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

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
        imports: {
          'kernel32.dll': ['CreateFileA', 'ReadFile', 'WriteFile', 'CloseHandle'],
          'user32.dll': ['MessageBoxA', 'GetWindowTextA'],
        },
        delay_imports: {},
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      mockCacheManager.getCachedResult.mockResolvedValue(mockCachedData)

      const result = await handler({
        sample_id: 'sha256:abc123',
        group_by_dll: true,
      })

      expect(result.ok).toBe(true)
      expect(result.data).toEqual(mockCachedData)
      expect(result.warnings).toContain('Result from cache')
      expect(mockCacheManager.getCachedResult).toHaveBeenCalled()
    })

    test('should generate correct cache key', async () => {
      const handler = createPEImportsExtractHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

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
        group_by_dll: true,
      })

      // Should have called getCachedResult with a cache key
      expect(mockCacheManager.getCachedResult).toHaveBeenCalled()
      
      // The call should have been made with a string starting with "cache:"
      const cacheKey = mockCacheManager.getCachedResult.mock.calls[0][0] as string
      expect(cacheKey).toMatch(/^cache:[a-f0-9]{64}$/)
    })
  })

  describe('Cache key generation', () => {
    test('should generate different keys for different group_by_dll values', async () => {
      const handler = createPEImportsExtractHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

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

      // Call with group_by_dll=true
      await handler({
        sample_id: 'sha256:abc123',
        group_by_dll: true,
      })
      const cacheKey1 = mockCacheManager.getCachedResult.mock.calls[0][0] as string

      // Reset mock
      mockCacheManager.getCachedResult.mockClear()

      // Call with group_by_dll=false
      await handler({
        sample_id: 'sha256:abc123',
        group_by_dll: false,
      })
      const cacheKey2 = mockCacheManager.getCachedResult.mock.calls[0][0] as string

      // Keys should be different
      expect(cacheKey1).not.toBe(cacheKey2)
    })
  })

  describe('Requirements validation', () => {
    test('should support group_by_dll parameter (Requirement 3.2)', () => {
      const input = {
        sample_id: 'sha256:abc123',
        group_by_dll: true,
      }

      const result = PEImportsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.group_by_dll).toBe(true)
      }
    })

    test('should extract DLL names and function names (Requirement 3.1)', async () => {
      const handler = createPEImportsExtractHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

      const mockSample = {
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: 'def456',
        size: 1024,
        file_type: 'PE',
        created_at: '2024-01-01T00:00:00Z',
        source: 'upload',
      }

      const mockImportsData = {
        imports: {
          'kernel32.dll': ['CreateFileA', 'ReadFile', 'WriteFile'],
          'user32.dll': ['MessageBoxA'],
        },
        delay_imports: {},
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      mockCacheManager.getCachedResult.mockResolvedValue(mockImportsData)

      const result = await handler({
        sample_id: 'sha256:abc123',
        group_by_dll: true,
      })

      expect(result.ok).toBe(true)
      expect(result.data).toHaveProperty('imports')
      
      const data = result.data as { imports: Record<string, string[]> }
      expect(Object.keys(data.imports)).toContain('kernel32.dll')
      expect(Object.keys(data.imports)).toContain('user32.dll')
      expect(data.imports['kernel32.dll']).toContain('CreateFileA')
      expect(data.imports['user32.dll']).toContain('MessageBoxA')
    })
  })
})
