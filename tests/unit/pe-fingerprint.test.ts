/**
 * Unit tests for pe.fingerprint tool
 * Requirements: 2.1, 2.2, 2.3, 2.5
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createPEFingerprintHandler, PEFingerprintInputSchema } from '../../src/plugins/pe-analysis/tools/pe-fingerprint.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'

describe('pe.fingerprint tool', () => {
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

      const result = PEFingerprintInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.sample_id).toBe('sha256:abc123')
        expect(result.data.fast).toBe(false) // default value
      }
    })

    test('should accept valid input with fast=true', () => {
      const input = {
        sample_id: 'sha256:abc123',
        fast: true,
      }

      const result = PEFingerprintInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.fast).toBe(true)
      }
    })

    test('should reject input without sample_id', () => {
      const input = {
        fast: true,
      }

      const result = PEFingerprintInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })

    test('should reject input with invalid fast type', () => {
      const input = {
        sample_id: 'sha256:abc123',
        fast: 'yes', // should be boolean
      }

      const result = PEFingerprintInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })
  })

  describe('Tool handler', () => {
    test('should return error when sample not found', async () => {
      const handler = createPEFingerprintHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({
        sample_id: 'sha256:nonexistent',
      })

      expect(result.ok).toBe(false)
      expect(result.errors).toContain('Sample not found: sha256:nonexistent')
    })

    test('should return cached result when available', async () => {
      const handler = createPEFingerprintHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

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
        machine: 332,
        machine_name: 'IMAGE_FILE_MACHINE_I386',
        subsystem: 3,
        subsystem_name: 'IMAGE_SUBSYSTEM_WINDOWS_CUI',
        timestamp: 1234567890,
        timestamp_iso: '2009-02-13T23:31:30.000Z',
        imphash: 'abc123def456',
        entry_point: 4096,
        image_base: 4194304,
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      mockCacheManager.getCachedResult.mockResolvedValue(mockCachedData)

      const result = await handler({
        sample_id: 'sha256:abc123',
        fast: true,
      })

      expect(result.ok).toBe(true)
      expect(result.data).toEqual(mockCachedData)
      expect(result.warnings).toContain('Result from cache')
      expect(mockCacheManager.getCachedResult).toHaveBeenCalled()
    })

    test('should generate correct cache key', async () => {
      const handler = createPEFingerprintHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

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
        fast: true,
      })

      // Should have called getCachedResult with a cache key
      expect(mockCacheManager.getCachedResult).toHaveBeenCalled()
      
      // The call should have been made with a string starting with "cache:"
      const cacheKey = mockCacheManager.getCachedResult.mock.calls[0][0] as string
      expect(cacheKey).toMatch(/^cache:[a-f0-9]{64}$/)
    })
  })

  describe('Cache key generation', () => {
    test('should generate different keys for different fast values', async () => {
      const handler = createPEFingerprintHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager } as any)

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

      // Call with fast=true
      await handler({
        sample_id: 'sha256:abc123',
        fast: true,
      })
      const cacheKey1 = mockCacheManager.getCachedResult.mock.calls[0][0] as string

      // Reset mock
      mockCacheManager.getCachedResult.mockClear()

      // Call with fast=false
      await handler({
        sample_id: 'sha256:abc123',
        fast: false,
      })
      const cacheKey2 = mockCacheManager.getCachedResult.mock.calls[0][0] as string

      // Keys should be different
      expect(cacheKey1).not.toBe(cacheKey2)
    })
  })
})
