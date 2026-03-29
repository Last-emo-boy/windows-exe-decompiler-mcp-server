/**
 * Unit tests for strings.extract tool
 * Requirements: 4.1, 4.2, 4.3
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createStringsExtractHandler, StringsExtractInputSchema } from '../../src/tools/strings-extract.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'

describe('strings.extract tool', () => {
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
    test('should accept valid input with all parameters', () => {
      const input = {
        sample_id: 'sha256:abc123',
        min_len: 4,
        encoding: 'all' as const,
        max_strings: 300,
        max_string_length: 256,
        category_filter: 'ioc' as const,
      }
      
      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should accept valid input with minimal parameters', () => {
      const input = {
        sample_id: 'sha256:abc123',
      }
      
      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.min_len).toBe(4) // default
        expect(result.data.encoding).toBe('all') // default
        expect(result.data.max_strings).toBe(500)
        expect(result.data.max_string_length).toBe(512)
        expect(result.data.category_filter).toBe('all')
      }
    })

    test('should reject invalid min_len (< 1)', () => {
      const input = {
        sample_id: 'sha256:abc123',
        min_len: 0,
      }
      
      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })

    test('should reject invalid encoding', () => {
      const input = {
        sample_id: 'sha256:abc123',
        encoding: 'invalid',
      }
      
      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })

    test('should accept encoding: ascii', () => {
      const input = {
        sample_id: 'sha256:abc123',
        encoding: 'ascii' as const,
      }
      
      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should accept encoding: unicode', () => {
      const input = {
        sample_id: 'sha256:abc123',
        encoding: 'unicode' as const,
      }
      
      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should reject invalid max_string_length', () => {
      const input = {
        sample_id: 'sha256:abc123',
        max_string_length: 8,
      }

      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })

    test('should reject invalid category_filter', () => {
      const input = {
        sample_id: 'sha256:abc123',
        category_filter: 'malware',
      }

      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })
  })

  describe('Tool handler', () => {
    test('should return error when sample not found', async () => {
      const handler = createStringsExtractHandler(
        mockWorkspaceManager,
        mockDatabase,
        mockCacheManager
      )

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({
        sample_id: 'sha256:nonexistent',
      })

      expect(result.ok).toBe(false)
      expect(result.errors).toContain('Sample not found: sha256:nonexistent')
    })

    test('should return cached result when available', async () => {
      const handler = createStringsExtractHandler(
        mockWorkspaceManager,
        mockDatabase,
        mockCacheManager
      )

      const mockSample = {
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: 'def456',
        size: 1024,
        file_type: 'PE32',
        created_at: '2024-01-01T00:00:00Z',
        source: 'test',
      }

      const mockCachedData = {
        strings: [
          { offset: 0, string: 'Hello World', encoding: 'ascii' },
          { offset: 20, string: 'Test String', encoding: 'ascii' },
        ],
        count: 2,
        min_len: 4,
        encoding_filter: 'all',
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      mockCacheManager.getCachedResult.mockResolvedValue(mockCachedData)

      const result = await handler({
        sample_id: 'sha256:abc123',
        min_len: 4,
        encoding: 'all',
      })

      expect(result.ok).toBe(true)
      expect(result.data).toMatchObject(mockCachedData)
      expect((result.data as any).enriched).toBeDefined()
      expect((result.data as any).enriched.top_iocs.length).toBeGreaterThanOrEqual(0)
      expect(result.warnings).toContain('Result from cache')
      expect(mockCacheManager.getCachedResult).toHaveBeenCalled()
    })

    test('should validate min_len parameter', () => {
      const input = {
        sample_id: 'sha256:abc123',
        min_len: 10,
        encoding: 'all' as const,
      }

      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.min_len).toBe(10)
      }
    })

    test('should validate encoding parameter', () => {
      const input = {
        sample_id: 'sha256:abc123',
        min_len: 4,
        encoding: 'ascii' as const,
      }

      const result = StringsExtractInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.encoding).toBe('ascii')
      }
    })
  })
})
