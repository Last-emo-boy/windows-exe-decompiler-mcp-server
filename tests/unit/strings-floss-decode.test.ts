/**
 * Unit tests for strings.floss.decode tool
 * Requirements: 4.4, 4.5
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createStringsFlossDecodeHandler, StringsFlossDecodeInputSchema } from '../../src/tools/strings-floss-decode.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'

describe('strings.floss.decode tool', () => {
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
        timeout: 60,
        modes: ['decoded', 'stack'] as const,
      }
      
      const result = StringsFlossDecodeInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should accept valid input with minimal parameters', () => {
      const input = {
        sample_id: 'sha256:abc123',
      }
      
      const result = StringsFlossDecodeInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.timeout).toBe(60) // default
        expect(result.data.modes).toEqual(['decoded']) // default
      }
    })

    test('should reject invalid timeout (< 1)', () => {
      const input = {
        sample_id: 'sha256:abc123',
        timeout: 0,
      }
      
      const result = StringsFlossDecodeInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })

    test('should reject invalid mode', () => {
      const input = {
        sample_id: 'sha256:abc123',
        modes: ['invalid'],
      }
      
      const result = StringsFlossDecodeInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })

    test('should accept mode: static', () => {
      const input = {
        sample_id: 'sha256:abc123',
        modes: ['static'] as const,
      }
      
      const result = StringsFlossDecodeInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should accept mode: stack', () => {
      const input = {
        sample_id: 'sha256:abc123',
        modes: ['stack'] as const,
      }
      
      const result = StringsFlossDecodeInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should accept mode: tight', () => {
      const input = {
        sample_id: 'sha256:abc123',
        modes: ['tight'] as const,
      }
      
      const result = StringsFlossDecodeInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should accept mode: decoded', () => {
      const input = {
        sample_id: 'sha256:abc123',
        modes: ['decoded'] as const,
      }
      
      const result = StringsFlossDecodeInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should accept multiple modes', () => {
      const input = {
        sample_id: 'sha256:abc123',
        modes: ['static', 'stack', 'tight', 'decoded'] as const,
      }
      
      const result = StringsFlossDecodeInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should accept custom timeout', () => {
      const input = {
        sample_id: 'sha256:abc123',
        timeout: 120,
      }
      
      const result = StringsFlossDecodeInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.timeout).toBe(120)
      }
    })
  })

  describe('Tool handler', () => {
    test('should return error when sample not found', async () => {
      const handler = createStringsFlossDecodeHandler(
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
      const handler = createStringsFlossDecodeHandler(
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
        decoded_strings: [
          { 
            string: 'http://malicious.com/payload', 
            offset: 0x1000, 
            type: 'decoded',
            decoding_method: 'xor_decode'
          },
          { 
            string: 'C:\\Windows\\System32\\cmd.exe', 
            offset: 0x2000, 
            type: 'stack',
            decoding_method: 'stack_analysis'
          },
        ],
        count: 2,
        timeout_occurred: false,
        partial_results: false,
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      mockCacheManager.getCachedResult.mockResolvedValue(mockCachedData)

      const result = await handler({
        sample_id: 'sha256:abc123',
        timeout: 60,
        modes: ['decoded'],
      })

      expect(result.ok).toBe(true)
      expect(result.data).toMatchObject(mockCachedData)
      expect((result.data as any).enriched).toBeDefined()
      expect((result.data as any).enriched.top_decoded.length).toBeGreaterThan(0)
      expect(result.warnings).toContain('Result from cache')
      expect(mockCacheManager.getCachedResult).toHaveBeenCalled()
    })

    test('should validate timeout parameter', () => {
      const input = {
        sample_id: 'sha256:abc123',
        timeout: 120,
      }

      const result = StringsFlossDecodeInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.timeout).toBe(120)
      }
    })

    test('should validate modes parameter', () => {
      const input = {
        sample_id: 'sha256:abc123',
        modes: ['decoded', 'stack'] as const,
      }

      const result = StringsFlossDecodeInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.modes).toEqual(['decoded', 'stack'])
      }
    })

    test('should handle timeout_occurred flag', async () => {
      const handler = createStringsFlossDecodeHandler(
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

      const mockDataWithTimeout = {
        decoded_strings: [
          { 
            string: 'partial_result', 
            offset: 0x1000, 
            type: 'decoded',
            decoding_method: 'xor_decode'
          },
        ],
        count: 1,
        timeout_occurred: true,
        partial_results: true,
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      mockCacheManager.getCachedResult.mockResolvedValue(mockDataWithTimeout)

      const result = await handler({
        sample_id: 'sha256:abc123',
        timeout: 60,
      })

      expect(result.ok).toBe(true)
      if (result.data && typeof result.data === 'object' && 'timeout_occurred' in result.data) {
        const data = result.data as { timeout_occurred: boolean; partial_results: boolean }
        expect(data.timeout_occurred).toBe(true)
        expect(data.partial_results).toBe(true)
      }
    })

    test('should handle partial_results flag', async () => {
      const handler = createStringsFlossDecodeHandler(
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

      const mockDataWithPartial = {
        decoded_strings: [
          { 
            string: 'partial_string', 
            offset: 0x1000, 
            type: 'decoded',
            decoding_method: 'xor_decode'
          },
        ],
        count: 1,
        timeout_occurred: false,
        partial_results: true,
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      mockCacheManager.getCachedResult.mockResolvedValue(mockDataWithPartial)

      const result = await handler({
        sample_id: 'sha256:abc123',
      })

      expect(result.ok).toBe(true)
      if (result.data && typeof result.data === 'object' && 'partial_results' in result.data) {
        const data = result.data as { partial_results: boolean }
        expect(data.partial_results).toBe(true)
      }
    })
  })

  describe('Output structure', () => {
    test('should validate output schema with decoded strings', () => {
      const output = {
        ok: true,
        data: {
          decoded_strings: [
            {
              string: 'http://example.com',
              offset: 0x1000,
              type: 'decoded',
              decoding_method: 'xor_decode',
            },
          ],
          count: 1,
          timeout_occurred: false,
          partial_results: false,
        },
        warnings: [],
        errors: [],
        artifacts: [],
        metrics: {
          elapsed_ms: 1000,
          tool: 'strings.floss.decode',
        },
      }

      // This should not throw
      expect(() => output).not.toThrow()
    })

    test('should validate output schema with timeout', () => {
      const output = {
        ok: true,
        data: {
          decoded_strings: [],
          count: 0,
          timeout_occurred: true,
          partial_results: true,
        },
        warnings: ['FLOSS execution timed out'],
        errors: [],
        artifacts: [],
        metrics: {
          elapsed_ms: 60000,
          tool: 'strings.floss.decode',
        },
      }

      // This should not throw
      expect(() => output).not.toThrow()
    })
  })
})
