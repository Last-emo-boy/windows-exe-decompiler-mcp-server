/**
 * Unit tests for c2.extract tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createC2ExtractHandler, C2ExtractInputSchema } from '../../src/plugins/malware/tools/c2-extract.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'
import type { Config } from '../../src/config.js'

describe('c2.extract tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockCacheManager: jest.Mocked<CacheManager>
  let mockConfig: jest.Mocked<Config>

  beforeEach(() => {
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    mockDatabase = {
      findSample: jest.fn(),
      getDb: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>

    mockCacheManager = {
      getCachedResult: jest.fn(),
      setCachedResult: jest.fn(),
    } as unknown as jest.Mocked<CacheManager>

    mockConfig = {} as unknown as jest.Mocked<Config>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = C2ExtractInputSchema.safeParse({ sample_id: 'sha256:abc123def456' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = C2ExtractInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = C2ExtractInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createC2ExtractHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, cacheManager: mockCacheManager, config: mockConfig } as any)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })
  })
})
