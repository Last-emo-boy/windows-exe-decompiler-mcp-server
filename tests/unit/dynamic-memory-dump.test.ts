/**
 * Unit tests for dynamic.memory.dump tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createDynamicMemoryDumpHandler, DynamicMemoryDumpInputSchema } from '../../src/plugins/dynamic/tools/dynamic-memory-dump.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { Config } from '../../src/config.js'

describe('dynamic.memory.dump tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockConfig: jest.Mocked<Config>

  beforeEach(() => {
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    mockDatabase = {
      findSample: jest.fn(),
      getDb: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>

    mockConfig = {} as unknown as jest.Mocked<Config>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = DynamicMemoryDumpInputSchema.safeParse({ sample_id: 'sha256:abc123def456' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = DynamicMemoryDumpInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = DynamicMemoryDumpInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createDynamicMemoryDumpHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, config: mockConfig } as any)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })
  })
})
