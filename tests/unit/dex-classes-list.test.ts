/**
 * Unit tests for dex.classes.list tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createDexClassesListHandler, DexClassesListInputSchema } from '../../src/plugins/android/tools/dex-classes-list.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { Config } from '../../src/config.js'

describe('dex.classes.list tool', () => {
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
      const result = DexClassesListInputSchema.safeParse({ sample_id: 'sha256:abc123def456' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = DexClassesListInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = DexClassesListInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createDexClassesListHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, config: mockConfig } as any)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })
  })
})
