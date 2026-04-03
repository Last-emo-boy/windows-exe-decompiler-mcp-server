/**
 * Unit tests for debug.session.continue tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createDebugSessionContinueHandler, DebugSessionContinueInputSchema } from '../../src/plugins/debug-session/tools/debug-session-continue.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'

describe('debug.session.continue tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>

  beforeEach(() => {
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    mockDatabase = {
      findSample: jest.fn(),
      getDb: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = DebugSessionContinueInputSchema.safeParse({ session_id: 'sess-abc123' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = DebugSessionContinueInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = DebugSessionContinueInputSchema.safeParse({ session_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createDebugSessionContinueHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase } as any)

      const result = await handler({ session_id: 'sess-abc123' })

      expect(result.ok).toBe(false)
    })
  })
})
