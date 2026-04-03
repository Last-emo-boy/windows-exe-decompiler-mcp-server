/**
 * Unit tests for debug.session.step tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createDebugSessionStepHandler, DebugSessionStepInputSchema } from '../../src/plugins/debug-session/tools/debug-session-step.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'

describe('debug.session.step tool', () => {
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
      const result = DebugSessionStepInputSchema.safeParse({ session_id: 'sess-abc123' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = DebugSessionStepInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = DebugSessionStepInputSchema.safeParse({ session_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createDebugSessionStepHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase } as any)

      const result = await handler({ session_id: 'sess-abc123' })

      expect(result.ok).toBe(false)
    })
  })
})
