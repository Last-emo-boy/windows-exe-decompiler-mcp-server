/**
 * Unit tests for task.status tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createTaskStatusHandler, taskStatusInputSchema } from '../../src/tools/task-status.js'
import type { DatabaseManager } from '../../src/database.js'
import type { JobQueue } from '../../src/job-queue.js'

describe('task.status tool', () => {
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockJobQueue: jest.Mocked<JobQueue>

  beforeEach(() => {
    mockDatabase = {
      findSample: jest.fn(),
      getDb: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>

    mockJobQueue = {
      enqueue: jest.fn(),
      getStatus: jest.fn(),
    } as unknown as jest.Mocked<JobQueue>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = taskStatusInputSchema.safeParse({ sample_id: 'sha256:abc123def456' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = taskStatusInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = taskStatusInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createTaskStatusHandler(mockDatabase, mockJobQueue)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })
  })
})
