/**
 * Unit tests for task.cancel tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createTaskCancelHandler, taskCancelInputSchema } from '../../src/tools/task-cancel.js'
import type { JobQueue } from '../../src/job-queue.js'

describe('task.cancel tool', () => {
  let mockJobQueue: jest.Mocked<JobQueue>

  beforeEach(() => {
    mockJobQueue = {
      enqueue: jest.fn(),
      getStatus: jest.fn(),
    } as unknown as jest.Mocked<JobQueue>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = taskCancelInputSchema.safeParse({ sample_id: 'sha256:abc123def456' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = taskCancelInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = taskCancelInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createTaskCancelHandler(mockJobQueue)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })
  })
})
