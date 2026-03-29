import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { JobQueue } from '../../src/job-queue.js'
import {
  createDeepStaticWorkflowHandler,
  deepStaticWorkflowInputSchema,
} from '../../src/workflows/deep-static.js'

describe('workflow.deep_static tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-deep-static')
    testDbPath = path.join(process.cwd(), 'test-deep-static.db')
    testCachePath = path.join(process.cwd(), 'test-cache-deep-static')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
    cacheManager = new CacheManager(testCachePath, database)
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore
    }

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }
  })

  test('should accept optional deep static options', () => {
    const parsed = deepStaticWorkflowInputSchema.parse({
      sample_id: 'sha256:' + 'a'.repeat(64),
      options: {
        top_functions: 5,
        ghidra_timeout: 900,
        include_cfg: true,
      },
    })

    expect(parsed.options?.top_functions).toBe(5)
    expect(parsed.options?.ghidra_timeout).toBe(900)
    expect(parsed.options?.include_cfg).toBe(true)
  })

  test('should return an error when sample does not exist', async () => {
    const handler = createDeepStaticWorkflowHandler(workspaceManager, database, cacheManager)
    const result = await handler({
      sample_id: 'sha256:' + 'f'.repeat(64),
    })

    expect(result.isError).toBe(true)
    const text = result.content.find((item) => item.type === 'text')?.text
    expect(text).toContain('Sample not found')
  })

  test('should enqueue deep static workflow as async job when queue is provided', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'b'.repeat(64),
      md5: 'c'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const queue = new JobQueue()
    const handler = createDeepStaticWorkflowHandler(workspaceManager, database, cacheManager, queue)
    const result = await handler({
      sample_id: sampleId,
      options: {
        ghidra_timeout: 900,
      },
    })

    expect(result.isError).toBeUndefined()
    const payload = JSON.parse(result.content.find((item) => item.type === 'text')?.text || '{}')
    expect(payload.ok).toBe(true)
    expect(payload.data.status).toBe('queued')
    expect(payload.data.tool).toBe('workflow.deep_static')
    expect(payload.data.job_id).toBeTruthy()
    expect(payload.data.result_mode).toBe('queued')
    expect(payload.data.next_actions[0]).toContain('recommended polling interval')
    expect(queue.getStatus(payload.data.job_id)?.status).toBe('queued')
    expect((result as any).structuredContent.data.result_mode).toBe('queued')
  })
})
