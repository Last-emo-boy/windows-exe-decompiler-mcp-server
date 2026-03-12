/**
 * Unit tests for sample.profile.get tool
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import { DatabaseManager } from '../../src/database.js'
import { createSampleProfileGetHandler } from '../../src/tools/sample-profile-get.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import type { Sample, Analysis } from '../../src/database.js'

describe('sample.profile.get tool', () => {
  let database: DatabaseManager
  let workspaceManager: WorkspaceManager
  let handler: ReturnType<typeof createSampleProfileGetHandler>
  const testDbPath = './test-sample-profile-get.db'
  const testWorkspaceRoot = './test-workspace-sample-profile-get'

  beforeEach(() => {
    // Clean up any existing test database
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }

    // Create fresh database
    database = new DatabaseManager(testDbPath)
    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    handler = createSampleProfileGetHandler(database, workspaceManager)
  })

  afterEach(() => {
    // Clean up
    database.close()
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
  })

  test('should retrieve sample profile with basic information', async () => {
    // Insert a test sample
    const sample: Sample = {
      id: 'sha256:abc123',
      sha256: 'abc123',
      md5: 'def456',
      size: 1024,
      file_type: 'PE',
      created_at: '2024-01-01T00:00:00Z',
      source: 'upload',
    }
    database.insertSample(sample)

    // Call the handler
    const result = await handler({ sample_id: 'sha256:abc123' })

    // Verify result
    expect(result.ok).toBe(true)
    expect(result.data).toBeDefined()
    
    const data = result.data as any
    expect(data.sample).toEqual({
      id: 'sha256:abc123',
      sha256: 'abc123',
      md5: 'def456',
      size: 1024,
      file_type: 'PE',
      created_at: '2024-01-01T00:00:00Z',
      source: 'upload',
    })
    expect(data.analyses).toEqual([])
  })

  test('should retrieve sample profile with completed analyses', async () => {
    // Insert a test sample
    const sample: Sample = {
      id: 'sha256:abc123',
      sha256: 'abc123',
      md5: 'def456',
      size: 1024,
      file_type: 'PE',
      created_at: '2024-01-01T00:00:00Z',
      source: 'upload',
    }
    database.insertSample(sample)

    // Insert test analyses
    const analysis1: Analysis = {
      id: 'analysis-1',
      sample_id: 'sha256:abc123',
      stage: 'pe_fingerprint',
      backend: 'static',
      status: 'done',
      started_at: '2024-01-01T00:01:00Z',
      finished_at: '2024-01-01T00:01:05Z',
      output_json: JSON.stringify({ imphash: 'test123' }),
      metrics_json: JSON.stringify({ elapsed_ms: 5000 }),
    }
    database.insertAnalysis(analysis1)

    const analysis2: Analysis = {
      id: 'analysis-2',
      sample_id: 'sha256:abc123',
      stage: 'strings',
      backend: 'static',
      status: 'done',
      started_at: '2024-01-01T00:02:00Z',
      finished_at: '2024-01-01T00:02:10Z',
      output_json: JSON.stringify({ strings: ['test', 'hello'] }),
      metrics_json: JSON.stringify({ elapsed_ms: 10000 }),
    }
    database.insertAnalysis(analysis2)

    // Call the handler
    const result = await handler({ sample_id: 'sha256:abc123' })

    // Verify result
    expect(result.ok).toBe(true)
    expect(result.data).toBeDefined()
    
    const data = result.data as any
    expect(data.sample.id).toBe('sha256:abc123')
    expect(data.analyses).toHaveLength(2)
    
    // Check first analysis (most recent first)
    expect(data.analyses[0]).toEqual({
      id: 'analysis-2',
      stage: 'strings',
      backend: 'static',
      status: 'done',
      started_at: '2024-01-01T00:02:00Z',
      finished_at: '2024-01-01T00:02:10Z',
      output_json: JSON.stringify({ strings: ['test', 'hello'] }),
      metrics_json: JSON.stringify({ elapsed_ms: 10000 }),
    })

    // Check second analysis
    expect(data.analyses[1]).toEqual({
      id: 'analysis-1',
      stage: 'pe_fingerprint',
      backend: 'static',
      status: 'done',
      started_at: '2024-01-01T00:01:00Z',
      finished_at: '2024-01-01T00:01:05Z',
      output_json: JSON.stringify({ imphash: 'test123' }),
      metrics_json: JSON.stringify({ elapsed_ms: 5000 }),
    })
  })

  test('should return error when sample does not exist', async () => {
    // Call the handler with non-existent sample
    const result = await handler({ sample_id: 'sha256:nonexistent' })

    // Verify error result
    expect(result.ok).toBe(false)
    expect(result.errors).toBeDefined()
    expect(result.errors).toHaveLength(1)
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should handle sample with no file_type', async () => {
    // Insert a test sample without file_type
    const sample: Sample = {
      id: 'sha256:xyz789',
      sha256: 'xyz789',
      md5: 'uvw012',
      size: 2048,
      file_type: null,
      created_at: '2024-01-02T00:00:00Z',
      source: 'manual',
    }
    database.insertSample(sample)

    // Call the handler
    const result = await handler({ sample_id: 'sha256:xyz789' })

    // Verify result
    expect(result.ok).toBe(true)
    expect(result.data).toBeDefined()
    
    const data = result.data as any
    expect(data.sample.file_type).toBeUndefined()
  })

  test('should handle analyses with null optional fields', async () => {
    // Insert a test sample
    const sample: Sample = {
      id: 'sha256:test123',
      sha256: 'test123',
      md5: 'test456',
      size: 512,
      file_type: 'PE',
      created_at: '2024-01-03T00:00:00Z',
      source: 'upload',
    }
    database.insertSample(sample)

    // Insert analysis with null optional fields
    const analysis: Analysis = {
      id: 'analysis-3',
      sample_id: 'sha256:test123',
      stage: 'ghidra',
      backend: 'ghidra',
      status: 'queued',
      started_at: null,
      finished_at: null,
      output_json: null,
      metrics_json: null,
    }
    database.insertAnalysis(analysis)

    // Call the handler
    const result = await handler({ sample_id: 'sha256:test123' })

    // Verify result
    expect(result.ok).toBe(true)
    expect(result.data).toBeDefined()
    
    const data = result.data as any
    expect(data.analyses).toHaveLength(1)
    expect(data.analyses[0]).toEqual({
      id: 'analysis-3',
      stage: 'ghidra',
      backend: 'ghidra',
      status: 'queued',
      started_at: undefined,
      finished_at: undefined,
      output_json: undefined,
      metrics_json: undefined,
    })
  })

  test('should retrieve multiple analyses in correct order', async () => {
    // Insert a test sample
    const sample: Sample = {
      id: 'sha256:multi123',
      sha256: 'multi123',
      md5: 'multi456',
      size: 4096,
      file_type: 'PE',
      created_at: '2024-01-04T00:00:00Z',
      source: 'upload',
    }
    database.insertSample(sample)

    // Insert multiple analyses
    for (let i = 1; i <= 5; i++) {
      const analysis: Analysis = {
        id: `analysis-${i}`,
        sample_id: 'sha256:multi123',
        stage: `stage-${i}`,
        backend: 'static',
        status: 'done',
        started_at: `2024-01-04T00:0${i}:00Z`,
        finished_at: `2024-01-04T00:0${i}:30Z`,
        output_json: JSON.stringify({ stage: i }),
        metrics_json: JSON.stringify({ elapsed_ms: 30000 }),
      }
      database.insertAnalysis(analysis)
    }

    // Call the handler
    const result = await handler({ sample_id: 'sha256:multi123' })

    // Verify result
    expect(result.ok).toBe(true)
    expect(result.data).toBeDefined()
    
    const data = result.data as any
    expect(data.analyses).toHaveLength(5)
    
    // Verify all analyses are present
    for (let i = 1; i <= 5; i++) {
      const analysis = data.analyses.find((a: any) => a.id === `analysis-${i}`)
      expect(analysis).toBeDefined()
      expect(analysis?.stage).toBe(`stage-${i}`)
    }
  })

  test('should reap stale running analyses before returning profile data', async () => {
    const sample: Sample = {
      id: 'sha256:stale123',
      sha256: 'stale123',
      md5: 'stale456',
      size: 512,
      file_type: 'PE',
      created_at: '2024-01-05T00:00:00Z',
      source: 'upload',
    }
    database.insertSample(sample)

    database.insertAnalysis({
      id: 'analysis-stale',
      sample_id: sample.id,
      stage: 'ghidra',
      backend: 'ghidra',
      status: 'running',
      started_at: '2024-01-01T00:00:00Z',
      finished_at: null,
      output_json: JSON.stringify({ project_key: 'demo' }),
      metrics_json: JSON.stringify({}),
    })

    const result = await handler({
      sample_id: sample.id,
      stale_running_ms: 1000,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.analyses).toHaveLength(1)
    expect(data.analyses[0].status).toBe('failed')
    expect(data.analyses[0].finished_at).toBeDefined()
    expect(data.analyses[0].output_json).toContain('"stale_reaped":true')
  })

  test('should not auto-reap running analyses when stale_running_ms is omitted', async () => {
    const sample: Sample = {
      id: 'sha256:noautostale',
      sha256: 'noautostale',
      md5: 'noautostale-md5',
      size: 512,
      file_type: 'PE',
      created_at: '2024-01-05T00:00:00Z',
      source: 'upload',
    }
    database.insertSample(sample)

    database.insertAnalysis({
      id: 'analysis-running',
      sample_id: sample.id,
      stage: 'ghidra',
      backend: 'ghidra',
      status: 'running',
      started_at: '2024-01-01T00:00:00Z',
      finished_at: null,
      output_json: JSON.stringify({ project_key: 'demo' }),
      metrics_json: JSON.stringify({}),
    })

    const result = await handler({
      sample_id: sample.id,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.analyses).toHaveLength(1)
    expect(data.analyses[0].status).toBe('running')
    expect(data.analyses[0].finished_at).toBeUndefined()
  })

  test('should report workspace/original integrity when the original sample file is missing', async () => {
    const hash = '7'.repeat(64)
    const sample: Sample = {
      id: `sha256:${hash}`,
      sha256: hash,
      md5: '7'.repeat(32),
      size: 512,
      file_type: 'PE',
      created_at: '2024-01-06T00:00:00Z',
      source: 'upload',
    }
    database.insertSample(sample)

    const workspace = await workspaceManager.createWorkspace(sample.id)
    expect(fs.existsSync(workspace.original)).toBe(true)
    expect(fs.readdirSync(workspace.original)).toHaveLength(0)

    const result = await handler({ sample_id: sample.id })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.workspace.status).toBe('original_file_missing')
    expect(data.workspace.original_present).toBe(false)
    expect(data.workspace.original_file_count).toBe(0)
    expect(data.workspace.remediation.some((item: string) => item.includes('sample.ingest'))).toBe(true)
  })
})
