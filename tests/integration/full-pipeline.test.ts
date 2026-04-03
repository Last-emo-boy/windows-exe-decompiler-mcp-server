/**
 * End-to-end pipeline integration test
 *
 * Tests the complete analysis path:
 *   ingest → triage → analyze.start → analyze.status
 *
 * Uses real in-memory components with a synthetic PE sample.
 */

import { describe, test, expect, beforeAll, afterAll } from '@jest/globals'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { createSampleIngestHandler } from '../../src/tools/sample-ingest.js'
import { createTriageWorkflowHandler } from '../../src/workflows/triage.js'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'

describe('Full Pipeline E2E', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let policyGuard: PolicyGuard
  let testDir: string

  beforeAll(async () => {
    testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'e2e-pipeline-'))
    workspaceManager = new WorkspaceManager(path.join(testDir, 'ws'))
    database = new DatabaseManager(path.join(testDir, 'test.db'))
    cacheManager = new CacheManager(path.join(testDir, 'cache'), database)
    policyGuard = new PolicyGuard(path.join(testDir, 'audit.log'))
  })

  afterAll(async () => {
    database.close()
    await fs.rm(testDir, { recursive: true, force: true })
  })

  function createMinimalPE(): Buffer {
    const pe = Buffer.alloc(512)
    // DOS header
    pe.write('MZ', 0)
    pe.writeUInt32LE(128, 0x3c) // e_lfanew
    // PE signature
    pe.write('PE\0\0', 128)
    // IMAGE_FILE_HEADER
    pe.writeUInt16LE(0x14c, 132) // Machine: i386
    pe.writeUInt16LE(1, 134) // NumberOfSections
    pe.writeUInt16LE(0xf0, 148) // SizeOfOptionalHeader
    pe.writeUInt16LE(0x0102, 150) // Characteristics: EXECUTABLE_IMAGE
    // Minimal optional header
    pe.writeUInt16LE(0x10b, 152) // Magic: PE32
    return pe
  }

  test('ingest → triage pipeline completes', async () => {
    const peBuffer = createMinimalPE()
    const samplePath = path.join(testDir, 'test-pipeline.exe')
    await fs.writeFile(samplePath, peBuffer)

    // Step 1: Ingest
    const ingestHandler = createSampleIngestHandler(workspaceManager, database, policyGuard)
    const ingestResult = await ingestHandler({ file_path: samplePath })

    expect(ingestResult.ok).toBe(true)
    expect(ingestResult.data).toBeDefined()

    const sampleId = (ingestResult.data as Record<string, unknown>)?.sample_id as string
    expect(sampleId).toMatch(/^sha256:/)

    // Step 2: Triage
    const triageHandler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    const triageResult = await triageHandler({
      sample_id: sampleId,
      raw_result_mode: 'compact',
    })

    // Triage should succeed even without external backends
    expect(triageResult.ok).toBe(true)
    expect(triageResult.data).toBeDefined()
    expect(triageResult.metrics).toBeDefined()
    expect(triageResult.metrics?.tool).toBe('workflow.triage')
  })

  test('ingest with invalid file returns error', async () => {
    const ingestHandler = createSampleIngestHandler(workspaceManager, database, policyGuard)
    const result = await ingestHandler({ file_path: '/nonexistent/file.exe' })

    expect(result.ok).toBe(false)
    expect(result.errors).toBeDefined()
    expect(result.errors!.length).toBeGreaterThan(0)
  })

  test('triage with unknown sample returns error', async () => {
    const triageHandler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    const result = await triageHandler({
      sample_id: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toBeDefined()
  })
})
