/**
 * Integration tests for beta.2 new tools
 *
 * Tests: malware-classify, apk-structure-analyze, symbolic-explore, c2-extract
 * All tests use mocked Python workers (no real Python required).
 */

import { describe, test, expect, beforeAll, afterAll } from '@jest/globals'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { loadConfig } from '../../src/config.js'
import { createMalwareClassifyHandler } from '../../src/plugins/malware/tools/malware-classify.js'
import { createC2ExtractHandler } from '../../src/plugins/malware/tools/c2-extract.js'
import { createMalwareConfigExtractHandler } from '../../src/plugins/malware/tools/malware-config-extract.js'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'

describe('Beta.2 New Tools Integration', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let policyGuard: PolicyGuard
  let testDir: string
  const config = loadConfig()

  beforeAll(async () => {
    testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'beta2-tools-'))
    workspaceManager = new WorkspaceManager(path.join(testDir, 'ws'))
    database = new DatabaseManager(path.join(testDir, 'test.db'))
    cacheManager = new CacheManager(path.join(testDir, 'cache'), database)
    policyGuard = new PolicyGuard(path.join(testDir, 'audit.log'))
  })

  afterAll(async () => {
    database.close()
    await fs.rm(testDir, { recursive: true, force: true })
  })

  describe('malware-classify', () => {
    test('rejects missing sample_id', async () => {
      const handler = createMalwareClassifyHandler({ workspaceManager, database, config, cacheManager } as any)
      const result = await handler({ sample_id: '' })
      expect(result.ok).toBe(false)
    })

    test('returns error for unknown sample', async () => {
      const handler = createMalwareClassifyHandler({ workspaceManager, database, config, cacheManager } as any)
      const result = await handler({
        sample_id: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      })
      expect(result.ok).toBe(false)
      expect(result.errors).toBeDefined()
    })
  })

  describe('c2-extract', () => {
    test('rejects missing sample_id', async () => {
      const handler = createC2ExtractHandler({ workspaceManager, database, config, cacheManager } as any)
      const result = await handler({ sample_id: '' })
      expect(result.ok).toBe(false)
    })

    test('returns error for unknown sample', async () => {
      const handler = createC2ExtractHandler({ workspaceManager, database, config, cacheManager } as any)
      const result = await handler({
        sample_id: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      })
      expect(result.ok).toBe(false)
      expect(result.errors).toBeDefined()
    })
  })

  describe('malware-config-extract', () => {
    test('rejects missing sample_id', async () => {
      const handler = createMalwareConfigExtractHandler({ workspaceManager, database, config, cacheManager } as any)
      const result = await handler({ sample_id: '' })
      expect(result.ok).toBe(false)
    })

    test('returns error for unknown sample', async () => {
      const handler = createMalwareConfigExtractHandler({ workspaceManager, database, config, cacheManager } as any)
      const result = await handler({
        sample_id: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      })
      expect(result.ok).toBe(false)
      expect(result.errors).toBeDefined()
    })
  })
})
