/**
 * Unit tests for apk.structure.analyze tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { ApkStructureAnalyzeInputSchema } from '../../src/plugins/android/tools/apk-structure-analyze.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { Config } from '../../src/config.js'

describe('apk.structure.analyze tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockConfig: Config

  beforeEach(() => {
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
      createWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    mockDatabase = {
      findSample: jest.fn(),
      findAnalysisEvidenceBySample: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>

    mockConfig = {
      workers: {
        static: { enabled: true, pythonPath: '/usr/bin/python3', dieTimeout: 30, timeout: 60 },
        ghidra: { enabled: false, projectRoot: '/tmp', logRoot: '/tmp', cleanupAfterAnalysis: false, logRetentionDays: 30, minJavaVersion: 21, maxConcurrent: 4, timeout: 300 },
        dotnet: { enabled: false, timeout: 60 },
        sandbox: { enabled: false, timeout: 120 },
        frida: { enabled: false, timeout: 30 },
      },
      server: { port: 3000, host: 'localhost' },
      database: { type: 'sqlite', path: '/tmp/db.sqlite' },
      workspace: { root: '/tmp/workspaces', maxSampleSize: 500 * 1024 * 1024 },
      cache: { enabled: true, root: '/tmp/cache', ttl: 2592000 },
      logging: { level: 'info', pretty: false, auditPath: '/tmp/audit.log' },
      api: { enabled: true, port: 18080, maxFileSize: 500 * 1024 * 1024, storageRoot: '/tmp/storage', retentionDays: 30 },
    } as Config
  })

  describe('Input validation', () => {
    test('should accept valid input with sample_id', () => {
      const result = ApkStructureAnalyzeInputSchema.safeParse({ sample_id: 'sha256:abc123' })
      expect(result.success).toBe(true)
    })

    test('should reject input without sample_id', () => {
      const result = ApkStructureAnalyzeInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })
  })

  describe('Tool handler (sample not found)', () => {
    test('should return error when sample not found', async () => {
      const { createApkStructureAnalyzeHandler } = await import('../../src/plugins/android/tools/apk-structure-analyze.js')
      const handler = createApkStructureAnalyzeHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, config: mockConfig } as any)
      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ sample_id: 'sha256:nonexistent' })
      expect(result.ok).toBe(false)
      expect(result.errors).toBeDefined()
    })
  })
})
