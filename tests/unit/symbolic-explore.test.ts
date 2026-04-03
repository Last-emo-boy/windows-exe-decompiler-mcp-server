/**
 * Unit tests for symbolic.explore tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { SymbolicExploreInputSchema } from '../../src/plugins/crackme/tools/symbolic-explore.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { Config } from '../../src/config.js'
import type { PolicyGuard } from '../../src/policy-guard.js'

describe('symbolic.explore tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockPolicyGuard: jest.Mocked<PolicyGuard>
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

    mockPolicyGuard = {
      checkPermission: jest.fn(),
      auditLog: jest.fn(),
    } as unknown as jest.Mocked<PolicyGuard>

    mockConfig = {
      workers: {
        static: { enabled: true, pythonPath: '/usr/bin/python3', dieTimeout: 30, timeout: 60 },
        ghidra: { enabled: false, projectRoot: '/tmp', logRoot: '/tmp', cleanupAfterAnalysis: false, logRetentionDays: 30, minJavaVersion: 21, maxConcurrent: 4, timeout: 300 },
        dotnet: { enabled: false, timeout: 60 },
        sandbox: { enabled: false, angrPythonPath: '/opt/angr-venv/bin/python', timeout: 120 },
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
    test('should accept valid input', () => {
      const result = SymbolicExploreInputSchema.safeParse({
        sample_id: 'sha256:abc123',
        find_addresses: ['0x401234'],
      })
      expect(result.success).toBe(true)
    })

    test('should reject input without find_addresses', () => {
      const result = SymbolicExploreInputSchema.safeParse({ sample_id: 'sha256:abc123' })
      expect(result.success).toBe(false)
    })

    test('should reject empty find_addresses', () => {
      const result = SymbolicExploreInputSchema.safeParse({
        sample_id: 'sha256:abc123',
        find_addresses: [],
      })
      expect(result.success).toBe(false)
    })
  })

  describe('Tool handler', () => {
    test('should return error when sample not found', async () => {
      const { createSymbolicExploreHandler } = await import('../../src/plugins/crackme/tools/symbolic-explore.js')
      const handler = createSymbolicExploreHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, config: mockConfig, policyGuard: mockPolicyGuard } as any)
      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({
        sample_id: 'sha256:nonexistent',
        find_addresses: ['0x401234'],
        avoid_addresses: [],
        input_length: 32,
        timeout_sec: 60,
        stdin_mode: true,
        argv_mode: false,
      })
      expect(result.ok).toBe(false)
      expect(result.errors).toContain('Sample not found: sha256:nonexistent')
    })

    test('should deny when policy guard rejects', async () => {
      const { createSymbolicExploreHandler } = await import('../../src/plugins/crackme/tools/symbolic-explore.js')
      const handler = createSymbolicExploreHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase, config: mockConfig, policyGuard: mockPolicyGuard } as any)

      mockDatabase.findSample.mockReturnValue({ sha256: 'abc123', name: 'test.exe', size: 1024 } as any)
      mockPolicyGuard.checkPermission.mockResolvedValue({ allowed: false, reason: 'Dynamic execution not permitted' })
      mockPolicyGuard.auditLog.mockResolvedValue(undefined)

      const result = await handler({
        sample_id: 'sha256:abc123',
        find_addresses: ['0x401234'],
        avoid_addresses: [],
        input_length: 32,
        timeout_sec: 60,
        stdin_mode: true,
        argv_mode: false,
      })
      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toContain('denied by policy guard')
    })
  })
})
