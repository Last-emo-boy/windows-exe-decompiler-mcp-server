/**
 * Unit tests for frida.runtime.instrument tool
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import * as fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  createFridaRuntimeInstrumentHandler,
  FridaRuntimeInstrumentInputSchema,
} from '../../src/tools/frida-runtime-instrument.js'

describe('FridaRuntimeInstrumentInputSchema', () => {
  test('should accept valid input with all fields', () => {
    const input = {
      sample_id: 'sha256:' + 'a'.repeat(64),
      mode: 'spawn' as const,
      pid: 1234,
      script_name: 'api_trace' as const,
      script_content: 'console.log("test");',
      script_parameters: { modules: ['kernel32.dll'] },
      timeout_sec: 60,
      persist_artifact: true,
      register_analysis: true,
    }

    const result = FridaRuntimeInstrumentInputSchema.parse(input)
    expect(result.sample_id).toBe(input.sample_id)
    expect(result.mode).toBe('spawn')
    expect(result.script_name).toBe('api_trace')
  })

  test('should accept minimal input with defaults', () => {
    const input = { sample_id: 'sha256:' + 'a'.repeat(64) }
    const result = FridaRuntimeInstrumentInputSchema.parse(input)
    expect(result.mode).toBe('spawn')
    expect(result.script_name).toBe('api_trace')
    expect(result.timeout_sec).toBe(30)
    expect(result.persist_artifact).toBe(true)
    expect(result.register_analysis).toBe(true)
  })

  test('should reject invalid mode', () => {
    const input = { sample_id: 'sha256:' + 'a'.repeat(64), mode: 'invalid' }
    expect(() => FridaRuntimeInstrumentInputSchema.parse(input)).toThrow()
  })

  test('should reject timeout out of range', () => {
    const input1 = { sample_id: 'sha256:' + 'a'.repeat(64), timeout_sec: 3 }
    expect(() => FridaRuntimeInstrumentInputSchema.parse(input1)).toThrow()

    const input2 = { sample_id: 'sha256:' + 'a'.repeat(64), timeout_sec: 301 }
    expect(() => FridaRuntimeInstrumentInputSchema.parse(input2)).toThrow()
  })

  test('should accept all valid script names', () => {
    const validScripts = ['api_trace', 'string_decoder', 'anti_debug_bypass', 'crypto_finder', 'file_registry_monitor', 'default']

    validScripts.forEach((scriptName) => {
      const input = { sample_id: 'sha256:' + 'a'.repeat(64), script_name: scriptName }
      const result = FridaRuntimeInstrumentInputSchema.parse(input)
      expect(result.script_name).toBe(scriptName)
    })
  })
})

describe('createFridaRuntimeInstrumentHandler', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-frida-runtime')
    testDbPath = path.join(process.cwd(), 'test-frida-runtime.db')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
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
  })

  test('should return error for missing sample', async () => {
    const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database, {
      callWorker: async () => {
        throw new Error('Should not be called')
      },
    })

    const result = await handler({ sample_id: 'sha256:' + 'a'.repeat(64) })

    expect(result.ok).toBe(false)
    expect(result.errors).toContainEqual(expect.stringContaining('Sample not found'))
  })

  test('should handle empty workspace gracefully with sample_id context', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: 'b'.repeat(64),
      md5: 'b'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'test-session',
          pid: null,
          trace_count: 0,
          traces: [],
          duration_ms: 0,
        },
        artifacts: [],
        metrics: { elapsed_ms: 100 },
      }),
    })
    const result = await handler({ sample_id: sampleId })

    // Should work without sample files, using sample_id context
    expect(result.ok).toBe(true)
  })

  test('should return error for attach mode without PID', async () => {
    const sampleId = 'sha256:' + 'c'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: 'c'.repeat(64),
      md5: 'c'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    const fs = await import('fs/promises')
    const dummyFile = path.join((await workspaceManager.getWorkspace(sampleId)).original, 'test.exe')
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database)
    const result = await handler({ sample_id: sampleId, mode: 'attach' })

    expect(result.ok).toBe(false)
    expect(result.errors).toContain('PID is required for attach mode')
  })

  test('should return error when worker call fails', async () => {
    const sampleId = 'sha256:' + 'd'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: 'd'.repeat(64),
      md5: 'd'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    const fs = await import('fs/promises')
    const dummyFile = path.join((await workspaceManager.getWorkspace(sampleId)).original, 'test.exe')
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database, {
      callWorker: async () => {
        throw new Error('Worker connection failed')
      },
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(false)
    expect(result.errors).toContainEqual(expect.stringContaining('Worker connection failed'))
  })

  test('should handle Frida not installed gracefully with setup actions', async () => {
    const sampleId = 'sha256:' + 'e'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: 'e'.repeat(64),
      md5: 'e'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    const fs = await import('fs/promises')
    const dummyFile = path.join((await workspaceManager.getWorkspace(sampleId)).original, 'test.exe')
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database, {
      callWorker: async () => {
        throw new Error('ModuleNotFoundError: No module named frida')
      },
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('error')
    expect(data.warnings).toContainEqual(expect.stringContaining('Frida is not available'))
    expect(data.setup_actions).toBeDefined()
    expect(data.setup_actions?.length).toBeGreaterThan(0)
  })

  test('should process successful spawn instrumentation', async () => {
    const sampleId = 'sha256:' + 'f'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: 'f'.repeat(64),
      md5: 'f'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    const fs = await import('fs/promises')
    const dummyFile = path.join((await workspaceManager.getWorkspace(sampleId)).original, 'test.exe')
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'spawn-session-123',
          pid: 5678,
          trace_count: 5,
          traces: [
            { type: 'api_call', function: 'LoadLibraryA', module: 'kernel32.dll' },
            { type: 'api_call', function: 'GetProcAddress', module: 'kernel32.dll' },
          ],
          duration_ms: 1500,
        },
        artifacts: [],
        metrics: { elapsed_ms: 1500 },
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      mode: 'spawn',
      script_name: 'api_trace',
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('completed')
    expect(data.session_id).toBe('spawn-session-123')
    expect(data.pid).toBe(5678)
    expect(data.mode).toBe('spawn')
    expect(data.script_name).toBe('api_trace')
    expect(data.trace_summary.total_calls).toBe(5)
    expect(data.trace_summary.unique_functions).toBe(2)
    expect(data.traces).toHaveLength(2)
  })

  test('should persist artifact when requested', async () => {
    const sampleId = 'sha256:' + '0'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: '0'.repeat(64),
      md5: '0'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    const fs = await import('fs/promises')
    const dummyFile = path.join((await workspaceManager.getWorkspace(sampleId)).original, 'test.exe')
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'persist-session',
          pid: 9999,
          trace_count: 3,
          traces: [{ type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' }],
          duration_ms: 500,
        },
        artifacts: [],
        metrics: { elapsed_ms: 500 },
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      persist_artifact: true,
    })

    expect(result.ok).toBe(true)
    expect(result.artifacts).toHaveLength(1)
    expect((result.artifacts as any)[0].type).toBe('dynamic_trace')
    const artifactExists = await fs.access((result.artifacts as any)[0].path).then(() => true).catch(() => false)
    expect(artifactExists).toBe(true)
  })

  test('should handle worker returning failure with import error', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: '1'.repeat(64),
      md5: '1'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    const fs = await import('fs/promises')
    const dummyFile = path.join((await workspaceManager.getWorkspace(sampleId)).original, 'test.exe')
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: false,
        warnings: [],
        errors: ['ImportError: No module named frida'],
        data: {},
        artifacts: [],
        metrics: { elapsed_ms: 100 },
      }),
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('error')
    expect(data.setup_actions).toBeDefined()
  })

  test('should compute correct trace summary', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: '2'.repeat(64),
      md5: '2'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    const fs = await import('fs/promises')
    const dummyFile = path.join((await workspaceManager.getWorkspace(sampleId)).original, 'test.exe')
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'summary-session',
          pid: 1111,
          trace_count: 6,
          traces: [
            { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
            { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
            { type: 'api_call', function: 'ReadFile', module: 'kernel32.dll' },
            { type: 'api_call', function: 'WriteFile', module: 'kernel32.dll' },
            { type: 'string_access', function: 'strlen', module: 'ntdll.dll' },
            { type: 'crypto_api', function: 'CryptEncrypt', module: 'advapi32.dll' },
          ],
          duration_ms: 2000,
        },
        artifacts: [],
        metrics: { elapsed_ms: 2000 },
      }),
    })

    const result = await handler({ sample_id: sampleId, persist_artifact: false })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.trace_summary.total_calls).toBe(6)
    expect(data.trace_summary.unique_functions).toBe(5)
    expect(data.trace_summary.modules_touched).toEqual(
      expect.arrayContaining(['kernel32.dll', 'ntdll.dll', 'advapi32.dll'])
    )
    expect(data.trace_summary.duration_ms).toBe(2000)
  })

  test('should limit returned traces to 500', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: '3'.repeat(64),
      md5: '3'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    const fs = await import('fs/promises')
    const dummyFile = path.join((await workspaceManager.getWorkspace(sampleId)).original, 'test.exe')
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'limit-session',
          pid: 2222,
          trace_count: 1000,
          traces: Array.from({ length: 1000 }, (_, i) => ({
            type: 'api_call',
            function: `func_${i}`,
            module: 'test.dll',
          })),
          duration_ms: 5000,
        },
        artifacts: [],
        metrics: { elapsed_ms: 5000 },
      }),
    })

    const result = await handler({ sample_id: sampleId, persist_artifact: false })

    expect(result.ok).toBe(true)
    expect((result.data as any).traces.length).toBeLessThanOrEqual(500)
  })

  test('should handle warnings from worker', async () => {
    const sampleId = 'sha256:' + '4'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: '4'.repeat(64),
      md5: '4'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    const fs = await import('fs/promises')
    const dummyFile = path.join((await workspaceManager.getWorkspace(sampleId)).original, 'test.exe')
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: ['Process exited early', 'Some hooks failed'],
        errors: [],
        data: {
          session_id: 'warning-session',
          pid: 3333,
          trace_count: 1,
          traces: [{ type: 'api_call', function: 'test', module: 'test.dll' }],
          duration_ms: 100,
        },
        artifacts: [],
        metrics: { elapsed_ms: 100 },
      }),
    })

    const result = await handler({ sample_id: sampleId, persist_artifact: false })

    expect(result.ok).toBe(true)
    expect(result.warnings).toContain('Process exited early')
    expect(result.warnings).toContain('Some hooks failed')
  })
})
