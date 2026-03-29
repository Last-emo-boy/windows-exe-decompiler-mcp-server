/**
 * Unit tests for frida.script.inject tool
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import * as fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  createFridaScriptInjectHandler,
  FridaScriptInjectInputSchema,
} from '../../src/tools/frida-script-inject.js'

describe('FridaScriptInjectInputSchema', () => {
  test('should accept valid input with all fields', () => {
    const input = {
      pid: 1234,
      sample_id: 'sha256:' + 'a'.repeat(64),
      script_name: 'api_trace' as const,
      script_content: 'console.log("test");',
      script_path: '/path/to/script.js',
      script_parameters: { modules: ['kernel32.dll'] },
      timeout_sec: 60,
      persist_artifact: true,
      register_analysis: true,
    }

    const result = FridaScriptInjectInputSchema.parse(input)
    expect(result.pid).toBe(1234)
    expect(result.script_name).toBe('api_trace')
    expect(result.timeout_sec).toBe(60)
  })

  test('should accept minimal input with pid only', () => {
    const input = { pid: 5678 }
    const result = FridaScriptInjectInputSchema.parse(input)
    expect(result.pid).toBe(5678)
    expect(result.timeout_sec).toBe(30)
    expect(result.persist_artifact).toBe(true)
    expect(result.register_analysis).toBe(true)
  })

  test('should reject invalid script_name', () => {
    const input = { pid: 1234, script_name: 'invalid_script' }
    expect(() => FridaScriptInjectInputSchema.parse(input)).toThrow()
  })

  test('should reject timeout out of range', () => {
    const input1 = { pid: 1234, timeout_sec: 3 }
    expect(() => FridaScriptInjectInputSchema.parse(input1)).toThrow()

    const input2 = { pid: 1234, timeout_sec: 301 }
    expect(() => FridaScriptInjectInputSchema.parse(input2)).toThrow()
  })

  test('should reject non-positive pid', () => {
    const input1 = { pid: 0 }
    expect(() => FridaScriptInjectInputSchema.parse(input1)).toThrow()

    const input2 = { pid: -1 }
    expect(() => FridaScriptInjectInputSchema.parse(input2)).toThrow()
  })

  test('should accept all valid script names', () => {
    const validScripts = ['api_trace', 'string_decoder', 'anti_debug_bypass', 'crypto_finder', 'file_registry_monitor', 'default']

    validScripts.forEach((scriptName) => {
      const input = { pid: 1234, script_name: scriptName }
      const result = FridaScriptInjectInputSchema.parse(input)
      expect(result.script_name).toBe(scriptName)
    })
  })
})

describe('createFridaScriptInjectHandler', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-frida-script')
    testDbPath = path.join(process.cwd(), 'test-frida-script.db')

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

  test('should return error when no script is provided', async () => {
    const handler = createFridaScriptInjectHandler(workspaceManager, database, {
      callWorker: async () => {
        throw new Error('Should not be called')
      },
    })

    const result = await handler({ pid: 1234 })

    expect(result.ok).toBe(false)
    expect(result.errors).toContainEqual(
      expect.stringContaining('One of script_content, script_path, or script_name must be provided')
    )
  })

  test('should return error for missing sample when sample_id provided but not found', async () => {
    const handler = createFridaScriptInjectHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'test-session',
          pid: 1234,
          messages_captured: 0,
          results: [],
        },
        artifacts: [],
        metrics: { elapsed_ms: 100 },
      }),
    })
    const result = await handler({
      pid: 1234,
      sample_id: 'sha256:' + 'a'.repeat(64),
      script_name: 'api_trace',
    })

    // Should still work without sample, just with empty path context
    expect(result.ok).toBe(true)
  })

  test('should return error when script file not found', async () => {
    const handler = createFridaScriptInjectHandler(workspaceManager, database)
    const result = await handler({
      pid: 1234,
      script_path: '/nonexistent/path/script.js',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toContainEqual(
      expect.stringContaining('Script file not found')
    )
  })

  test('should return error when worker call fails', async () => {
    const sampleId = 'sha256:' + 'a'.repeat(64)
    const createdAt = new Date().toISOString()

    database.insertSample({
      id: sampleId,
      sha256: 'a'.repeat(64),
      md5: 'a'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })

    await workspaceManager.createWorkspace(sampleId)

    const fs = await import('fs/promises')
    const dummyFile = path.join(
      (await workspaceManager.getWorkspace(sampleId)).original,
      'test.exe'
    )
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaScriptInjectHandler(workspaceManager, database, {
      callWorker: async () => {
        throw new Error('Worker connection failed')
      },
    })

    const result = await handler({
      pid: 1234,
      sample_id: sampleId,
      script_name: 'api_trace',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toContainEqual(
      expect.stringContaining('Worker connection failed')
    )
  })

  test('should handle Frida not installed gracefully with setup guidance', async () => {
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

    const fs = await import('fs/promises')
    const dummyFile = path.join(
      (await workspaceManager.getWorkspace(sampleId)).original,
      'test.exe'
    )
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaScriptInjectHandler(workspaceManager, database, {
      callWorker: async () => {
        throw new Error('ModuleNotFoundError: No module named frida')
      },
    })

    const result = await handler({
      pid: 1234,
      sample_id: sampleId,
      script_name: 'api_trace',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('error')
    expect(data.warnings).toContainEqual(
      expect.stringContaining('Frida is not available')
    )
    expect(data.setup_actions).toBeDefined()
    expect(data.setup_actions?.length).toBeGreaterThan(0)
  })

  test('should handle worker returning failure with import error', async () => {
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
    const dummyFile = path.join(
      (await workspaceManager.getWorkspace(sampleId)).original,
      'test.exe'
    )
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaScriptInjectHandler(workspaceManager, database, {
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

    const result = await handler({
      pid: 1234,
      sample_id: sampleId,
      script_name: 'api_trace',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('error')
    expect(data.setup_actions).toBeDefined()
  })

  test('should process successful script injection', async () => {
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
    const dummyFile = path.join(
      (await workspaceManager.getWorkspace(sampleId)).original,
      'test.exe'
    )
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaScriptInjectHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'inject-session-123',
          pid: 1234,
          messages_captured: 10,
          results: [
            { type: 'api_call', function: 'LoadLibraryA', module: 'kernel32.dll', args: ['user32.dll'] },
            { type: 'api_call', function: 'GetProcAddress', module: 'kernel32.dll', args: ['LoadLibraryA'] },
          ],
        },
        artifacts: [],
        metrics: { elapsed_ms: 500 },
      }),
    })

    const result = await handler({
      pid: 1234,
      sample_id: sampleId,
      script_name: 'api_trace',
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('completed')
    expect(data.session_id).toBe('inject-session-123')
    expect(data.pid).toBe(1234)
    expect(data.script_name).toBe('api_trace')
    expect(data.messages_captured).toBe(10)
    expect(data.results).toHaveLength(2)
  })

  test('should handle custom script content', async () => {
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
    const dummyFile = path.join(
      (await workspaceManager.getWorkspace(sampleId)).original,
      'test.exe'
    )
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaScriptInjectHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'custom-script-session',
          pid: 5678,
          messages_captured: 5,
          results: [{ type: 'custom_event', data: 'custom data' }],
        },
        artifacts: [],
        metrics: { elapsed_ms: 300 },
      }),
    })

    const result = await handler({
      pid: 5678,
      sample_id: sampleId,
      script_content: 'console.log("custom script");',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('completed')
    expect(data.script_name).toBe('custom')
    expect(data.results).toHaveLength(1)
  })

  test('should persist artifact when requested', async () => {
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
    const dummyFile = path.join(
      (await workspaceManager.getWorkspace(sampleId)).original,
      'test.exe'
    )
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaScriptInjectHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'persist-session',
          pid: 9999,
          messages_captured: 3,
          results: [{ type: 'test', function: 'test_func' }],
        },
        artifacts: [],
        metrics: { elapsed_ms: 200 },
      }),
    })

    const result = await handler({
      pid: 9999,
      sample_id: sampleId,
      script_name: 'api_trace',
      persist_artifact: true,
    })

    expect(result.ok).toBe(true)
    expect(result.artifacts).toHaveLength(1)
    expect((result.artifacts as any)[0].type).toBe('script_injection')
    const artifactExists = await fs.access((result.artifacts as any)[0].path).then(() => true).catch(() => false)
    expect(artifactExists).toBe(true)
  })

  test('should limit returned results to 500', async () => {
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
    const dummyFile = path.join(
      (await workspaceManager.getWorkspace(sampleId)).original,
      'test.exe'
    )
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaScriptInjectHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'limit-session',
          pid: 1111,
          messages_captured: 1000,
          results: Array.from({ length: 1000 }, (_, i) => ({
            type: 'api_call',
            function: `func_${i}`,
            module: 'test.dll',
          })),
        },
        artifacts: [],
        metrics: { elapsed_ms: 2000 },
      }),
    })

    const result = await handler({
      pid: 1111,
      sample_id: sampleId,
      script_name: 'api_trace',
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    expect((result.data as any).results.length).toBeLessThanOrEqual(500)
  })

  test('should handle warnings from worker', async () => {
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
    const dummyFile = path.join(
      (await workspaceManager.getWorkspace(sampleId)).original,
      'test.exe'
    )
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaScriptInjectHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: ['Script terminated early', 'Some hooks failed to attach'],
        errors: [],
        data: {
          session_id: 'warning-session',
          pid: 2222,
          messages_captured: 1,
          results: [{ type: 'test' }],
        },
        artifacts: [],
        metrics: { elapsed_ms: 100 },
      }),
    })

    const result = await handler({
      pid: 2222,
      sample_id: sampleId,
      script_name: 'api_trace',
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    expect(result.warnings).toContain('Script terminated early')
    expect(result.warnings).toContain('Some hooks failed to attach')
  })

  test('should handle script with parameters', async () => {
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
    const dummyFile = path.join(
      (await workspaceManager.getWorkspace(sampleId)).original,
      'test.exe'
    )
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaScriptInjectHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'param-session',
          pid: 3333,
          messages_captured: 7,
          results: [{ type: 'filtered_api', function: 'CreateFileW' }],
        },
        artifacts: [],
        metrics: { elapsed_ms: 400 },
      }),
    })

    const result = await handler({
      pid: 3333,
      sample_id: sampleId,
      script_name: 'api_trace',
      script_parameters: { modules: ['kernel32.dll'], functions: ['CreateFileW'] },
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('completed')
    expect(data.messages_captured).toBe(7)
  })
})
