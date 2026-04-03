/**
 * Integration tests for Frida dynamic instrumentation workflows
 * Tests spawn/attach/capture workflows with safe test samples
 */

import { describe, test, expect, beforeAll, afterAll } from '@jest/globals'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createFridaRuntimeInstrumentHandler } from '../../src/plugins/frida/tools/frida-runtime-instrument.js'
import { createFridaScriptInjectHandler } from '../../src/plugins/frida/tools/frida-script-inject.js'
import { createFridaTraceCaptureHandler } from '../../src/plugins/frida/tools/frida-trace-capture.js'
import { createSampleIngestHandler } from '../../src/tools/sample-ingest.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'

describe('Frida Integration Tests', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let policyGuard: PolicyGuard
  let testDir: string
  let dbPath: string
  let auditLogPath: string

  beforeAll(async () => {
    // Create temporary test directory
    testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'frida-integration-'))
    const workspaceRoot = path.join(testDir, 'workspaces')
    dbPath = path.join(testDir, 'test.db')
    auditLogPath = path.join(testDir, 'audit.log')

    // Initialize components
    workspaceManager = new WorkspaceManager(workspaceRoot)
    database = new DatabaseManager(dbPath)
    policyGuard = new PolicyGuard(auditLogPath)
  })

  afterAll(async () => {
    // Cleanup
    database.close()
    await fs.rm(testDir, { recursive: true, force: true })
  })

  /**
   * Create a minimal PE file for testing
   */
  async function createMinimalPE(): Promise<Buffer> {
    const pe = Buffer.alloc(1024)

    // DOS header
    pe.write('MZ', 0, 'ascii')
    pe.writeUInt32LE(0x80, 0x3c)

    // PE header at offset 0x80
    pe.write('PE\0\0', 0x80, 'ascii')

    // COFF header
    pe.writeUInt16LE(0x014c, 0x84) // Machine (IMAGE_FILE_MACHINE_I386)
    pe.writeUInt16LE(1, 0x86) // NumberOfSections
    pe.writeUInt32LE(Math.floor(Date.now() / 1000), 0x88) // TimeDateStamp
    pe.writeUInt32LE(0, 0x8c) // PointerToSymbolTable
    pe.writeUInt32LE(0, 0x90) // NumberOfSymbols
    pe.writeUInt16LE(0xe0, 0x94) // SizeOfOptionalHeader
    pe.writeUInt16LE(0x010f, 0x96) // Characteristics

    // Optional header
    pe.writeUInt16LE(0x010b, 0x98) // Magic (PE32)
    pe.writeUInt8(0x0e, 0x9a) // MajorLinkerVersion
    pe.writeUInt8(0x00, 0x9b) // MinorLinkerVersion
    pe.writeUInt32LE(0x1000, 0x9c) // SizeOfCode

    return pe
  }

  /**
   * Helper to ingest a test sample
   */
  async function ingestTestSample(peBuffer: Buffer): Promise<string> {
    const ingestHandler = createSampleIngestHandler({ workspaceManager, database, policyGuard } as any)
    const result = await ingestHandler({
      bytes_b64: peBuffer.toString('base64'),
      filename: 'test-sample.exe',
      source: 'integration-test',
    })

    if (!result.ok || !result.data) {
      throw new Error('Failed to ingest test sample')
    }

    return (result.data as { sample_id: string }).sample_id
  }

  describe('Frida Runtime Instrument', () => {
    test('should handle spawn mode with graceful degradation when Frida unavailable', async () => {
      const peBuffer = await createMinimalPE()
      const sampleId = await ingestTestSample(peBuffer)

      const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database, {
        callWorker: async () => {
          throw new Error('ModuleNotFoundError: No module named frida')
        },
      })

      const result = await handler({
        sample_id: sampleId,
        mode: 'spawn',
        script_name: 'api_trace',
        timeout_sec: 10,
      })

      // Should return graceful error with setup guidance
      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.status).toBe('error')
      expect(data.warnings).toContainEqual(expect.stringContaining('Frida is not available'))
      expect(data.setup_actions).toBeDefined()
      expect(data.setup_actions?.length).toBeGreaterThan(0)
    })

    test('should handle attach mode without PID gracefully', async () => {
      const peBuffer = await createMinimalPE()
      const sampleId = await ingestTestSample(peBuffer)

      const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database)
      const result = await handler({
        sample_id: sampleId,
        mode: 'attach',
        script_name: 'api_trace',
      })

      expect(result.ok).toBe(false)
      expect(result.errors).toContain('PID is required for attach mode')
    })

    test('should process mock spawn instrumentation successfully', async () => {
      const peBuffer = await createMinimalPE()
      const sampleId = await ingestTestSample(peBuffer)

      const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database, {
        callWorker: async () => ({
          job_id: 'test-job',
          ok: true,
          warnings: [],
          errors: [],
          data: {
            session_id: 'test-session-123',
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
        persist_artifact: true,
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.status).toBe('completed')
      expect(data.session_id).toBe('test-session-123')
      expect(data.pid).toBe(5678)
      expect(data.mode).toBe('spawn')
      expect(data.trace_summary.total_calls).toBe(5)
      expect(result.artifacts).toBeDefined()
    })
  })

  describe('Frida Script Inject', () => {
    test('should handle script injection with graceful degradation', async () => {
      const peBuffer = await createMinimalPE()
      const sampleId = await ingestTestSample(peBuffer)

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
      expect(data.warnings).toContainEqual(expect.stringContaining('Frida is not available'))
      expect(data.setup_actions).toBeDefined()
    })

    test('should handle custom script content injection', async () => {
      const peBuffer = await createMinimalPE()
      const sampleId = await ingestTestSample(peBuffer)

      const handler = createFridaScriptInjectHandler(workspaceManager, database, {
        callWorker: async () => ({
          job_id: 'test-job',
          ok: true,
          warnings: [],
          errors: [],
          data: {
            session_id: 'custom-script-session',
            pid: 1234,
            messages_captured: 3,
            results: [
              { type: 'custom_event', data: 'test message 1' },
              { type: 'custom_event', data: 'test message 2' },
            ],
          },
          artifacts: [],
          metrics: { elapsed_ms: 500 },
        }),
      })

      const result = await handler({
        pid: 1234,
        sample_id: sampleId,
        script_content: 'console.log("custom script");',
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.status).toBe('completed')
      expect(data.script_name).toBe('custom')
      expect(data.messages_captured).toBe(3)
      expect(data.results).toHaveLength(2)
    })

    test('should handle script file injection', async () => {
      const peBuffer = await createMinimalPE()
      const sampleId = await ingestTestSample(peBuffer)

      // Create a temporary script file
      const scriptPath = path.join(testDir, 'test_script.js')
      await fs.writeFile(scriptPath, 'console.log("test script");')

      const handler = createFridaScriptInjectHandler(workspaceManager, database, {
        callWorker: async () => ({
          job_id: 'test-job',
          ok: true,
          warnings: [],
          errors: [],
          data: {
            session_id: 'file-script-session',
            pid: 9999,
            messages_captured: 1,
            results: [{ type: 'file_script_event', data: 'loaded from file' }],
          },
          artifacts: [],
          metrics: { elapsed_ms: 300 },
        }),
      })

      const result = await handler({
        pid: 9999,
        sample_id: sampleId,
        script_path: scriptPath,
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.status).toBe('completed')
      expect(data.script_name).toContain('test_script.js')
    })
  })

  describe('Frida Trace Capture', () => {
    test('should handle trace capture with graceful degradation', async () => {
      const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
        callWorker: async () => {
          throw new Error('ModuleNotFoundError: No module named frida')
        },
      })

      const result = await handler({
        sample_id: 'sha256:' + 'a'.repeat(64),
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.status).toBe('error')
      expect(data.warnings).toContainEqual(expect.stringContaining('Frida is not available'))
    })

    test('should capture and normalize trace events', async () => {
      const peBuffer = await createMinimalPE()
      const sampleId = await ingestTestSample(peBuffer)

      const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
        callWorker: async () => ({
          job_id: 'test-job',
          ok: true,
          warnings: [],
          errors: [],
          data: {
            session_id: 'trace-capture-session',
            sample_id: sampleId,
            captured_at: new Date().toISOString(),
            total_events: 10,
            events: [
              { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll', args: ['C:\\test.txt'] },
              { type: 'api_call', function: 'ReadFile', module: 'kernel32.dll', args: [0x100, 0x200, 0x300] },
              { type: 'string_access', function: 'strlen', module: 'ntdll.dll', value: 'secret' },
            ],
          },
          artifacts: [],
          metrics: { elapsed_ms: 2000 },
        }),
      })

      const result = await handler({
        sample_id: sampleId,
        trace_format: 'normalized',
        persist_artifact: false,
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.session_id).toBe('trace-capture-session')
      expect(data.total_events).toBe(10)
      expect(data.events).toHaveLength(3)
      expect(data.events[0].type).toBe('api_call')
      expect(data.events[0].function).toBe('CreateFileW')
    })

    test('should apply trace filtering', async () => {
      const peBuffer = await createMinimalPE()
      const sampleId = await ingestTestSample(peBuffer)

      const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
        callWorker: async () => ({
          job_id: 'test-job',
          ok: true,
          warnings: [],
          errors: [],
          data: {
            session_id: 'filter-session',
            sample_id: sampleId,
            captured_at: new Date().toISOString(),
            total_events: 20,
            events: [
              { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
              { type: 'string_access', function: 'strlen', module: 'ntdll.dll' },
              { type: 'crypto_api', function: 'CryptEncrypt', module: 'advapi32.dll' },
            ],
          },
          artifacts: [],
          metrics: { elapsed_ms: 1000 },
        }),
      })

      const result = await handler({
        sample_id: sampleId,
        filter: { types: ['api_call', 'crypto_api'] },
        persist_artifact: false,
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.filtered_events).toBeLessThanOrEqual(20)
      // All returned events should match the filter
      data.events.forEach((event: any) => {
        expect(['api_call', 'crypto_api']).toContain(event.type)
      })
    })

    test('should apply trace aggregation and deduplication', async () => {
      const peBuffer = await createMinimalPE()
      const sampleId = await ingestTestSample(peBuffer)

      const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
        callWorker: async () => ({
          job_id: 'test-job',
          ok: true,
          warnings: [],
          errors: [],
          data: {
            session_id: 'aggregate-session',
            sample_id: sampleId,
            captured_at: new Date().toISOString(),
            total_events: 100,
            events: [
              { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
              { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' }, // Duplicate
              { type: 'api_call', function: 'ReadFile', module: 'kernel32.dll' },
              { type: 'string_access', function: 'strlen', module: 'ntdll.dll' },
            ],
          },
          artifacts: [],
          metrics: { elapsed_ms: 1500 },
        }),
      })

      const result = await handler({
        sample_id: sampleId,
        aggregate: true,
        persist_artifact: false,
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.aggregation).toBeDefined()
      expect(data.aggregation.by_type).toBeDefined()
      expect(data.aggregation.by_module).toBeDefined()
      expect(data.aggregation.by_function).toBeDefined()
    })

    test('should handle compact format conversion', async () => {
      const peBuffer = await createMinimalPE()
      const sampleId = await ingestTestSample(peBuffer)

      const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
        callWorker: async () => ({
          job_id: 'test-job',
          ok: true,
          warnings: [],
          errors: [],
          data: {
            session_id: 'compact-session',
            sample_id: sampleId,
            captured_at: new Date().toISOString(),
            total_events: 50,
            events: [
              { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
              { type: 'api_call', function: 'ReadFile', module: 'kernel32.dll' },
              { type: 'string_access', module: 'ntdll.dll' },
            ],
          },
          artifacts: [],
          metrics: { elapsed_ms: 800 },
        }),
      })

      const result = await handler({
        sample_id: sampleId,
        trace_format: 'compact',
        persist_artifact: false,
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.trace_format).toBe('compact')
      data.events.forEach((event: any) => {
        expect(event.data_preview).toBeDefined()
      })
    })

    test('should persist trace artifact when requested', async () => {
      const peBuffer = await createMinimalPE()
      const sampleId = await ingestTestSample(peBuffer)

      const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
        callWorker: async () => ({
          job_id: 'test-job',
          ok: true,
          warnings: [],
          errors: [],
          data: {
            session_id: 'persist-session',
            sample_id: sampleId,
            captured_at: new Date().toISOString(),
            total_events: 5,
            events: [{ type: 'api_call', function: 'Test', module: 'test.dll' }],
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
      const artifact = result.artifacts[0]
      expect(artifact.type).toBe('frida_trace')

      // Verify artifact file exists
      const artifactExists = await fs.access(artifact.path).then(() => true).catch(() => false)
      expect(artifactExists).toBe(true)
    })
  })

  describe('Concurrent Frida Operations', () => {
    test('should handle multiple concurrent instrument operations', async () => {
      const peBuffer = await createMinimalPE()
      const sampleId = await ingestTestSample(peBuffer)

      const handler = createFridaRuntimeInstrumentHandler(workspaceManager, database, {
        callWorker: async () => ({
          job_id: 'test-job',
          ok: true,
          warnings: [],
          errors: [],
          data: {
            session_id: `session-${Math.random()}`,
            pid: Math.floor(Math.random() * 10000) + 1000,
            trace_count: 3,
            traces: [{ type: 'api_call', function: 'Test', module: 'test.dll' }],
            duration_ms: 500,
          },
          artifacts: [],
          metrics: { elapsed_ms: 500 },
        }),
      })

      // Run 5 concurrent operations
      const results = await Promise.all(
        Array.from({ length: 5 }).map(() =>
          handler({
            sample_id: sampleId,
            mode: 'spawn',
            script_name: 'api_trace',
            persist_artifact: false,
          })
        )
      )

      // All operations should succeed
      results.forEach((result) => {
        expect(result.ok).toBe(true)
        const data = result.data as any
        expect(data.status).toBe('completed')
      })
    })
  })
})
