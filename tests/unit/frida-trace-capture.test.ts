/**
 * Unit tests for frida.trace.capture tool
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  createFridaTraceCaptureHandler,
  FridaTraceCaptureInputSchema,
  normalizeTraceEvent,
  filterTraceEvents,
  aggregateTraceEvents,
  deduplicateTraceEvents,
  convertToCompactFormat,
} from '../../src/tools/frida-trace-capture.js'

describe('FridaTraceCaptureInputSchema', () => {
  test('should accept valid input with all optional fields', () => {
    const input = {
      sample_id: 'sha256:' + 'a'.repeat(64),
      session_id: 'session-123',
      artifact_id: 'artifact-456',
      trace_format: 'normalized' as const,
      filter: {
        types: ['api_call'],
        modules: ['kernel32.dll'],
        functions: ['CreateFile'],
        min_timestamp: 1000,
        max_timestamp: 2000,
      },
      aggregate: true,
      limit: 500,
      persist_artifact: true,
      register_analysis: true,
    }

    const result = FridaTraceCaptureInputSchema.parse(input)
    expect(result.sample_id).toBe(input.sample_id)
    expect(result.filter?.modules).toContain('kernel32.dll')
  })

  test('should accept minimal input with defaults', () => {
    const input = {}
    const result = FridaTraceCaptureInputSchema.parse(input)
    expect(result.trace_format).toBe('normalized')
    expect(result.aggregate).toBe(false)
    expect(result.limit).toBe(1000)
    expect(result.persist_artifact).toBe(true)
    expect(result.register_analysis).toBe(true)
  })

  test('should reject invalid trace_format', () => {
    const input = { trace_format: 'invalid' }
    expect(() => FridaTraceCaptureInputSchema.parse(input)).toThrow()
  })

  test('should reject limit out of range', () => {
    const input = { limit: 0 }
    expect(() => FridaTraceCaptureInputSchema.parse(input)).toThrow()

    const input2 = { limit: 10001 }
    expect(() => FridaTraceCaptureInputSchema.parse(input2)).toThrow()
  })
})

describe('normalizeTraceEvent', () => {
  test('should normalize standard trace event', () => {
    const rawEvent = {
      type: 'api_call',
      function: 'CreateFileW',
      module: 'kernel32.dll',
      args: ['C:\\test.txt'],
      timestamp: 1234567890,
      thread_id: 1234,
    }

    const normalized = normalizeTraceEvent(rawEvent)

    expect(normalized.type).toBe('api_call')
    expect(normalized.function).toBe('CreateFileW')
    expect(normalized.module).toBe('kernel32.dll')
    expect(normalized.args).toEqual(['C:\\test.txt'])
    expect(normalized.timestamp).toBe(1234567890)
    expect(normalized.thread_id).toBe(1234)
  })

  test('should handle alternative field names', () => {
    const rawEvent = {
      _type: 'string_access',
      _timestamp: 9876543210,
      value: 'secret',
      data_preview: 'preview data',
      source: 'frida',
      category: 'io',
    }

    const normalized = normalizeTraceEvent(rawEvent)

    expect(normalized.type).toBe('string_access')
    expect(normalized.timestamp).toBe(9876543210)
    expect(normalized.value).toBe('secret')
    expect(normalized.data_preview).toBe('preview data')
    expect(normalized.source).toBe('frida')
    expect(normalized.category).toBe('io')
  })

  test('should handle missing optional fields', () => {
    const rawEvent = { type: 'unknown' }
    const normalized = normalizeTraceEvent(rawEvent)

    expect(normalized.type).toBe('unknown')
    expect(normalized.function).toBeUndefined()
    expect(normalized.module).toBeUndefined()
    expect(normalized.args).toBeUndefined()
  })

  test('should handle empty event', () => {
    const rawEvent = {}
    const normalized = normalizeTraceEvent(rawEvent)

    expect(normalized.type).toBe('unknown')
  })
})

describe('filterTraceEvents', () => {
  const events: ReturnType<typeof import('../../src/tools/frida-trace-capture.js').normalizeTraceEvent>[] = [
    { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll', timestamp: 1000 },
    { type: 'api_call', function: 'ReadFile', module: 'kernel32.dll', timestamp: 1500 },
    { type: 'string_access', function: 'strlen', module: 'ntdll.dll', timestamp: 2000 },
    { type: 'crypto_api', function: 'CryptEncrypt', module: 'advapi32.dll', timestamp: 2500 },
  ]

  test('should filter by types', () => {
    const filter = { types: ['api_call'] }
    const filtered = filterTraceEvents(events, filter)

    expect(filtered.length).toBe(2)
    expect(filtered.every((e) => e.type === 'api_call')).toBe(true)
  })

  test('should filter by modules', () => {
    const filter = { modules: ['kernel32'] }
    const filtered = filterTraceEvents(events, filter)

    expect(filtered.length).toBe(2)
    expect(filtered.every((e) => e.module?.includes('kernel32'))).toBe(true)
  })

  test('should filter by functions', () => {
    const filter = { functions: ['CreateFile'] }
    const filtered = filterTraceEvents(events, filter)

    expect(filtered.length).toBe(1)
    expect(filtered[0].function).toBe('CreateFileW')
  })

  test('should filter by timestamp range', () => {
    const filter = { min_timestamp: 1000, max_timestamp: 2000 }
    const filtered = filterTraceEvents(events, filter)

    expect(filtered.length).toBe(3)
    expect(filtered[0].timestamp).toBe(1000)
    expect(filtered[1].timestamp).toBe(1500)
    expect(filtered[2].timestamp).toBe(2000)
  })

  test('should apply multiple filters', () => {
    const filter = { types: ['api_call'], modules: ['kernel32'] }
    const filtered = filterTraceEvents(events, filter)

    expect(filtered.length).toBe(2)
  })

  test('should return all events with empty filter', () => {
    const filter = {}
    const filtered = filterTraceEvents(events, filter)

    expect(filtered.length).toBe(4)
  })
})

describe('aggregateTraceEvents', () => {
  const events: ReturnType<typeof import('../../src/tools/frida-trace-capture.js').normalizeTraceEvent>[] = [
    { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
    { type: 'api_call', function: 'ReadFile', module: 'kernel32.dll' },
    { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
    { type: 'string_access', function: 'strlen', module: 'ntdll.dll' },
  ]

  test('should aggregate by type', () => {
    const aggregation = aggregateTraceEvents(events)

    expect(aggregation.by_type['api_call']).toBe(3)
    expect(aggregation.by_type['string_access']).toBe(1)
  })

  test('should aggregate by module', () => {
    const aggregation = aggregateTraceEvents(events)

    expect(aggregation.by_module['kernel32.dll']).toBe(3)
    expect(aggregation.by_module['ntdll.dll']).toBe(1)
  })

  test('should aggregate by function', () => {
    const aggregation = aggregateTraceEvents(events)

    expect(aggregation.by_function['CreateFileW']).toBe(2)
    expect(aggregation.by_function['ReadFile']).toBe(1)
    expect(aggregation.by_function['strlen']).toBe(1)
  })
})

describe('deduplicateTraceEvents', () => {
  test('should remove duplicate events', () => {
    const events: ReturnType<typeof import('../../src/tools/frida-trace-capture.js').normalizeTraceEvent>[] = [
      { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll', args: ['C:\\test.txt'] },
      { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll', args: ['C:\\test.txt'] },
      { type: 'api_call', function: 'ReadFile', module: 'kernel32.dll', args: [0x100] },
    ]

    const deduped = deduplicateTraceEvents(events)

    expect(deduped.length).toBe(2)
  })

  test('should preserve order of unique events', () => {
    const events: ReturnType<typeof import('../../src/tools/frida-trace-capture.js').normalizeTraceEvent>[] = [
      { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll', args: ['C:\\a.txt'] },
      { type: 'api_call', function: 'ReadFile', module: 'kernel32.dll', args: [0x100] },
      { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll', args: ['C:\\a.txt'] },
    ]

    const deduped = deduplicateTraceEvents(events)

    expect(deduped[0].function).toBe('CreateFileW')
    expect(deduped[0].args).toEqual(['C:\\a.txt'])
    expect(deduped[1].function).toBe('ReadFile')
  })

  test('should handle events without distinguishing fields', () => {
    const events: ReturnType<typeof import('../../src/tools/frida-trace-capture.js').normalizeTraceEvent>[] = [
      { type: 'unknown' },
      { type: 'unknown' },
      { type: 'api_call', function: 'test' },
    ]

    const deduped = deduplicateTraceEvents(events)

    expect(deduped.length).toBe(2)
  })
})

describe('convertToCompactFormat', () => {
  const events: ReturnType<typeof import('../../src/tools/frida-trace-capture.js').normalizeTraceEvent>[] = [
    { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
    { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
    { type: 'api_call', function: 'ReadFile', module: 'kernel32.dll' },
    { type: 'string_access', module: 'ntdll.dll' },
  ]

  const aggregation = {
    by_type: { api_call: 3, string_access: 1 },
    by_module: { 'kernel32.dll': 3, 'ntdll.dll': 1 },
    by_function: { CreateFileW: 2, ReadFile: 1 },
  }

  test('should return summary with counts', () => {
    const compact = convertToCompactFormat(events, aggregation)

    expect(compact.length).toBeLessThanOrEqual(events.length)
    compact.forEach((event) => {
      expect(event.data_preview).toBeDefined()
      expect(event.data_preview).toContain('count:')
    })
  })

  test('should return unique type/module/function combinations', () => {
    const compact = convertToCompactFormat(events, aggregation)
    const seen = new Set<string>()

    compact.forEach((event) => {
      const key = `${event.type}|${event.module || ''}|${event.function || ''}`
      expect(seen.has(key)).toBe(false)
      seen.add(key)
    })
  })
})

describe('createFridaTraceCaptureHandler', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-frida-trace')
    testDbPath = path.join(process.cwd(), 'test-frida-trace.db')

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

  test('should return error when worker call fails', async () => {
    const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
      callWorker: async () => {
        throw new Error('Worker connection failed')
      },
    })

    const result = await handler({ sample_id: 'sha256:' + 'a'.repeat(64) })

    expect(result.ok).toBe(false)
    expect(result.errors).toContainEqual(expect.stringContaining('Worker connection failed'))
  })

  test('should return error when worker returns failure', async () => {
    const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: false,
        warnings: [],
        errors: ['Frida session expired'],
        data: {},
        artifacts: [],
        metrics: { elapsed_ms: 100 },
      }),
    })

    const result = await handler({ sample_id: 'sha256:' + 'a'.repeat(64) })

    expect(result.ok).toBe(false)
    expect(result.errors).toContain('Frida session expired')
  })

  test('should process and return trace data from worker', async () => {
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

    // Create a dummy file in workspace
    const fs = await import('fs/promises')
    const dummyFile = path.join((await workspaceManager.getWorkspace(sampleId)).original, 'test.exe')
    await fs.writeFile(dummyFile, 'dummy content')

    const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'test-session',
          traces: [
            { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
            { type: 'api_call', function: 'ReadFile', module: 'kernel32.dll' },
          ],
        },
        artifacts: [],
        metrics: { elapsed_ms: 100 },
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      trace_format: 'normalized',
      limit: 100,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.session_id).toBe('test-session')
    expect(data.total_events).toBe(2)
    expect(data.filtered_events).toBe(2)
    expect(data.events).toHaveLength(2)
  })

  test('should apply filtering to trace events', async () => {
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

    const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'test-session',
          traces: [
            { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
            { type: 'string_access', function: 'strlen', module: 'ntdll.dll' },
          ],
        },
        artifacts: [],
        metrics: { elapsed_ms: 100 },
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      filter: { types: ['api_call'] },
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.filtered_events).toBe(1)
    expect(data.events[0].type).toBe('api_call')
  })

  test('should apply limit and generate warning', async () => {
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

    const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'test-session',
          traces: Array.from({ length: 100 }, (_, i) => ({
            type: 'api_call',
            function: `func_${i}`,
            module: 'test.dll',
          })),
        },
        artifacts: [],
        metrics: { elapsed_ms: 100 },
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      limit: 10,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    expect((result.data as any).filtered_events).toBe(10)
    expect(result.warnings).toContainEqual(expect.stringContaining('limited to 10 events'))
  })

  test('should persist artifact when requested', async () => {
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

    const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'test-session',
          traces: [{ type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' }],
        },
        artifacts: [],
        metrics: { elapsed_ms: 100 },
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      persist_artifact: true,
    })

    expect(result.ok).toBe(true)
    expect(result.artifacts).toHaveLength(1)
    expect((result.artifacts as any)[0].type).toBe('frida_trace')
    const artifactExists = await fs.access((result.artifacts as any)[0].path).then(() => true).catch(() => false)
    expect(artifactExists).toBe(true)
  })

  test('should aggregate trace events when requested', async () => {
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

    const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'test-session',
          traces: [
            { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
            { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
            { type: 'api_call', function: 'ReadFile', module: 'kernel32.dll' },
          ],
        },
        artifacts: [],
        metrics: { elapsed_ms: 100 },
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      aggregate: true,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.filtered_events).toBe(2) // Deduplicated
    expect(data.aggregation).toBeDefined()
  })

  test('should handle compact format conversion', async () => {
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

    const handler = createFridaTraceCaptureHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'test-job',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          session_id: 'test-session',
          traces: [
            { type: 'api_call', function: 'CreateFileW', module: 'kernel32.dll' },
            { type: 'api_call', function: 'ReadFile', module: 'kernel32.dll' },
          ],
        },
        artifacts: [],
        metrics: { elapsed_ms: 100 },
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
})
