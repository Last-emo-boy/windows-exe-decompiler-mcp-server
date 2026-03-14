import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createDynamicMemoryImportHandler } from '../../src/tools/dynamic-memory-import.js'

describe('dynamic.memory.import tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testDumpRoot: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-dynamic-memory-import')
    testDbPath = path.join(process.cwd(), 'test-dynamic-memory-import.db')
    testDumpRoot = path.join(process.cwd(), 'test-dynamic-memory-dumps')

    for (const target of [testWorkspaceRoot, testDumpRoot]) {
      if (fs.existsSync(target)) {
        fs.rmSync(target, { recursive: true, force: true })
      }
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }

    fs.mkdirSync(testDumpRoot, { recursive: true })
    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore
    }

    for (const target of [testWorkspaceRoot, testDumpRoot]) {
      if (fs.existsSync(target)) {
        fs.rmSync(target, { recursive: true, force: true })
      }
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
  })

  test('should import minidump-style memory evidence and persist raw dump plus normalized trace', async () => {
    const sampleId = 'sha256:' + 'a'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'a'.repeat(64),
      md5: 'a'.repeat(32),
      size: 8192,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const dumpPath = path.join(testDumpRoot, 'remote_ops.dmp')
    const embeddedImage = Buffer.alloc(0x200, 0)
    embeddedImage.write('MZ', 0x80, 'ascii')
    embeddedImage.writeUInt32LE(0x40, 0x80 + 0x3c)
    embeddedImage.write('PE\0\0', 0x80 + 0x40, 'ascii')
    const dumpBytes = Buffer.concat([
      Buffer.from('MDMP', 'ascii'),
      Buffer.alloc(96, 0),
      Buffer.from(
        'GetProcAddress LoadLibraryA OpenProcess WriteProcessMemory ResumeThread SetThreadContext akasha.exe kernel32.dll',
        'utf-8'
      ),
      Buffer.alloc(64, 0),
      Buffer.from('NtQueryInformationProcess CreateFileW RegOpenKeyExW', 'utf-8'),
      embeddedImage,
    ])
    fs.writeFileSync(dumpPath, dumpBytes)

    const handler = createDynamicMemoryImportHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      path: dumpPath,
      format: 'auto',
      trace_name: 'akasha_remote_ops',
    })

    expect(result.ok).toBe(true)
    expect(result.warnings?.some((item) => item.includes('does not prove full execution'))).toBe(
      true
    )

    const data = result.data as any
    expect(data.format).toBe('minidump')
    expect(data.evidence_kind).toBe('memory_snapshot')
    expect(data.executed).toBe(false)
    expect(data.summary.high_signal_apis).toContain('OpenProcess')
    expect(data.summary.high_signal_apis).toContain('WriteProcessMemory')
    expect(data.summary.high_signal_apis).toContain('GetProcAddress')
    expect(data.summary.stages).toContain('prepare_remote_process_access')
    expect(data.summary.stages).toContain('resolve_dynamic_apis')
    expect(data.summary.source_formats).toContain('minidump')
    expect(data.summary.region_types).toContain('minidump_header')
    expect(data.summary.region_types).toContain('mapped_pe_image')
    expect(data.summary.protections).toContain('file_container')
    expect(data.summary.protections).toContain('r-x_image')
    expect(data.summary.address_ranges.some((item: string) => item.startsWith('0x0-'))).toBe(true)
    expect(data.summary.region_owners).toContain('akasha.exe')
    expect(data.summary.observed_modules).toContain('akasha.exe')
    expect(data.summary.segment_names).toContain('header')
    expect(data.summary.segment_names).toContain('.image')
    expect(data.raw_artifact.type).toBe('raw_dump')
    expect(data.trace_artifact.type).toBe('dynamic_trace_json')

    const rawArtifacts = database.findArtifactsByType(sampleId, 'raw_dump')
    const traceArtifacts = database.findArtifactsByType(sampleId, 'dynamic_trace_json')
    expect(rawArtifacts).toHaveLength(1)
    expect(traceArtifacts).toHaveLength(1)

    const analyses = database.findAnalysesBySample(sampleId)
    expect(analyses.some((item) => item.stage === 'memory_snapshot_import')).toBe(true)
  })

  test('should detect process-memory snapshots by extension and derive file plus registry stages', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'b'.repeat(64),
      md5: 'b'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const dumpPath = path.join(testDumpRoot, 'snapshot.mem')
    const dumpBytes = Buffer.concat([
      Buffer.alloc(32, 0),
      Buffer.from('CreateFileW ReadFile WriteFile RegOpenKeyExW RegSetValueExW advapi32.dll', 'utf-8'),
      Buffer.alloc(48, 0),
      Buffer.from('InternetOpenA InternetConnectA HttpSendRequestA', 'utf-8'),
    ])
    fs.writeFileSync(dumpPath, dumpBytes)

    const handler = createDynamicMemoryImportHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      path: dumpPath,
      format: 'auto',
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.format).toBe('process_memory')
    expect(data.summary.stages).toContain('file_operations')
    expect(data.summary.stages).toContain('registry_operations')
    expect(data.summary.source_formats).toContain('process_memory')
    expect(data.summary.protections).toContain('read_write_plan')
    expect(data.context_window_count).toBeGreaterThan(0)
    expect(data.summary.api_count).toBeGreaterThan(0)
    expect(data.summary.observed_modules).toContain('advapi32.dll')
  })
})
