import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createCodeFunctionsSmartRecoverHandler } from '../../src/tools/code-functions-smart-recover.js'

function createMinimalAmd64PdataPE(): Buffer {
  const dosHeader = Buffer.alloc(0x80, 0)
  dosHeader.write('MZ', 0, 'ascii')
  dosHeader.writeUInt32LE(0x80, 0x3c)

  const peSignature = Buffer.from('PE\0\0', 'ascii')
  const coffHeader = Buffer.alloc(20, 0)
  coffHeader.writeUInt16LE(0x8664, 0)
  coffHeader.writeUInt16LE(3, 2)
  coffHeader.writeUInt16LE(0x00f0, 16)
  coffHeader.writeUInt16LE(0x0022, 18)

  const optionalHeader = Buffer.alloc(0x00f0, 0)
  optionalHeader.writeUInt16LE(0x20b, 0)
  optionalHeader.writeUInt32LE(0x200, 4)
  optionalHeader.writeUInt32LE(0x1000, 16)
  optionalHeader.writeUInt32LE(0x1000, 20)
  optionalHeader.writeBigUInt64LE(0x140000000n, 24)
  optionalHeader.writeUInt32LE(0x1000, 32)
  optionalHeader.writeUInt32LE(0x200, 36)
  optionalHeader.writeUInt32LE(0x4000, 56)
  optionalHeader.writeUInt32LE(0x200, 60)
  optionalHeader.writeUInt16LE(3, 68)
  optionalHeader.writeUInt32LE(16, 108)
  optionalHeader.writeUInt32LE(0x2000, 136)
  optionalHeader.writeUInt32LE(12, 140)

  const textSection = Buffer.alloc(40, 0)
  textSection.write('.text', 0, 'ascii')
  textSection.writeUInt32LE(0x100, 8)
  textSection.writeUInt32LE(0x1000, 12)
  textSection.writeUInt32LE(0x200, 16)
  textSection.writeUInt32LE(0x200, 20)
  textSection.writeUInt32LE(0x60000020, 36)

  const pdataSection = Buffer.alloc(40, 0)
  pdataSection.write('.pdata', 0, 'ascii')
  pdataSection.writeUInt32LE(0x0c, 8)
  pdataSection.writeUInt32LE(0x2000, 12)
  pdataSection.writeUInt32LE(0x200, 16)
  pdataSection.writeUInt32LE(0x400, 20)
  pdataSection.writeUInt32LE(0x40000040, 36)

  const xdataSection = Buffer.alloc(40, 0)
  xdataSection.write('.xdata', 0, 'ascii')
  xdataSection.writeUInt32LE(0x10, 8)
  xdataSection.writeUInt32LE(0x3000, 12)
  xdataSection.writeUInt32LE(0x200, 16)
  xdataSection.writeUInt32LE(0x600, 20)
  xdataSection.writeUInt32LE(0x40000040, 36)

  const headers = Buffer.concat([
    dosHeader,
    peSignature,
    coffHeader,
    optionalHeader,
    textSection,
    pdataSection,
    xdataSection,
  ])

  const textData = Buffer.alloc(0x200, 0)
  textData[0] = 0xc3

  const pdataData = Buffer.alloc(0x200, 0)
  pdataData.writeUInt32LE(0x1000, 0)
  pdataData.writeUInt32LE(0x1100, 4)
  pdataData.writeUInt32LE(0x3000, 8)

  const xdataData = Buffer.alloc(0x200, 0)
  xdataData.writeUInt8(0x01, 0)
  xdataData.writeUInt8(0x10, 1)

  return Buffer.concat([headers, textData, pdataData, xdataData])
}

describe('code.functions.smart_recover tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string
  const sampleId = 'sha256:' + '8'.repeat(64)

  beforeEach(async () => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-code-functions-smart-recover')
    testDbPath = path.join(process.cwd(), 'test-code-functions-smart-recover.db')
    testCachePath = path.join(process.cwd(), 'test-cache-code-functions-smart-recover')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
    cacheManager = new CacheManager(testCachePath, database)

    database.insertSample({
      id: sampleId,
      sha256: '8'.repeat(64),
      md5: '8'.repeat(32),
      size: 2048,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const workspace = await workspaceManager.createWorkspace(sampleId)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), createMinimalAmd64PdataPE())
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
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }
  })

  test('should recover entry-point-aligned function candidates from .pdata metadata', async () => {
    const handler = createCodeFunctionsSmartRecoverHandler(workspaceManager, database, cacheManager)
    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.machine_name).toBe('IMAGE_FILE_MACHINE_AMD64')
    expect(data.strategy).toContain('pdata_runtime_functions')
    expect(data.strategy).toContain('entry_point')
    expect(data.count).toBe(1)
    expect(data.functions[0].name).toBe('entry_point')
    expect(data.functions[0].name_source).toBe('entry_point')
    expect(data.functions[0].source).toBe('pdata_runtime_function')
    expect(data.functions[0].is_entry_point).toBe(true)
    expect(data.functions[0].section_name).toBe('.text')
  })
})
