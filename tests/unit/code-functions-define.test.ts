import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createCodeFunctionsDefineHandler } from '../../src/tools/code-functions-define.js'

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

  const textSection = Buffer.alloc(40, 0)
  textSection.write('.text', 0, 'ascii')
  textSection.writeUInt32LE(0x100, 8)
  textSection.writeUInt32LE(0x1000, 12)
  textSection.writeUInt32LE(0x200, 16)
  textSection.writeUInt32LE(0x200, 20)
  textSection.writeUInt32LE(0x60000020, 36)

  return Buffer.concat([dosHeader, peSignature, coffHeader, optionalHeader, textSection, Buffer.alloc(0x200, 0)])
}

describe('code.functions.define tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string
  const sampleId = 'sha256:' + '6'.repeat(64)

  beforeEach(async () => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-code-functions-define')
    testDbPath = path.join(process.cwd(), 'test-code-functions-define.db')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)

    database.insertSample({
      id: sampleId,
      sha256: '6'.repeat(64),
      md5: '6'.repeat(32),
      size: 1024,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const workspace = await workspaceManager.createWorkspace(sampleId)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), createMinimalAmd64PdataPE())
    database.insertFunction({
      sample_id: sampleId,
      address: '0x140000900',
      name: 'stale_function',
      size: 32,
      score: null,
      tags: null,
      summary: null,
      caller_count: 0,
      callee_count: 0,
      is_entry_point: 0,
      is_exported: 0,
      callees: null,
    })
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

  test('should import recovered functions, persist an artifact, and keep decompile/cfg readiness missing', async () => {
    const handler = createCodeFunctionsDefineHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      source: 'symbols_recover',
      replace_all: true,
      session_tag: 'rust-import',
      definitions: [
        {
          rva: 0x1000,
          size: 0x100,
          recovered_name: 'rust_entry_point_00001000',
          is_entry_point: true,
          evidence: ['Recovered from .pdata'],
        },
      ],
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.imported_count).toBe(1)
    expect(data.function_index_status).toBe('ready')
    expect(data.decompile_status).toBe('missing')
    expect(data.cfg_status).toBe('missing')
    expect(data.image_base).toBe(0x140000000)
    expect(data.imported_functions[0].address).toBe('0x140001000')
    expect(data.artifact.path).toContain('reports/function_definitions/')

    const functions = database.findFunctions(sampleId)
    expect(functions).toHaveLength(1)
    expect(functions[0].name).toBe('rust_entry_point_00001000')
    expect(functions[0].address).toBe('0x140001000')

    const analyses = database.findAnalysesBySample(sampleId)
    const analysis = analyses.find((item) => item.stage === 'function_definition')
    expect(analysis).toBeDefined()
    const output = JSON.parse(analysis!.output_json || '{}')
    expect(output.readiness.function_index.status).toBe('ready')
    expect(output.readiness.decompile.status).toBe('missing')
    expect(output.readiness.cfg.status).toBe('missing')
  })
})
