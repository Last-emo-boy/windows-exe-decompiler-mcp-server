import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createFunctionIndexRecoverWorkflowHandler } from '../../src/workflows/function-index-recover.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'

describe('workflow.function_index_recover', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-function-index-recover')
    testDbPath = path.join(process.cwd(), 'test-function-index-recover.db')
    testCachePath = path.join(process.cwd(), 'test-cache-function-index-recover')

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

  test('should recover functions, prefer recovered symbol names, and materialize a function index', async () => {
    const sampleId = 'sha256:' + 'e'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'e'.repeat(64),
      md5: 'e'.repeat(32),
      size: 8192,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    await workspaceManager.createWorkspace(sampleId)

    const smartRecoverHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        machine: 0x8664,
        machine_name: 'x86_64',
        image_base: 0x140000000,
        entry_point_rva: 0x1000,
        strategy: ['pdata_runtime_function', 'entry_point_only'],
        count: 2,
        functions: [
          {
            address: '0x140001000',
            rva: 0x1000,
            size: 0x120,
            name: 'sub_140001000',
            is_entry_point: true,
            is_exported: false,
            evidence: ['Recovered from .pdata'],
          },
          {
            address: '0x140001200',
            rva: 0x1200,
            size: 0x80,
            name: 'sub_140001200',
            is_entry_point: false,
            is_exported: false,
            evidence: ['Recovered from .pdata'],
          },
        ],
      },
    })
    const symbolsRecoverHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        machine: 0x8664,
        machine_name: 'x86_64',
        image_base: 0x140000000,
        entry_point_rva: 0x1000,
        primary_runtime: 'rust',
        runtime_hints: ['rust'],
        crate_hints: ['tokio'],
        count: 2,
        symbols: [
          {
            address: '0x140001000',
            rva: 0x1000,
            size: 0x120,
            recovered_name: 'rust_entry_point_00001000',
            confidence: 0.88,
            name_strategy: 'rust_entry_point',
            evidence: ['Matches PE entry point RVA'],
            is_entry_point: true,
            is_exported: false,
          },
          {
            address: '0x140001200',
            rva: 0x1200,
            size: 0x80,
            recovered_name: 'rust_runtime_function_00001200',
            confidence: 0.74,
            name_strategy: 'rust_runtime_function',
            evidence: ['Rust unwind flags observed'],
            is_entry_point: false,
            is_exported: false,
          },
        ],
        warnings: [],
      },
    })

    const handler = createFunctionIndexRecoverWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        smartRecoverHandler,
        symbolsRecoverHandler,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      include_rank_preview: true,
      rank_topk: 4,
      session_tag: 'rust-recover',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.define_from).toBe('symbols_recover')
    expect(data.recovered_function_count).toBe(2)
    expect(data.recovered_symbol_count).toBe(2)
    expect(data.imported_count).toBe(2)
    expect(data.function_index_status).toBe('ready')
    expect(data.decompile_status).toBe('missing')
    expect(data.cfg_status).toBe('missing')
    expect(data.imported_function_preview[0].name).toBe('rust_entry_point_00001000')
    expect(data.recovered_symbol_preview[0].recovered_name).toContain('rust_entry_point')
    expect(data.imported_artifact.path).toContain('reports/function_definitions/')
    expect(data.rank_preview.length).toBeGreaterThan(0)
    expect(data.next_steps.some((item: string) => item.includes('code.functions.list'))).toBe(true)

    const functions = database.findFunctions(sampleId)
    expect(functions.map((item) => item.name)).toContain('rust_entry_point_00001000')
    expect(functions.map((item) => item.name)).toContain('rust_runtime_function_00001200')
  })

  test('should fall back to smart_recover names when symbols recovery fails', async () => {
    const sampleId = 'sha256:' + 'f'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'f'.repeat(64),
      md5: 'f'.repeat(32),
      size: 8192,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    await workspaceManager.createWorkspace(sampleId)

    const smartRecoverHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        machine: 0x8664,
        machine_name: 'x86_64',
        image_base: 0x140000000,
        entry_point_rva: 0x1000,
        strategy: ['pdata_runtime_function'],
        count: 1,
        functions: [
          {
            address: '0x140001000',
            rva: 0x1000,
            size: 0x120,
            name: 'sub_140001000',
            is_entry_point: true,
            is_exported: false,
            evidence: ['Recovered from .pdata'],
          },
        ],
      },
      warnings: ['smart recover warning'],
    })
    const symbolsRecoverHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: false,
      errors: ['symbols failed'],
      warnings: ['symbol recovery warning'],
    })

    const handler = createFunctionIndexRecoverWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        smartRecoverHandler,
        symbolsRecoverHandler,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      include_rank_preview: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.define_from).toBe('smart_recover')
    expect(data.imported_function_preview[0].name).toBe('sub_140001000')
    expect(result.warnings?.some((item) => item.includes('pe.symbols.recover unavailable'))).toBe(true)
  })
})
