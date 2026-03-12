import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import { createRustBinaryAnalyzeHandler } from '../../src/tools/rust-binary-analyze.js'

describe('rust_binary.analyze tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string
  const sampleId = 'sha256:' + '5'.repeat(64)

  beforeEach(async () => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-rust-binary-analyze')
    testDbPath = path.join(process.cwd(), 'test-rust-binary-analyze.db')
    testCachePath = path.join(process.cwd(), 'test-cache-rust-binary-analyze')

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
      sha256: '5'.repeat(64),
      md5: '5'.repeat(32),
      size: 8192,
      file_type: 'PE32+ executable',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const workspace = await workspaceManager.createWorkspace(sampleId)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), 'dummy', 'utf-8')
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

  test('should aggregate runtime, crate, and recovery evidence into a Rust-focused assessment', async () => {
    const handler = createRustBinaryAnalyzeHandler(workspaceManager, database, cacheManager, {
      runtimeHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: {
          is_dotnet: false,
          suspected: [{ runtime: 'rust', confidence: 0.93, evidence: ['cargo strings'] }],
        },
      }),
      stringsHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: {
          strings: [
            {
              offset: 1,
              string: 'C:\\Users\\analyst\\cargo\\registry\\src\\tokio-1.43.0\\src\\runtime\\mod.rs',
              encoding: 'ascii',
            },
            {
              offset: 2,
              string: 'rust_panic at src\\main.rs',
              encoding: 'ascii',
            },
            {
              offset: 3,
              string: 'iced-x86 disassembly backend initialized',
              encoding: 'ascii',
            },
          ],
        },
      }),
      smartRecoverHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: {
          count: 12,
          strategy: ['pdata_runtime_functions', 'entry_point'],
        },
      }),
      symbolsRecoverHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: {
          primary_runtime: 'rust',
          runtime_hints: ['rust'],
          crate_hints: ['tokio', 'iced-x86'],
          count: 12,
          symbols: [
            {
              address: '0x140001000',
              recovered_name: 'rust_entry_point_00001000',
              name_strategy: 'rust_entry_point',
              confidence: 0.92,
            },
            {
              address: '0x140001120',
              recovered_name: 'rust_runtime_function_00001120',
              name_strategy: 'rust_runtime_function',
              confidence: 0.76,
            },
          ],
        },
      }),
      binaryRoleHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: {
          sample_id: sampleId,
          original_filename: 'sample.exe',
          binary_role: 'executable',
          role_confidence: 0.87,
          runtime_hint: {
            is_dotnet: false,
            dotnet_version: null,
            target_framework: null,
            primary_runtime: 'rust',
          },
          export_surface: {
            total_exports: 0,
            total_forwarders: 0,
            notable_exports: [],
            com_related_exports: [],
            service_related_exports: [],
            plugin_related_exports: [],
            forwarded_exports: [],
          },
          import_surface: {
            dll_count: 2,
            notable_dlls: ['KERNEL32.dll'],
            com_related_imports: [],
            service_related_imports: [],
            network_related_imports: [],
            process_related_imports: ['KERNEL32.dll'],
          },
          packed: false,
          packing_confidence: 0.1,
          indicators: {
            com_server: { likely: false, confidence: 0.1, evidence: [] },
            service_binary: { likely: false, confidence: 0.1, evidence: [] },
            plugin_binary: { likely: false, confidence: 0.1, evidence: [] },
            driver_binary: { likely: false, confidence: 0.1, evidence: [] },
          },
          analysis_priorities: ['review_process_manipulation_and_dynamic_resolution_paths'],
          strings_considered: 3,
        },
      }),
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.suspected_rust).toBe(true)
    expect(data.primary_runtime).toBe('rust')
    expect(data.runtime_hints).toContain('rust')
    expect(data.cargo_paths[0]).toContain('cargo')
    expect(data.rust_markers[0]).toContain('rust_panic')
    expect(data.crate_hints).toContain('tokio')
    expect(data.library_profile.top_crates).toContain('tokio')
    expect(data.library_profile.notable_libraries).toContain('iced-x86')
    expect(data.recovered_function_count).toBe(12)
    expect(data.recovered_symbol_count).toBe(12)
    expect(data.recovered_symbol_preview[0].recovered_name).toBe('rust_entry_point_00001000')
    expect(data.components.runtime_detect.ok).toBe(true)
    expect(data.components.symbols_recover.ok).toBe(true)
    expect(data.importable_with_code_functions_define).toBe(true)
    expect(data.analysis_priorities).toContain('feed_recovered_boundaries_into_code.functions.define')
    expect(data.next_steps.some((item: string) => item.includes('code.functions.define'))).toBe(true)
    expect(data.binary_profile.binary_role).toBe('executable')
    expect(data.confidence).toBeGreaterThan(0.7)
  })

  test('should surface downstream tool failures as warnings instead of silently returning an empty profile', async () => {
    const handler = createRustBinaryAnalyzeHandler(workspaceManager, database, cacheManager, {
      runtimeHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: false,
        errors: ['runtime worker unavailable'],
      }),
      stringsHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: false,
        errors: ['strings worker failed'],
      }),
      smartRecoverHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: false,
        errors: ['no runtime functions recovered'],
      }),
      symbolsRecoverHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: false,
        errors: ['symbol recovery skipped'],
      }),
      binaryRoleHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: false,
        errors: ['binary role unavailable'],
      }),
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(true)
    expect(result.warnings).toContain('runtime error: runtime worker unavailable')
    expect(result.warnings).toContain('strings error: strings worker failed')
    const data = result.data as any
    expect(data.components.runtime_detect.ok).toBe(false)
    expect(data.components.binary_role_profile.ok).toBe(false)
    expect(data.confidence).toBe(0.08)
  })
})
