import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import { createBinaryRoleProfileHandler } from '../../src/tools/binary-role-profile.js'

describe('binary.role.profile tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(async () => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-binary-role-profile')
    testDbPath = path.join(process.cwd(), 'test-binary-role-profile.db')
    testCachePath = path.join(process.cwd(), 'test-cache-binary-role-profile')

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

    const sampleId = 'sha256:' + 'b'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'b'.repeat(64),
      md5: 'b'.repeat(32),
      size: 4096,
      file_type: 'PE32 DLL',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const workspace = await workspaceManager.createWorkspace(sampleId)
    fs.writeFileSync(path.join(workspace.original, 'sample.dll'), 'dummy', 'utf-8')
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

  test('should summarize dll/com/service/plugin role indicators', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)
    const handler = createBinaryRoleProfileHandler(workspaceManager, database, cacheManager, {
      exportsHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: {
          exports: [
            { ordinal: 1, address: 4096, name: 'DllGetClassObject' },
            { ordinal: 2, address: 8192, name: 'DllRegisterServer' },
            { ordinal: 3, address: 12288, name: 'InitializePlugin' },
          ],
          forwarders: [
            { ordinal: 4, address: 16384, name: 'ForwardedApi', forwarder: 'KERNEL32.Sleep' },
          ],
          total_exports: 4,
          total_forwarders: 1,
        },
      }),
      importsHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: {
          imports: {
            ole32: ['CoCreateInstance'],
            advapi32: ['StartServiceCtrlDispatcherW', 'SetServiceStatus'],
            ws2_32: ['connect'],
            kernel32: ['GetProcAddress', 'DisableThreadLibraryCalls'],
          },
        },
      }),
      stringsHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: {
          strings: [
            { offset: 1, string: '{12345678-1234-1234-1234-1234567890AB}', encoding: 'ascii' },
            { offset: 2, string: 'ProgID=Acme.Sample.Component', encoding: 'ascii' },
            { offset: 3, string: 'CurrentControlSet\\Services\\AcmeSvc', encoding: 'ascii' },
            { offset: 4, string: 'Plugin host extension', encoding: 'ascii' },
          ],
        },
      }),
      runtimeHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: {
          is_dotnet: false,
          dotnet_version: null,
          target_framework: null,
          suspected: [{ runtime: 'native', confidence: 0.92, evidence: ['imports'] }],
        },
      }),
      packerHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: {
          packed: false,
          confidence: 0.12,
        },
      }),
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.binary_role).toBe('dll')
    expect(data.export_surface.total_exports).toBe(4)
    expect(data.export_surface.com_related_exports).toContain('DllGetClassObject')
    expect(data.export_surface.plugin_related_exports).toContain('InitializePlugin')
    expect(data.import_surface.com_related_imports).toContain('ole32')
    expect(data.import_surface.service_related_imports).toContain('advapi32')
      expect(data.indicators.com_server.likely).toBe(true)
      expect(data.indicators.service_binary.likely).toBe(true)
      expect(data.indicators.plugin_binary.likely).toBe(true)
      expect(data.export_dispatch_profile.registration_exports).toContain('DllRegisterServer')
      expect(data.export_dispatch_profile.likely_dispatch_model).toBe('com_registration_and_class_factory')
      expect(data.lifecycle_surface).toContain('DisableThreadLibraryCalls')
      expect(data.com_profile.class_factory_exports).toContain('DllGetClassObject')
      expect(data.com_profile.class_factory_surface).toContain('DllGetClassObject')
      expect(data.host_interaction_profile.likely_hosted).toBe(true)
      expect(data.host_interaction_profile.callback_surface).toContain('Plugin host extension')
      expect(data.host_interaction_profile.service_hooks).toContain('StartServiceCtrlDispatcherW')
      expect(data.analysis_priorities).toContain('trace_com_activation_and_class_factory_flow')
      expect(data.analysis_priorities).toContain('trace_service_entrypoint_and_scm_lifecycle')
      expect(data.analysis_priorities).toContain('trace_host_plugin_exports_and_callback_model')
      expect(data.analysis_priorities).toContain('review_dllmain_lifecycle_and_attach_detach_side_effects')
    })

  test('should return unified remediation when workspace/original is missing', async () => {
    const sampleId = 'sha256:' + 'c'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'c'.repeat(64),
      md5: 'c'.repeat(32),
      size: 4096,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'test',
    })
    await workspaceManager.createWorkspace(sampleId)

    const handler = createBinaryRoleProfileHandler(workspaceManager, database, cacheManager)
    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample original file is unavailable')
    expect(result.errors?.[0]).toContain('sample.ingest')
  })

  test('should use alternate sibling workspace original when current workspace/original is missing', async () => {
    const baseRoot = path.join(process.cwd(), 'test-binary-role-profile-fallback')
    const currentRoot = path.join(baseRoot, 'reverse', 'workspaces')
    const alternateRoot = path.join(baseRoot, 'workspaces')
    const currentDbPath = path.join(baseRoot, 'fallback.db')
    const currentCachePath = path.join(baseRoot, 'cache')

    if (fs.existsSync(baseRoot)) {
      fs.rmSync(baseRoot, { recursive: true, force: true })
    }

    const localWorkspaceManager = new WorkspaceManager(currentRoot)
    const localDatabase = new DatabaseManager(currentDbPath)
    const localCacheManager = new CacheManager(currentCachePath, localDatabase)

    try {
      const sampleId = 'sha256:' + 'd'.repeat(64)
      localDatabase.insertSample({
        id: sampleId,
        sha256: 'd'.repeat(64),
        md5: 'd'.repeat(32),
        size: 4096,
        file_type: 'PE32 DLL',
        created_at: new Date().toISOString(),
        source: 'test',
      })

      await localWorkspaceManager.createWorkspace(sampleId)

      const alternateOriginalDir = path.join(alternateRoot, 'dd', 'dd', 'd'.repeat(64), 'original')
      fs.mkdirSync(alternateOriginalDir, { recursive: true })
      fs.writeFileSync(path.join(alternateOriginalDir, 'fallback.dll'), 'dummy', 'utf-8')

      const handler = createBinaryRoleProfileHandler(localWorkspaceManager, localDatabase, localCacheManager, {
        exportsHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            exports: [],
            forwarders: [],
            total_exports: 0,
            total_forwarders: 0,
          },
        }),
        importsHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            imports: {},
          },
        }),
        stringsHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            strings: [],
          },
        }),
        runtimeHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            is_dotnet: false,
            dotnet_version: null,
            target_framework: null,
            suspected: [{ runtime: 'native', confidence: 0.8, evidence: ['fallback'] }],
          },
        }),
        packerHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            packed: false,
            confidence: 0.1,
          },
        }),
      })

      const result = await handler({ sample_id: sampleId })

      expect(result.ok).toBe(true)
      expect((result.data as any).original_filename).toBe('fallback.dll')
    } finally {
      try {
        localDatabase.close()
      } catch {
        // ignore
      }
      if (fs.existsSync(baseRoot)) {
        fs.rmSync(baseRoot, { recursive: true, force: true })
      }
    }
  })
})
