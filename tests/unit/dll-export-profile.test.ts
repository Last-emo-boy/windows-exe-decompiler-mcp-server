import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import { createDllExportProfileHandler } from '../../src/tools/dll-export-profile.js'

describe('dll.export.profile tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(async () => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-dll-export-profile')
    testDbPath = path.join(process.cwd(), 'test-dll-export-profile.db')
    testCachePath = path.join(process.cwd(), 'test-cache-dll-export-profile')

    for (const target of [testWorkspaceRoot, testCachePath]) {
      if (fs.existsSync(target)) {
        fs.rmSync(target, { recursive: true, force: true })
      }
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
    cacheManager = new CacheManager(testCachePath, database)

    const sampleId = 'sha256:' + 'e'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'e'.repeat(64),
      md5: 'e'.repeat(32),
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
    for (const target of [testWorkspaceRoot, testCachePath]) {
      if (fs.existsSync(target)) {
        fs.rmSync(target, { recursive: true, force: true })
      }
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
  })

  test('should project DLL-specific export, lifecycle, and host interaction hints', async () => {
    const sampleId = 'sha256:' + 'e'.repeat(64)
    const handler = createDllExportProfileHandler(workspaceManager, database, cacheManager, {
      binaryRoleProfileHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: {
          sample_id: sampleId,
          original_filename: 'sample.dll',
          binary_role: 'dll',
          role_confidence: 0.93,
          runtime_hint: {
            is_dotnet: false,
            dotnet_version: null,
            target_framework: null,
            primary_runtime: 'native',
          },
          export_surface: {
            total_exports: 5,
            total_forwarders: 1,
            notable_exports: ['DllGetClassObject', 'DllRegisterServer', 'InitializePlugin'],
            com_related_exports: ['DllGetClassObject'],
            service_related_exports: [],
            plugin_related_exports: ['InitializePlugin'],
            forwarded_exports: ['ForwardedApi -> KERNEL32.Sleep'],
          },
          import_surface: {
            dll_count: 2,
            notable_dlls: ['kernel32.dll', 'ole32.dll'],
            com_related_imports: ['ole32'],
            service_related_imports: [],
            network_related_imports: [],
            process_related_imports: ['kernel32'],
          },
          packed: false,
          packing_confidence: 0.1,
          indicators: {
            com_server: { likely: true, confidence: 0.82, evidence: ['export:DllGetClassObject'] },
            service_binary: { likely: false, confidence: 0.1, evidence: [] },
            plugin_binary: { likely: true, confidence: 0.71, evidence: ['export:InitializePlugin'] },
            driver_binary: { likely: false, confidence: 0.05, evidence: [] },
          },
          export_dispatch_profile: {
            command_like_exports: ['InvokeCommand'],
            callback_like_exports: ['InitializePlugin'],
            registration_exports: ['DllRegisterServer'],
            ordinal_only_exports: 0,
            likely_dispatch_model: 'com_registration_and_class_factory',
            confidence: 0.78,
          },
          com_profile: {
            clsid_strings: ['{12345678-1234-1234-1234-1234567890AB}'],
            progid_strings: ['Acme.Plugin.Component'],
            interface_hints: ['IClassFactory'],
            registration_strings: ['InprocServer32'],
            class_factory_exports: ['DllGetClassObject'],
            confidence: 0.84,
          },
          host_interaction_profile: {
            likely_hosted: true,
            host_hints: ['Plugin host extension'],
            callback_exports: ['InitializePlugin'],
            callback_strings: ['plugin host'],
            service_hooks: [],
            confidence: 0.67,
          },
          analysis_priorities: ['trace_export_surface_first'],
          strings_considered: 12,
        },
      }),
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.library_like).toBe(true)
    expect(data.likely_entry_model).toBe('registration_and_class_factory')
    expect(data.dll_entry_hints.some((item: string) => item.includes('DllRegisterServer'))).toBe(true)
    expect(data.lifecycle_surface.lifecycle_imports).toContain('kernel32')
    expect(data.class_factory_surface.class_factory_exports).toContain('DllGetClassObject')
    expect(data.callback_surface.callback_exports).toContain('InitializePlugin')
    expect(data.analysis_priorities).toContain('review_dllmain_lifecycle_and_attach_detach_side_effects')
  })
})
