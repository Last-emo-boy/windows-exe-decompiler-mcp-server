import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import { createComRoleProfileHandler } from '../../src/tools/com-role-profile.js'

describe('com.role.profile tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(async () => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-com-role-profile')
    testDbPath = path.join(process.cwd(), 'test-com-role-profile.db')
    testCachePath = path.join(process.cwd(), 'test-cache-com-role-profile')

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

    const sampleId = 'sha256:' + 'f'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'f'.repeat(64),
      md5: 'f'.repeat(32),
      size: 4096,
      file_type: 'PE32 DLL',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const workspace = await workspaceManager.createWorkspace(sampleId)
    fs.writeFileSync(path.join(workspace.original, 'com.dll'), 'dummy', 'utf-8')
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

  test('should project COM activation and registration hints', async () => {
    const sampleId = 'sha256:' + 'f'.repeat(64)
    const handler = createComRoleProfileHandler(workspaceManager, database, cacheManager, {
      binaryRoleProfileHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: {
          sample_id: sampleId,
          original_filename: 'com.dll',
          binary_role: 'dll',
          role_confidence: 0.89,
          runtime_hint: {
            is_dotnet: false,
            dotnet_version: null,
            target_framework: null,
            primary_runtime: 'native',
          },
          export_surface: {
            total_exports: 3,
            total_forwarders: 0,
            notable_exports: ['DllGetClassObject', 'DllRegisterServer'],
            com_related_exports: ['DllGetClassObject'],
            service_related_exports: [],
            plugin_related_exports: [],
            forwarded_exports: [],
          },
          import_surface: {
            dll_count: 2,
            notable_dlls: ['ole32.dll', 'oleaut32.dll'],
            com_related_imports: ['ole32', 'oleaut32'],
            service_related_imports: [],
            network_related_imports: [],
            process_related_imports: [],
          },
          packed: false,
          packing_confidence: 0.1,
          indicators: {
            com_server: { likely: true, confidence: 0.88, evidence: ['export:DllGetClassObject'] },
            service_binary: { likely: false, confidence: 0.1, evidence: [] },
            plugin_binary: { likely: false, confidence: 0.2, evidence: [] },
            driver_binary: { likely: false, confidence: 0.05, evidence: [] },
          },
          export_dispatch_profile: {
            command_like_exports: [],
            callback_like_exports: [],
            registration_exports: ['DllRegisterServer'],
            ordinal_only_exports: 0,
            likely_dispatch_model: 'com_registration_and_class_factory',
            confidence: 0.81,
          },
          com_profile: {
            clsid_strings: ['{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}'],
            progid_strings: ['Acme.Component'],
            interface_hints: ['IClassFactory', 'IUnknown'],
            registration_strings: ['InprocServer32'],
            class_factory_exports: ['DllGetClassObject'],
            confidence: 0.9,
          },
          host_interaction_profile: {
            likely_hosted: false,
            host_hints: [],
            callback_exports: [],
            callback_strings: [],
            service_hooks: [],
            confidence: 0.18,
          },
          analysis_priorities: ['trace_com_activation_and_class_factory_flow'],
          strings_considered: 20,
        },
      }),
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.likely_com_server).toBe(true)
    expect(data.activation_model).toBe('inproc_class_factory')
    expect(data.class_factory_exports).toContain('DllGetClassObject')
    expect(data.registration_exports).toContain('DllRegisterServer')
    expect(data.class_factory_surface.class_factory_exports).toContain('DllGetClassObject')
    expect(data.activation_steps.some((item: string) => item.includes('InprocServer32'))).toBe(true)
    expect(data.analysis_priorities).toContain('trace_com_activation_and_class_factory_flow')
  })
})
