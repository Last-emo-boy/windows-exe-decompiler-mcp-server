import { beforeEach, describe, expect, jest, test } from '@jest/globals'
import { createBreakpointSmartHandler } from '../../src/tools/breakpoint-smart.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'

describe('breakpoint.smart tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockCacheManager: jest.Mocked<CacheManager>

  beforeEach(() => {
    mockWorkspaceManager = {} as unknown as jest.Mocked<WorkspaceManager>
    mockDatabase = {
      findSample: jest.fn(),
      findArtifactsByType: jest.fn().mockReturnValue([]),
    } as unknown as jest.Mocked<DatabaseManager>
    mockCacheManager = {} as unknown as jest.Mocked<CacheManager>
  })

  test('should rank breakpoint candidates from crypto findings', async () => {
    mockDatabase.findSample.mockReturnValue({
      id: 'sha256:test',
      sha256: 'a'.repeat(64),
      md5: 'b'.repeat(32),
      size: 4096,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'test',
    } as any)

    const handler = createBreakpointSmartHandler(mockWorkspaceManager, mockDatabase, mockCacheManager, {
      cryptoIdentify: async () => ({
        ok: true,
        data: {
          algorithms: [
            {
              algorithm_family: 'aes',
              algorithm_name: 'AES-CBC',
              mode: 'CBC',
              confidence: 0.9,
              function: 'FUN_140023A50',
              address: '0x140023a50',
              source_apis: ['CryptEncrypt'],
              evidence: [
                {
                  kind: 'import',
                  value: 'CryptEncrypt',
                  source_tool: 'pe.imports.extract',
                  confidence: 0.7,
                },
              ],
              candidate_constants: [],
              dynamic_support: true,
              xref_available: true,
            },
          ],
          source_artifact_refs: [],
        },
      }),
      dynamicDependencies: async () => ({
        ok: true,
        data: {
          available_components: ['frida', 'worker'],
          components: {
            frida: { available: true },
            worker: { available: true },
          },
        },
      }),
      loadDynamicTrace: async () =>
        ({
          observed_apis: ['CryptEncrypt'],
        }) as any,
    })

    const result = await handler({
      sample_id: 'sha256:test',
      persist_artifact: false,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.recommended_breakpoints.length).toBeGreaterThan(0)
    expect(data.runtime_readiness.ready).toBe(true)
    expect(data.recommended_next_tools[0]).toBe('trace.condition')
  })

  test('should keep planning results even when Frida readiness is missing', async () => {
    mockDatabase.findSample.mockReturnValue({
      id: 'sha256:test',
      sha256: 'a'.repeat(64),
      md5: 'b'.repeat(32),
      size: 4096,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'test',
    } as any)

    const handler = createBreakpointSmartHandler(mockWorkspaceManager, mockDatabase, mockCacheManager, {
      cryptoIdentify: async () => ({
        ok: true,
        data: {
          algorithms: [
            {
              algorithm_family: 'windows_cryptoapi',
              algorithm_name: 'Windows CryptoAPI',
              mode: null,
              confidence: 0.78,
              function: null,
              address: null,
              source_apis: ['CryptEncrypt'],
              evidence: [
                {
                  kind: 'import',
                  value: 'CryptEncrypt',
                  source_tool: 'pe.imports.extract',
                  confidence: 0.7,
                },
              ],
              candidate_constants: [],
              dynamic_support: false,
              xref_available: false,
            },
          ],
        },
      }),
      dynamicDependencies: async () => ({
        ok: true,
        data: {
          available_components: [],
          components: {
            frida: { available: false },
            worker: { available: false },
          },
          setup_actions: [{ id: 'install_frida', kind: 'pip_install', required: true, title: 'Install Frida', summary: 'Install Frida' }],
        },
      }),
    })

    const result = await handler({
      sample_id: 'sha256:test',
      persist_artifact: false,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.recommended_breakpoints.some((item: any) => item.kind === 'api_call')).toBe(true)
    expect(data.runtime_readiness.ready).toBe(false)
    expect(data.runtime_readiness.status).toBe('setup_required')
  })
})
