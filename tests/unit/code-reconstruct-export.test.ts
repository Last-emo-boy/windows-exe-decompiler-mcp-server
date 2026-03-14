/**
 * Unit tests for code.reconstruct.export tool
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import {
  createCodeReconstructExportHandler,
  CodeReconstructExportInputSchema,
} from '../../src/tools/code-reconstruct-export.js'
import {
  persistSemanticFunctionExplanationsArtifact,
  persistSemanticModuleReviewsArtifact,
  persistSemanticNameSuggestionsArtifact,
} from '../../src/semantic-name-suggestion-artifacts.js'

describe('code.reconstruct.export tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-reconstruct-export')
    testDbPath = path.join(process.cwd(), 'test-reconstruct-export.db')
    testCachePath = path.join(process.cwd(), 'test-cache-reconstruct-export')

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

  async function setupSample(sampleId: string, hashChar: string) {
    database.insertSample({
      id: sampleId,
      sha256: hashChar.repeat(64),
      md5: hashChar.repeat(32),
      size: 2048,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })
    await workspaceManager.createWorkspace(sampleId)
  }

  function buildReconstructResult(): WorkerResult {
    return {
      ok: true,
      data: {
        functions: [
          {
            function: 'net_init',
            address: '0x401000',
            confidence: 0.82,
            gaps: ['unresolved_function_symbols'],
            behavior_tags: ['networking'],
            semantic_summary: 'Likely handles network communication and dispatches InternetOpenA.',
            xref_signals: [
              {
                api: 'InternetOpenA',
                provenance: 'static_named_call',
                confidence: 0.78,
                evidence: ['callee:InternetOpenA'],
              },
            ],
            call_context: {
              callers: [],
              callees: ['InternetOpenA@0x500000'],
            },
            call_relationships: {
              callers: [],
              callees: [
                {
                  target: 'resolver_stub@0x401050',
                  relation_types: ['tail_jump_hint'],
                  reference_types: ['UNCONDITIONAL_JUMP'],
                  resolved_by: null,
                  is_exact: false,
                },
                {
                  target: 'InternetOpenA@0x500000',
                  relation_types: ['direct_call_body'],
                  reference_types: ['UNCONDITIONAL_CALL'],
                  resolved_by: null,
                  is_exact: true,
                },
              ],
            },
            source_like_snippet:
              '// function=net_init confidence=0.82 gaps=unresolved_function_symbols\nint net_init(void){return 0;}',
            rank_reasons: ['calls_sensitive_api:InternetOpenA'],
          },
          {
            function: 'file_worker',
            address: '0x402000',
            confidence: 0.64,
            gaps: [],
            behavior_tags: ['file_io'],
            semantic_summary: 'Likely handles file system operations.',
            xref_signals: [],
            call_context: {
              callers: ['core_main@0x403000'],
              callees: ['CreateFileW@0x500100'],
            },
            source_like_snippet:
              '// function=file_worker confidence=0.64 gaps=none\nint file_worker(void){return 1;}',
            rank_reasons: ['high_callers'],
          },
          {
            function: 'core_main',
            address: '0x403000',
            confidence: 0.55,
            gaps: ['missing_cfg'],
            behavior_tags: [],
            semantic_summary: 'Partial semantic recovery for core_main.',
            xref_signals: [],
            call_context: {
              callers: [],
              callees: ['file_worker@0x402000'],
            },
            source_like_snippet:
              '// function=core_main confidence=0.55 gaps=missing_cfg\nint core_main(void){return 2;}',
            rank_reasons: [],
          },
        ],
      },
    }
  }

  function buildBinaryMetadataDependencies(options?: {
    exportsData?: Record<string, unknown>
    packerData?: Record<string, unknown>
    exportsOk?: boolean
    packerOk?: boolean
  }) {
    const exportsExtractHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue(
        options?.exportsOk === false
          ? {
              ok: false,
              errors: ['exports worker unavailable'],
            }
          : {
              ok: true,
              data: options?.exportsData || {
                exports: [],
                forwarders: [],
                total_exports: 0,
                total_forwarders: 0,
              },
            }
      )

    const packerDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue(
        options?.packerOk === false
          ? {
              ok: false,
              errors: ['packer worker unavailable'],
            }
          : {
              ok: true,
              data: options?.packerData || {
                packed: false,
                confidence: 0.05,
                detected: [],
              },
            }
      )

    return {
      exportsExtractHandler,
      packerDetectHandler,
    }
  }

  test('should apply input defaults', () => {
    const parsed = CodeReconstructExportInputSchema.parse({
      sample_id: 'sha256:' + 'a'.repeat(64),
    })

    expect(parsed.topk).toBe(12)
    expect(parsed.module_limit).toBe(6)
    expect(parsed.min_module_size).toBe(2)
    expect(parsed.include_imports).toBe(true)
    expect(parsed.include_strings).toBe(true)
    expect(parsed.validate_build).toBe(true)
    expect(parsed.run_harness).toBe(true)
    expect(parsed.build_timeout_ms).toBe(60000)
    expect(parsed.run_timeout_ms).toBe(30000)
    expect(parsed.evidence_scope).toBe('all')
    expect(parsed.semantic_scope).toBe('all')
    expect(parsed.reuse_cached).toBe(true)
  })

  test('should require evidence_session_tag when evidence_scope=session', () => {
    expect(() =>
      CodeReconstructExportInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        evidence_scope: 'session',
      })
    ).toThrow('evidence_session_tag')
  })

  test('should require semantic_session_tag when semantic_scope=session', () => {
    expect(() =>
      CodeReconstructExportInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        semantic_scope: 'session',
      })
    ).toThrow('semantic_session_tag')
  })

  test('should return error when sample does not exist', async () => {
    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager
    )

    const result = await handler({
      sample_id: 'sha256:' + 'f'.repeat(64),
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should export module skeleton and gaps report', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    await setupSample(sampleId, '1')

    const reconstructFunctionsHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue(buildReconstructResult())
    const importsExtractHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          imports: {
            'ws2_32.dll': ['connect'],
            'kernel32.dll': ['CreateFileW'],
          },
        },
      })
    const stringsExtractHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          summary: {
            top_high_value: [
              { string: 'http://example.com/c2', categories: ['url', 'network'] },
              { string: 'HKCU\\Software\\X', categories: ['registry'] },
            ],
          },
        },
      })
    const runtimeEvidenceLoader = jest
      .fn<
        (
          sampleId: string,
          options?: {
            evidenceScope?: 'all' | 'latest' | 'session'
            sessionTag?: string
          }
        ) => Promise<any>
      >()
      .mockResolvedValue({
        artifact_count: 1,
        executed: true,
        executed_artifact_count: 1,
        api_count: 3,
        memory_region_count: 1,
        stage_count: 2,
        observed_apis: ['InternetOpenA', 'CreateFileW', 'GetProcAddress'],
        high_signal_apis: ['CreateFileW', 'GetProcAddress'],
        memory_regions: ['process_operation_plan'],
        stages: ['file_operations', 'resolve_dynamic_apis'],
        risk_hints: [],
        source_formats: ['sandbox_trace'],
        evidence_kinds: ['trace'],
        source_names: ['speakeasy-live'],
        evidence: ['Runtime evidence observed InternetOpenA and CreateFileW'],
        summary: 'Imported runtime evidence from 1 artifact(s) observed 3 API(s).',
      })

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler,
        importsExtractHandler,
        stringsExtractHandler,
        runtimeEvidenceLoader,
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      topk: 8,
      module_limit: 4,
      min_module_size: 1,
      export_name: 'manual_export',
      evidence_scope: 'session',
      evidence_session_tag: 'runtime-alpha',
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    expect(runtimeEvidenceLoader).toHaveBeenCalledWith(sampleId, {
      evidenceScope: 'session',
      sessionTag: 'runtime-alpha',
    })
    expect(reconstructFunctionsHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: sampleId,
        topk: 8,
        include_xrefs: true,
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
      })
    )
    expect(stringsExtractHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: sampleId,
        category_filter: 'all',
      })
    )
    const data = result.data as any
    expect(data.module_count).toBeGreaterThan(0)
    expect(data.manifest_path).toContain('manifest.json')
    expect(data.gaps_path).toContain('gaps.md')
    expect(data.notes_path).toContain('reverse_notes.md')
    expect(data.binary_profile).toBeDefined()
    expect(data.runtime_evidence).toBeDefined()
    expect(data.runtime_evidence.observed_apis).toContain('InternetOpenA')
    expect(Array.isArray(data.modules)).toBe(true)
    expect(result.artifacts?.length).toBeGreaterThanOrEqual(5)
    expect(result.artifacts?.some((artifact: any) => artifact.type === 'ghidra_pseudocode')).toBe(
      true
    )
    expect(result.artifacts?.some((artifact: any) => artifact.type === 'report')).toBe(true)
    expect(result.artifacts?.some((artifact: any) => artifact.type === 'reconstruct_notes')).toBe(
      true
    )
    expect(result.artifacts?.some((artifact: any) => artifact.type === 'reconstruct_rewrite')).toBe(
      true
    )

    const workspace = await workspaceManager.getWorkspace(sampleId)
    const manifestAbs = path.join(workspace.root, data.manifest_path)
    const gapsAbs = path.join(workspace.root, data.gaps_path)
    const notesAbs = path.join(workspace.root, data.notes_path)
    expect(fs.existsSync(manifestAbs)).toBe(true)
    expect(fs.existsSync(gapsAbs)).toBe(true)
    expect(fs.existsSync(notesAbs)).toBe(true)

    const manifestObj = JSON.parse(fs.readFileSync(manifestAbs, 'utf-8'))
    expect(manifestObj.module_count).toBeGreaterThan(0)
    expect(Array.isArray(manifestObj.modules)).toBe(true)
    expect(manifestObj.modules[0].rewrite_path).toContain('.rewrite.c')

    const gapsContent = fs.readFileSync(gapsAbs, 'utf-8')
    expect(gapsContent).toContain('# gaps.md')
    expect(gapsContent).toContain('Function Gaps')

    const notesContent = fs.readFileSync(notesAbs, 'utf-8')
    expect(notesContent).toContain('## Binary Profile')
    expect(notesContent).toContain('## Runtime Evidence')
    expect(notesContent).toContain('InternetOpenA')

    const rewriteContents = data.modules.map((module: any) => {
      const rewriteAbs = path.join(workspace.root, module.rewrite_path)
      expect(fs.existsSync(rewriteAbs)).toBe(true)
      return fs.readFileSync(rewriteAbs, 'utf-8')
    })
    expect(rewriteContents.some((content: string) => content.includes('annotated rewrite'))).toBe(
      true
    )
    expect(rewriteContents.some((content: string) => content.includes('inferred_role'))).toBe(
      true
    )
    expect(rewriteContents.some((content: string) => content.includes('runtime_context'))).toBe(
      true
    )
    expect(rewriteContents.some((content: string) => content.includes('sources=sandbox_trace:trace'))).toBe(
      true
    )
    expect(rewriteContents.some((content: string) => content.includes('executed=yes'))).toBe(
      true
    )
    expect(rewriteContents.some((content: string) => content.includes('relation_hints'))).toBe(
      true
    )
    expect(rewriteContents.some((content: string) => content.includes('tail_jump_hint'))).toBe(
      true
    )
  })

  test('should capture native build and harness validation artifacts in export output', async () => {
    const sampleId = 'sha256:' + 'd'.repeat(64)
    await setupSample(sampleId, 'd')

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue(buildReconstructResult()),
        stringsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: { summary: { top_high_value: [] } },
        }),
        nativeBuildValidator: jest
          .fn<
            (
              args: {
                exportRoot: string
                srcRoot: string
                moduleRewriteFiles: string[]
                compilerPath?: string | null
                timeoutMs: number
              }
            ) => Promise<any>
          >()
          .mockImplementation(async ({
            exportRoot,
            srcRoot: _srcRoot,
            moduleRewriteFiles: _moduleRewriteFiles,
            compilerPath: _compilerPath,
            timeoutMs: _timeoutMs,
          }) => {
          const executablePath = path.join(exportRoot, 'reconstruct_harness.exe')
          fs.writeFileSync(executablePath, 'MZ')
          return {
            attempted: true,
            status: 'passed' as const,
            compiler: 'clang',
            compiler_path: 'E:/clang/bin/clang.exe',
            command: '"clang" -std=c99',
            exit_code: 0,
            timed_out: false,
            error: null,
            stdout: 'build ok',
            stderr: '',
            log_path: null,
            executable_path: executablePath,
          }
        }),
        harnessValidator: jest
          .fn<
            (
              args: {
                executablePath: string
                cwd: string
                timeoutMs: number
              }
            ) => Promise<any>
          >()
          .mockImplementation(async ({ executablePath, cwd: _cwd, timeoutMs: _timeoutMs }) => ({
            attempted: true,
            status: 'passed' as const,
            command: `"${executablePath}"`,
            exit_code: 0,
            timed_out: false,
            error: null,
            stdout:
              '[process_ops] FUN_1 => status=0 stage=remote_memory_transfer expected=remote_memory_transfer match=ok detail=none',
            stderr: '',
            log_path: null,
            matched_entries: 1,
            mismatched_entries: 0,
          })),
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'validated_export',
      min_module_size: 1,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.build_validation.status).toBe('passed')
    expect(data.build_validation.compiler).toBe('clang')
    expect(data.build_validation.log_path).toContain('BUILD_VALIDATION.log')
    expect(data.build_validation.executable_path).toContain('reconstruct_harness.exe')
    expect(data.harness_validation.status).toBe('passed')
    expect(data.harness_validation.log_path).toContain('HARNESS_VALIDATION.log')
    expect(data.harness_validation.matched_entries).toBe(1)
    expect(result.artifacts?.some((artifact: any) => artifact.type === 'reconstruct_build_log')).toBe(
      true
    )
    expect(result.artifacts?.some((artifact: any) => artifact.type === 'reconstruct_run_log')).toBe(
      true
    )
    expect(
      result.artifacts?.some((artifact: any) => artifact.type === 'reconstruct_harness_binary')
    ).toBe(true)

    const workspace = await workspaceManager.getWorkspace(sampleId)
    const buildLogAbs = path.join(workspace.root, data.build_validation.log_path)
    const harnessLogAbs = path.join(workspace.root, data.harness_validation.log_path)
    const exeAbs = path.join(workspace.root, data.build_validation.executable_path)
    expect(fs.existsSync(buildLogAbs)).toBe(true)
    expect(fs.existsSync(harnessLogAbs)).toBe(true)
    expect(fs.existsSync(exeAbs)).toBe(true)

    const notesAbs = path.join(workspace.root, data.notes_path)
    const notesContent = fs.readFileSync(notesAbs, 'utf-8')
    expect(notesContent).toContain('## Native Validation')
    expect(notesContent).toContain('build: status=passed')
    expect(notesContent).toContain('harness: status=passed')
  })

  test('should dedupe duplicate reconstructed functions before emitting rewrite entries', async () => {
    const sampleId = 'sha256:' + 'e'.repeat(64)
    await setupSample(sampleId, 'e')

    const duplicateFunction = {
      function: 'entrypoint_fallback',
      address: '0x14013fab0',
      confidence: 0.33,
      gaps: ['missing_cfg'],
      behavior_tags: [],
      semantic_summary: 'Partial semantic recovery for entrypoint_fallback; analysis gaps remain: missing_cfg.',
      xref_signals: [],
      call_context: {
        callers: [],
        callees: [],
      },
      source_like_snippet: [
        '// function=entrypoint_fallback confidence=0.33 gaps=missing_cfg',
        '// strings: Packer Detection UPX VMProtect',
        'int entrypoint_fallback(void){return 0;}',
      ].join('\n'),
      rank_reasons: ['high_callers'],
    }

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            functions: [duplicateFunction, duplicateFunction, { ...duplicateFunction }],
          },
        }),
        stringsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            summary: {
              top_high_value: [{ string: '@Packer/Protector Detection', categories: ['command'] }],
            },
          },
        }),
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'dedupe_export',
      min_module_size: 1,
      validate_build: false,
      run_harness: false,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const packerModule = data.modules.find((module: any) => module.name === 'packer_analysis')
    expect(packerModule.function_count).toBe(1)

    const rewrite = fs.readFileSync(path.join(workspace.root, packerModule.rewrite_path), 'utf-8')
    expect((rewrite.match(/int scan_packer_signatures_14013fab0\(/g) || []).length).toBe(1)
    expect((rewrite.match(/int entrypoint_fallback\(void\)/g) || []).length).toBe(1)
  })

  test('should use string reverse lookup to recover packer_analysis module membership', async () => {
    const sampleId = 'sha256:' + '9'.repeat(64)
    await setupSample(sampleId, '9')
    database.insertAnalysis({
      id: 'ghidra-ready-export',
      sample_id: sampleId,
      stage: 'ghidra',
      backend: 'ghidra',
      status: 'done',
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      output_json: JSON.stringify({
        project_path: 'C:/ghidra/project',
        project_key: 'project',
        readiness: {
          function_index: { available: true, status: 'ready' },
          decompile: { available: true, status: 'ready', target: '0x404000' },
          cfg: { available: true, status: 'ready', target: '0x404000' },
        },
      }),
      metrics_json: JSON.stringify({}),
    })

    const reconstructFunctionsHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          functions: [
            {
              function: 'FUN_14000f8f0',
              address: '0x404000',
              confidence: 0.71,
              gaps: [],
              behavior_tags: [],
              semantic_summary: 'Partial semantic recovery for packer routine.',
              xref_signals: [],
              call_context: {
                callers: [],
                callees: [],
              },
              source_like_snippet:
                '// function=FUN_14000f8f0 confidence=0.71 gaps=none\nint FUN_14000f8f0(void){return 0;}',
              rank_reasons: [],
            },
          ],
        },
      })
    const stringsExtractHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          summary: {
            top_high_value: [
              { string: 'Packer Detection', categories: ['command'] },
            ],
            context_windows: [
              {
                start_offset: 0x1200,
                end_offset: 0x1260,
                score: 8.2,
                categories: ['command'],
                strings: [
                  {
                    offset: 0x1200,
                    string: 'Packer Detection',
                    encoding: 'ascii',
                    categories: ['command'],
                  },
                ],
              },
            ],
          },
        },
      })
    const searchFunctions = jest
      .fn<
        (
          sampleId: string,
          options: {
            apiQuery?: string
            stringQuery?: string
            limit?: number
            timeout?: number
          }
        ) => Promise<any>
      >()
      .mockResolvedValue({
        query: {
          string: 'Packer Detection',
          limit: 6,
        },
        matches: [
          {
            function: 'FUN_14000f8f0',
            address: '0x404000',
            caller_count: 0,
            callee_count: 0,
            string_matches: [
              {
                value: 'Packer Detection',
                data_address: '0x18001200',
                referenced_from: '0x404020',
              },
            ],
            match_types: ['string_reference'],
          },
        ],
        count: 1,
      })

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler,
        importsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: { imports: {} },
        }),
        stringsExtractHandler,
        searchFunctions,
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'string_linked_export',
      min_module_size: 1,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.modules.some((module: any) => module.name === 'packer_analysis')).toBe(true)
    expect(data.modules.find((module: any) => module.name === 'packer_analysis')?.string_hints).toContain(
      'Packer Detection'
    )
    expect(searchFunctions).toHaveBeenCalledWith(
      sampleId,
      expect.objectContaining({
        stringQuery: 'Packer Detection',
      })
    )
  })

  test('should preserve DLL and COM role-aware modules even when they are smaller than min_module_size', async () => {
    const sampleId = 'sha256:' + 'd'.repeat(64)
    await setupSample(sampleId, 'd')

    const reconstructFunctionsHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          functions: [
            {
              function: 'dll_entry_handler',
              address: '0x500000',
              confidence: 0.74,
              gaps: [],
              behavior_tags: [],
              semantic_summary: 'Handles DLL process attach/detach and calls DisableThreadLibraryCalls during initialization.',
              xref_signals: [
                {
                  api: 'DisableThreadLibraryCalls',
                  provenance: 'static_named_call',
                  confidence: 0.8,
                  evidence: ['callee:DisableThreadLibraryCalls'],
                },
              ],
              call_context: { callers: [], callees: [] },
              runtime_context: {
                corroborated_apis: ['DisableThreadLibraryCalls'],
                corroborated_stages: ['dll_lifecycle'],
                notes: ['Runtime segment hints indicate DLL attach/detach state.'],
                confidence: 0.77,
                executed: false,
                matched_memory_regions: ['dll_lifecycle_state'],
                matched_protections: ['r-x_image'],
                matched_region_owners: ['sample.dll'],
                matched_observed_modules: ['sample.dll'],
                matched_segment_names: ['.tls'],
                matched_address_ranges: ['0x500000-0x500180'],
                suggested_modules: ['dll_lifecycle'],
                matched_by: ['semantic_summary'],
              },
              source_like_snippet: 'int dll_entry_handler(void){return 0;}',
              rank_reasons: [],
            },
            {
              function: 'class_factory_entry',
              address: '0x500100',
              confidence: 0.81,
              gaps: [],
              behavior_tags: [],
              semantic_summary: 'Implements DllGetClassObject and IClassFactory activation for InprocServer32 registration.',
              xref_signals: [],
              call_context: { callers: [], callees: [] },
              runtime_context: {
                corroborated_apis: ['CoCreateInstance'],
                corroborated_stages: ['com_activation', 'export_dispatch'],
                notes: ['Observed COM activation metadata in runtime import set.'],
                confidence: 0.83,
                executed: false,
                matched_memory_regions: ['class_factory_surface'],
                matched_protections: ['r-x_image'],
                matched_region_owners: ['ole32.dll'],
                matched_observed_modules: ['ole32.dll', 'sample.dll'],
                matched_segment_names: ['.edata'],
                matched_address_ranges: ['0x500100-0x5002a0'],
                suggested_modules: ['com_activation', 'export_dispatch'],
                matched_by: ['semantic_summary', 'string_hint'],
              },
              source_like_snippet: 'int class_factory_entry(void){return 1;}',
              rank_reasons: ['string_context:DllGetClassObject'],
            },
            {
              function: 'plugin_callback_entry',
              address: '0x500200',
              confidence: 0.69,
              gaps: [],
              behavior_tags: [],
              semantic_summary: 'Registers plugin callbacks and notifies the host extension entrypoint.',
              xref_signals: [],
              call_context: { callers: [], callees: [] },
              runtime_context: {
                corroborated_apis: [],
                corroborated_stages: ['callback_surface'],
                notes: ['Observed plugin host callback strings.'],
                confidence: 0.7,
                executed: false,
                matched_memory_regions: ['callback_surface'],
                matched_protections: ['r-x_image'],
                matched_region_owners: ['plugin_host.dll'],
                matched_observed_modules: ['plugin_host.dll'],
                matched_segment_names: ['callback_dispatch'],
                matched_address_ranges: ['0x500200-0x500260'],
                suggested_modules: ['callback_surface'],
                matched_by: ['string_hint'],
              },
              source_like_snippet: 'int plugin_callback_entry(void){return 2;}',
              rank_reasons: ['string_context:InitializePlugin'],
            },
          ],
        },
      })

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler,
        importsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            imports: {
              'kernel32.dll': ['DisableThreadLibraryCalls'],
              'ole32.dll': ['CoCreateInstance'],
            },
          },
        }),
        stringsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            summary: {
              top_high_value: [
                { string: 'DllGetClassObject', categories: ['command'] },
                { string: 'InprocServer32', categories: ['command'] },
                { string: 'InitializePlugin callback', categories: ['command'] },
              ],
            },
          },
        }),
        searchFunctions: jest.fn<(sampleId: string, options: any) => Promise<any>>().mockResolvedValue({
          ok: true,
          matches: [],
          count: 0,
        }) as any,
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'role_aware_dll_com_export',
      min_module_size: 2,
      validate_build: false,
      run_harness: false,
      role_target: 'com_server',
      role_focus_areas: [
        'class_factory_and_registration',
        'host_callbacks_and_attach_detach',
        'dll_entry_lifecycle',
      ],
      role_priority_order: [
        'trace_com_activation_and_class_factory_flow',
        'identify_host_callbacks_and_extension_contract',
        'review_dllmain_lifecycle_and_attach_detach_side_effects',
      ],
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.modules.some((module: any) => module.name === 'dll_lifecycle')).toBe(true)
    expect(data.modules.some((module: any) => module.name === 'com_activation')).toBe(true)
    expect(data.modules.some((module: any) => module.name === 'callback_surface')).toBe(true)

    const comModule = data.modules.find((module: any) => module.name === 'com_activation')
    expect(comModule.role_hint).toContain('COM activation')
    expect(comModule.focus_matches).toContain('target:com_server')
    expect(
      comModule.focus_matches.some((item: string) => item.includes('class_factory_and_registration'))
    ).toBe(true)
    const rewrite = fs.readFileSync(path.join((await workspaceManager.getWorkspace(sampleId)).root, comModule.rewrite_path), 'utf-8')
    expect(rewrite).toContain('COM Activation Surface')
    expect(rewrite).toContain('role_focus: target:com_server')
    expect(rewrite).toContain('prioritized_functions: class_factory_entry')
    expect(rewrite).toContain('owners=ole32.dll')
    expect(rewrite).toContain('segments=.edata')
  })

  test('should emit semantic rewrite scaffolding for process and packer modules', async () => {
    const sampleId = 'sha256:' + '7'.repeat(64)
    await setupSample(sampleId, '7')

    const reconstructFunctionsHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          functions: [
            {
              function: 'FUN_140081090',
              address: '0x140081090',
              confidence: 0.93,
              gaps: [],
              behavior_tags: ['process_injection', 'process_spawn'],
              semantic_summary:
                'Builds capability dispatch tables, probes a remote process, and dispatches process operations.',
              xref_signals: [
                {
                  api: 'GetProcAddress',
                  provenance: 'dynamic_resolution_api',
                  confidence: 0.96,
                  evidence: ['resolver:GetProcAddress'],
                },
                {
                  api: 'WriteProcessMemory',
                  provenance: 'static_named_call',
                  confidence: 0.95,
                  evidence: ['callee:WriteProcessMemory'],
                },
                {
                  api: 'CreateProcessW',
                  provenance: 'static_named_call',
                  confidence: 0.91,
                  evidence: ['callee:CreateProcessW'],
                },
                {
                  api: 'NtQueryInformationProcess',
                  provenance: 'dynamic_resolution_api',
                  confidence: 0.9,
                  evidence: ['resolver:NtQueryInformationProcess'],
                },
                {
                  api: 'NtQuerySystemInformation',
                  provenance: 'dynamic_resolution_api',
                  confidence: 0.88,
                  evidence: ['resolver:NtQuerySystemInformation'],
                },
              ],
              call_context: {
                callers: ['dispatcher_main@0x140010000'],
                callees: ['WriteProcessMemory@0x180010100'],
              },
              call_relationships: {
                callers: [
                  {
                    target: 'dispatcher_main@0x140010000',
                    relation_types: ['body_reference_hint'],
                    reference_types: ['DATA'],
                    resolved_by: 'function_containing',
                    is_exact: false,
                  },
                ],
                callees: [
                  {
                    target: 'OpenProcess@0x180010080',
                    relation_types: ['direct_call_body'],
                    reference_types: ['UNCONDITIONAL_CALL'],
                    resolved_by: null,
                    is_exact: true,
                  },
                ],
              },
              parameter_roles: [
                {
                  slot: 'string_arg_0',
                  role: 'target_process_selector',
                  inferred_type: 'const char *',
                  confidence: 0.78,
                  evidence: ['behavior:process_injection_or_spawn'],
                },
                {
                  slot: 'pointer_arg_0',
                  role: 'payload_buffer',
                  inferred_type: 'void *',
                  confidence: 0.73,
                  evidence: ['api:WriteProcessMemory/ReadProcessMemory'],
                },
              ],
              return_role: {
                role: 'resolved_symbol_pointer',
                inferred_type: 'void *',
                confidence: 0.78,
                evidence: ['api:GetProcAddress/LoadLibrary*'],
              },
              state_roles: [
                {
                  state_key: 'dynamic_api_table',
                  role: 'Caches dynamically resolved imports or late-bound API pointers.',
                  confidence: 0.84,
                  evidence: ['api:GetProcAddress/LoadLibrary*'],
                },
              ],
              struct_inference: [
                {
                  semantic_name: 'remote_process_request',
                  rewrite_type_name: 'AkRemoteProcessRequest',
                  kind: 'request',
                  confidence: 0.82,
                  fields: [
                    {
                      name: 'target_selector',
                      inferred_type: 'const char *',
                      source_slot: 'string_arg_0',
                    },
                  ],
                  evidence: ['parameter_roles:target_process_selector/payload_buffer/process_handle'],
                },
              ],
              source_like_snippet: [
                '// function=FUN_140081090 confidence=0.93 gaps=none',
                '// strings: CreateFileW ReadFile WriteFile DeleteFile CopyFile RegOpenKeyExW',
                'int FUN_140081090(void){return 0;}',
              ].join('\n'),
              rank_reasons: ['calls_sensitive_api:WriteProcessMemory'],
            },
            {
              function: 'FUN_14000f8f0',
              address: '0x14000f8f0',
              confidence: 0.78,
              gaps: [],
              behavior_tags: [],
              semantic_summary:
                'Scans PE sections for packer signatures such as UPX, Themida, and VMProtect.',
              xref_signals: [],
              call_context: {
                callers: [],
                callees: [],
              },
              parameter_roles: [
                {
                  slot: 'pointer_arg_0',
                  role: 'image_view',
                  inferred_type: 'void *',
                  confidence: 0.81,
                  evidence: ['summary:packer_or_pe_layout_scan'],
                },
              ],
              return_role: {
                role: 'heuristic_match_score',
                inferred_type: 'int',
                confidence: 0.66,
                evidence: ['strings:packer/protector'],
              },
              state_roles: [
                {
                  state_key: 'packer_heuristics',
                  role: 'Accumulates packer heuristics, matched signatures, and section-layout findings.',
                  confidence: 0.83,
                  evidence: ['strings:packer/protector'],
                },
              ],
              struct_inference: [
                {
                  semantic_name: 'packer_scan_session',
                  rewrite_type_name: 'AkPackerScanSession',
                  kind: 'session',
                  confidence: 0.79,
                  fields: [
                    {
                      name: 'request',
                      inferred_type: 'packer_scan_request',
                      source_slot: null,
                    },
                  ],
                  evidence: ['parameter_roles:image_view/section_name_hint', 'state_roles:packer_heuristics'],
                },
              ],
              source_like_snippet: [
                '// function=FUN_14000f8f0 confidence=0.78 gaps=none',
                '// strings: Packer Detection UPX VMProtect Themida Entry point in non-first section',
                'int FUN_14000f8f0(void){return 0;}',
              ].join('\n'),
              rank_reasons: ['string_context:packer_detection'],
            },
          ],
        },
      })

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler,
        importsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            imports: {
              'kernel32.dll': ['CreateFileW', 'WriteFile', 'CreateProcessW'],
              'advapi32.dll': ['RegOpenKeyExW'],
            },
          },
        }),
        stringsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            summary: {
              top_high_value: [
                { string: 'Packer Detection', categories: ['command'] },
                { string: 'Akasha Auto Recon', categories: ['command'] },
              ],
              context_windows: [
                {
                  start_offset: 0,
                  end_offset: 120,
                  score: 9,
                  categories: ['command'],
                  strings: [
                    { offset: 4, string: 'akasha recon inject', encoding: 'ascii', categories: ['command'] },
                    { offset: 32, string: 'WriteProcessMemory', encoding: 'ascii', categories: ['suspicious_api'] },
                  ],
                },
              ],
            },
          },
        }),
        runtimeEvidenceLoader: jest.fn(async () => ({
          artifact_count: 2,
          executed: true,
          executed_artifact_count: 1,
          api_count: 3,
          memory_region_count: 2,
          stage_count: 2,
          observed_apis: ['GetProcAddress', 'CreateProcessW', 'WriteProcessMemory'],
          high_signal_apis: ['CreateProcessW', 'WriteProcessMemory'],
          memory_regions: ['process_operation_plan', 'api_resolution_table'],
          region_types: ['process_operation_plan', 'api_resolution_table'],
          observed_modules: ['process_ops', 'packer_analysis'],
          observed_strings: ['Akasha Auto Recon'],
          stages: ['prepare_remote_process_access', 'resolve_dynamic_apis'],
          risk_hints: [],
          source_formats: ['sandbox_trace'],
          evidence_kinds: ['trace'],
          source_names: ['speakeasy-live'],
          evidence: ['Runtime evidence observed CreateProcessW and GetProcAddress'],
          summary: 'Imported runtime evidence from 2 artifact(s) observed 3 API(s).',
        })),
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'semantic_rewrite_export',
      min_module_size: 1,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const processModule = data.modules.find((module: any) => module.name === 'process_ops')
    const packerModule = data.modules.find((module: any) => module.name === 'packer_analysis')

    expect(processModule).toBeDefined()
    expect(packerModule).toBeDefined()

    const processRewrite = fs.readFileSync(
      path.join(workspace.root, processModule.rewrite_path),
      'utf-8'
    )
    expect(processRewrite).toContain(
      'int build_capability_dispatch_tables_140081090(AkRuntimeContext *runtime_ctx, const AkSemanticInputs *inputs, AkSemanticOutputs *outputs)'
    )
    expect(processRewrite).toContain('/* original_symbol: FUN_140081090 @ 0x140081090 */')
    expect(processRewrite).toContain('semantic_alias: build_capability_dispatch_tables_140081090')
    expect(processRewrite).toContain('static int resolve_dynamic_api_table(AkResolvedApiTable *table)')
    expect(processRewrite).toContain('static int resolve_file_api_table(AkResolvedApiTable *table)')
    expect(processRewrite).toContain('static int resolve_registry_api_table(AkResolvedApiTable *table)')
    expect(processRewrite).toContain('static int query_remote_process_snapshot(AkProcessProbeResult *probe)')
    expect(processRewrite).toContain('static int query_code_integrity_state(AkProcessProbeResult *probe)')
    expect(processRewrite).toContain('static int dispatch_process_operation(')
    expect(processRewrite).toContain('static int ak_prepare_runtime_capabilities(')
    expect(processRewrite).toContain('static int ak_collect_process_context(')
    expect(processRewrite).toContain('static void ak_finalize_process_session(')
    expect(processRewrite).toContain('static const char *AK_TOOL_NAME = "Remote Process Operation Dispatcher";')
    expect(processRewrite).toContain('runtime_ctx->process_probe')
    expect(processRewrite).toContain('AkProcessOperationSession process_session = ak_start_process_session(inputs);')
    expect(processRewrite).toContain('if (process_session.remote_request.target_selector != 0) {')
    expect(processRewrite).toContain('if (process_session.remote_request.payload_view != 0 && runtime_ctx->last_status_detail == 0) {')
    expect(processRewrite).toContain('if (!ak_prepare_runtime_capabilities(runtime_ctx, 1, 1, 1)) {')
    expect(processRewrite).toContain(
      'ak_finalize_process_session(runtime_ctx, outputs, &process_session, recovered_status, AK_STAGE_PREPARE_REMOTE_PROCESS_ACCESS, "remote_memory_transfer");'
    )
    expect(processRewrite).toContain('semantic_parameters: runtime_ctx stores recovered mutable state')
    expect(processRewrite).toContain('parameter_roles: string_arg_0=>target_process_selector<const char *>')
    expect(processRewrite).toContain('return_role: resolved_symbol_pointer<void *>')
    expect(processRewrite).toContain('state_roles: dynamic_api_table=>Caches dynamically resolved imports or late-bound API pointers.')
    expect(processRewrite).toContain('struct_inference: remote_process_request=>AkRemoteProcessRequest')
    expect(processRewrite).toContain('regions=process_operation_plan')
    expect(processRewrite).toContain('modules=process_ops')
    expect(processRewrite).toContain('AK_DYNAMIC_API_HINTS_COUNT')
    expect(processRewrite).not.toContain('AK_DYNAMIC_API_HINT_COUNT')
    expect(processRewrite).toContain('AkRuntimeContext runtime_ctx = {0};')
    expect(processRewrite).toContain(
      'return build_capability_dispatch_tables_140081090(&runtime_ctx, &inputs, &outputs);'
    )
    expect(processRewrite).toContain('body_reference_hint')

    const packerRewrite = fs.readFileSync(
      path.join(workspace.root, packerModule.rewrite_path),
      'utf-8'
    )
    expect(packerRewrite).toContain(
      'int scan_packer_signatures_14000f8f0(AkRuntimeContext *runtime_ctx, const AkSemanticInputs *inputs, AkSemanticOutputs *outputs)'
    )
    expect(packerRewrite).toContain(' * - recovered_role: Detect packers, protectors, and suspicious PE layout signals.')
    expect(packerRewrite).toContain('semantic_alias: scan_packer_signatures_14000f8f0')
    expect(packerRewrite).toContain('static int ak_prepare_cli_model(AkCliModel *model)')
    expect(packerRewrite).toContain('static const char *AK_HELP_BANNER')
    expect(packerRewrite).toContain('static void ak_finalize_packer_session(')
    expect(packerRewrite).toContain('AK_PACKER_SIGNATURE_HINTS_COUNT')
    expect(packerRewrite).not.toContain('AK_PACKER_SIGNATURE_HINT_COUNT')
    expect(packerRewrite).toContain('AkPackerScanSession packer_session = ak_start_packer_session(inputs);')
    expect(packerRewrite).toContain('ak_finalize_packer_session(runtime_ctx, outputs, &packer_session, recovered_status);')
    expect(packerRewrite).toContain('static int scan_packer_signatures(AkPackerHeuristics *heuristics)')
    expect(packerRewrite).toContain('static int finalize_packer_assessment(const AkPackerHeuristics *heuristics)')
    expect(packerRewrite).toContain('parameter_roles: pointer_arg_0=>image_view<void *>')
    expect(packerRewrite).toContain('return_role: heuristic_match_score<int>')
    expect(packerRewrite).toContain('state_roles: packer_heuristics=>Accumulates packer heuristics, matched signatures, and section-layout findings.')
    expect(packerRewrite).toContain('struct_inference: packer_scan_session=>AkPackerScanSession')
    expect(packerRewrite).toContain(
      'return scan_packer_signatures_14000f8f0(&runtime_ctx, &inputs, &outputs);'
    )

    const supportHeader = fs.readFileSync(path.join(workspace.root, data.support_header_path), 'utf-8')
    expect(supportHeader).toContain('typedef struct AkRuntimeContext {')
    expect(supportHeader).toContain('typedef struct AkSemanticInputs {')
    expect(supportHeader).toContain('#define AK_INPUT_PRIMARY_TEXT(inputs)')
    expect(supportHeader).toContain('#define AK_STAGE_PREPARE_REMOTE_PROCESS_ACCESS "prepare_remote_process_access"')
    expect(supportHeader).toContain('typedef struct AkRemoteProcessRequest {')
    expect(supportHeader).toContain('typedef struct AkExecutionTransferResult {')
    expect(supportHeader).toContain('typedef struct AkProcessOperationSession {')
    expect(supportHeader).toContain('typedef struct AkCapabilityDispatchRequest {')
    expect(supportHeader).toContain('typedef struct AkCapabilityDispatchPlan {')
    expect(supportHeader).toContain('typedef struct AkPackerScanRequest {')
    expect(supportHeader).toContain('typedef struct AkPackerScanSession {')
    expect(supportHeader).toContain('static inline AkRemoteProcessRequest ak_build_remote_process_request')
    expect(supportHeader).toContain('static inline AkExecutionTransferResult ak_init_execution_transfer_result')
    expect(supportHeader).toContain('static inline AkProcessOperationSession ak_start_process_session')
    expect(supportHeader).toContain('static inline AkCapabilityDispatchPlan ak_start_capability_plan')
    expect(supportHeader).toContain('static inline AkPackerScanSession ak_start_packer_session')
    expect(supportHeader).toContain('static inline void ak_publish_packer_result')
    expect(supportHeader).toContain('typedef struct AkSemanticOutputs {')

    const harness = fs.readFileSync(path.join(workspace.root, data.harness_path), 'utf-8')
    expect(harness).toContain('#include <string.h>')
    expect(harness).toContain('#include "reconstruct_support.h"')
    expect(harness).toContain('const char *expected_stage;')
    expect(harness).toContain('static int ak_stage_matches(const char *expected_stage, const char *observed_stage)')
    expect(harness).toContain('build_capability_dispatch_tables_140081090')
    expect(harness).toContain('scan_packer_signatures_14000f8f0')
    expect(harness).toContain('inputs.string_args[0] = AK_HARNESS_ENTRIES[index].seed_text;')
    expect(harness).toContain('inputs.string_args[1] = AK_HARNESS_ENTRIES[index].seed_text;')
    expect(harness).toContain('inputs.handle_args[0] = (uintptr_t)(0x1000u + (unsigned int)index);')
    expect(harness).toContain('int stage_match = ak_stage_matches(AK_HARNESS_ENTRIES[index].expected_stage, outputs.observed_stage);')
    expect(harness).toContain('expected=%s match=%s detail=%s\\n')
    expect(harness).toContain('return mismatch_count == 0 ? 0 : 1;')
    expect(harness).toMatch(/"(?:Akasha Auto Recon|Packer Detection|Packer\/Protector Detection) (?:scan|recon|detect)"/)

    const buildManifest = fs.readFileSync(path.join(workspace.root, data.build_manifest_path), 'utf-8')
    expect(buildManifest).toContain('add_executable(reconstruct_harness')
    expect(buildManifest).toContain('src/process_ops.rewrite.c')

    const cliModel = JSON.parse(
      fs.readFileSync(path.join(workspace.root, data.cli_model_path), 'utf-8')
    )
    expect(Array.isArray(cliModel)).toBe(true)
    expect(
      cliModel.some(
        (item: any) =>
          item.tool_name.toLowerCase().includes('akasha') ||
          item.help_banner.toLowerCase().includes('packer')
      )
    ).toBe(true)

    const reverseNotes = fs.readFileSync(path.join(workspace.root, data.notes_path), 'utf-8')
    expect(reverseNotes).toContain('## Primary CLI Model')
    expect(reverseNotes).toContain('## Module CLI Models')
    expect(reverseNotes).toContain('role=Detect packers, protectors, and suspicious PE layout signals.')
    expect(reverseNotes).toContain('Akasha Auto Recon')
    expect(data.binary_profile.cli_profile.command_count).toBeGreaterThan(0)

    expect(data.runtime_evidence.region_types).toContain('process_operation_plan')
    expect(data.runtime_evidence.observed_modules).toContain('process_ops')
  })

  test('should prioritize anti-analysis rewrite bodies over packer module bias', async () => {
    const sampleId = 'sha256:' + '6'.repeat(64)
    await setupSample(sampleId, '6')

    const reconstructFunctionsHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          functions: [
            {
              function: 'FUN_1400747c0',
              address: '0x1400747c0',
              confidence: 0.97,
              gaps: [],
              behavior_tags: [],
              semantic_summary:
                'Queries Kernel_Code_Integrity_Status_Raw through NtQuerySystemInformation while feeding packer-oriented telemetry.',
              xref_signals: [
                {
                  api: 'GetProcAddress',
                  provenance: 'dynamic_resolution_api',
                  confidence: 0.95,
                  evidence: ['resolver:GetProcAddress'],
                },
                {
                  api: 'NtQuerySystemInformation',
                  provenance: 'static_named_call',
                  confidence: 0.9,
                  evidence: ['callee:NtQuerySystemInformation'],
                },
              ],
              call_context: {
                callers: [],
                callees: ['NtQuerySystemInformation@0x180012340'],
              },
              source_like_snippet: [
                '// function=FUN_1400747c0 confidence=0.97 gaps=none',
                '// strings: Packer Detection Kernel_Code_Integrity_Status_Raw VMProtect',
                'int FUN_1400747c0(void){return 0;}',
              ].join('\n'),
              rank_reasons: ['calls_sensitive_api:GetProcAddress'],
            },
          ],
        },
      })

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler,
        importsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: { imports: {} },
        }),
        stringsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            summary: {
              top_high_value: [
                { string: '@Packer/Protector Detection', categories: ['command'] },
              ],
            },
          },
        }),
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'anti_over_packer_export',
      min_module_size: 1,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const ownerModule = data.modules.find((module: any) =>
      module.functions?.some((func: any) => func.address === '0x1400747c0')
    )
    expect(ownerModule).toBeDefined()

    const rewrite = fs.readFileSync(path.join(workspace.root, ownerModule.rewrite_path), 'utf-8')
    expect(rewrite).toContain(
      'int query_code_integrity_state_1400747c0(AkRuntimeContext *runtime_ctx, const AkSemanticInputs *inputs, AkSemanticOutputs *outputs)'
    )
    expect(rewrite).toContain('semantic_alias: query_code_integrity_state_1400747c0')
    expect(rewrite).toContain('AkProcessOperationSession process_session = ak_start_process_session(inputs);')
    expect(rewrite).toContain('if (!ak_collect_process_context(runtime_ctx, 0, 1)) {')
    expect(rewrite).toContain('recovered_status = finalize_process_probe(&runtime_ctx->process_probe);')
    expect(rewrite).toContain(
      'ak_finalize_process_session(runtime_ctx, outputs, &process_session, recovered_status, AK_STAGE_ANTI_ANALYSIS_CHECKS, "process_probe");'
    )
    expect(rewrite).toContain('return query_code_integrity_state_1400747c0(&runtime_ctx, &inputs, &outputs);')
    expect(rewrite).not.toContain('recovered_status = finalize_packer_assessment(&runtime_ctx->packer_heuristics);')
  })

  test('should prefer reconstruct suggested_name when deriving semantic aliases', async () => {
    const sampleId = 'sha256:' + '5'.repeat(64)
    await setupSample(sampleId, '5')

    const reconstructFunctionsHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          functions: [
            {
              function: 'FUN_140081090',
              address: '0x140081090',
              confidence: 0.94,
              gaps: [],
              suggested_name: null,
              suggested_role: 'Writes payload bytes into a remote process region.',
              rename_confidence: 0.91,
              rename_evidence: ['api:WriteProcessMemory', 'stage:prepare_remote_process_access'],
              name_resolution: {
                rule_based_name: null,
                llm_suggested_name: 'write_remote_memory',
                llm_confidence: 0.91,
                llm_why: 'Remote memory write APIs dominate the evidence pack.',
                required_assumptions: [
                  'Assumes the function performs the write instead of only building a capability table.',
                ],
                evidence_used: ['api:WriteProcessMemory', 'stage:prepare_remote_process_access'],
                validated_name: 'write_remote_memory',
                resolution_source: 'llm',
                unresolved_semantic_name: false,
              },
              behavior_tags: ['process_injection'],
              semantic_summary:
                'Writes payload bytes into a remote process region after target preparation.',
              xref_signals: [
                {
                  api: 'WriteProcessMemory',
                  provenance: 'static_named_call',
                  confidence: 0.96,
                  evidence: ['callee:WriteProcessMemory'],
                },
              ],
              call_context: {
                callers: [],
                callees: ['WriteProcessMemory@0x180010100'],
              },
              source_like_snippet: [
                '// function=FUN_140081090 confidence=0.94 gaps=none',
                '// name_resolution=source:llm rule:none llm:write_remote_memory validated:write_remote_memory unresolved:no',
                'int FUN_140081090(void){return 0;}',
              ].join('\n'),
              rank_reasons: ['calls_sensitive_api:WriteProcessMemory'],
            },
          ],
        },
      })

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler,
        importsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: { imports: {} },
        }),
        stringsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: { summary: {} },
        }),
        runtimeEvidenceLoader: jest.fn(async () => null),
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'rename_alias_export',
      min_module_size: 1,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const processModule = data.modules.find((module: any) => module.name === 'process_ops')
    expect(processModule.functions[0].suggested_name).toBeNull()
    expect(processModule.functions[0].rename_confidence).toBeCloseTo(0.91, 2)
    expect(processModule.functions[0].validated_name).toBe('write_remote_memory')
    expect(processModule.functions[0].name_resolution_source).toBe('llm')

    const rewrite = fs.readFileSync(path.join(workspace.root, processModule.rewrite_path), 'utf-8')
    expect(rewrite).toContain(
      'int write_remote_memory_140081090(AkRuntimeContext *runtime_ctx, const AkSemanticInputs *inputs, AkSemanticOutputs *outputs)'
    )
    expect(rewrite).toContain('/* suggested_name: write_remote_memory confidence=0.91')
    expect(rewrite).toContain('/* name_resolution: source=llm rule=none llm=write_remote_memory validated=write_remote_memory unresolved=no */')
    expect(rewrite).toContain('semantic_alias: write_remote_memory_140081090')
    expect(rewrite).toContain('return write_remote_memory_140081090(&runtime_ctx, &inputs, &outputs);')
  })

  test('should propagate external explanation artifacts into rewrite comments and manifest output', async () => {
    const sampleId = 'sha256:' + '6'.repeat(64)
    await setupSample(sampleId, '6')

    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: new Date().toISOString(),
      session_tag: 'explain-session',
      client_name: 'claude-desktop',
      model_name: 'generic-tool-calling-llm',
      prepare_artifact_id: 'artifact-explain-prepare',
      explanations: [
        {
          address: '0x140081090',
          summary: 'Writes payload bytes into a remote process region after preparing the target context.',
          behavior: 'write_remote_memory',
          confidence: 0.87,
          assumptions: ['The target buffer belongs to a remote process and not a local scratch mapping.'],
          evidence_used: ['api:WriteProcessMemory', 'runtime:prepare_remote_process_access'],
          rewrite_guidance: [
            'Split remote handle acquisition from the memory write primitive.',
            'Model the payload buffer and byte count as explicit inputs.',
          ],
        },
      ],
    })

    const reconstructFunctionsHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          functions: [
            {
              function: 'FUN_140081090',
              address: '0x140081090',
              confidence: 0.94,
              gaps: [],
              suggested_name: 'write_remote_memory',
              suggested_role: 'Writes payload bytes into a remote process region.',
              rename_confidence: 0.91,
              rename_evidence: ['api:WriteProcessMemory', 'stage:prepare_remote_process_access'],
              name_resolution: {
                rule_based_name: 'write_remote_memory',
                llm_suggested_name: null,
                llm_confidence: null,
                llm_why: null,
                required_assumptions: [],
                evidence_used: [],
                validated_name: 'write_remote_memory',
                resolution_source: 'rule',
                unresolved_semantic_name: false,
              },
              behavior_tags: ['process_injection'],
              semantic_summary:
                'Writes payload bytes into a remote process region after target preparation.',
              xref_signals: [
                {
                  api: 'WriteProcessMemory',
                  provenance: 'static_named_call',
                  confidence: 0.96,
                  evidence: ['callee:WriteProcessMemory'],
                },
              ],
              call_context: {
                callers: [],
                callees: ['WriteProcessMemory@0x180010100'],
              },
              source_like_snippet:
                '// function=FUN_140081090 confidence=0.94 gaps=none\nint FUN_140081090(void){return 0;}',
              rank_reasons: ['calls_sensitive_api:WriteProcessMemory'],
            },
          ],
        },
      })

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler,
        importsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: { imports: {} },
        }),
        stringsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: { summary: {} },
        }),
        runtimeEvidenceLoader: jest.fn(async () => null),
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'explanation_export',
      min_module_size: 1,
      validate_build: false,
      run_harness: false,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const processModule = data.modules.find((module: any) => module.name === 'process_ops')
    expect(processModule.functions[0].explanation_behavior).toBe('write_remote_memory')
    expect(processModule.functions[0].explanation_summary).toContain('remote process region')
    expect(processModule.functions[0].explanation_confidence).toBeCloseTo(0.87, 2)

    const rewrite = fs.readFileSync(path.join(workspace.root, processModule.rewrite_path), 'utf-8')
    expect(rewrite).toContain('/* explanation: behavior=write_remote_memory confidence=0.87 source=llm')
    expect(rewrite).toContain('summary=Writes payload bytes into a remote process region')
    expect(rewrite).toContain('/* explanation_assumptions: The target buffer belongs to a remote process and not a local scratch mapping. */')
    expect(rewrite).toContain('/* explanation_evidence: api:WriteProcessMemory || runtime:prepare_remote_process_access */')
    expect(rewrite).toContain('/* rewrite_guidance: Split remote handle acquisition from the memory write primitive. || Model the payload buffer and byte count as explicit inputs. */')
  })

  test('should scope external explanation artifacts by semantic session selector', async () => {
    const sampleId = 'sha256:' + '7'.repeat(64)
    await setupSample(sampleId, '7')

    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: '2026-03-11T00:00:00.000Z',
      session_tag: 'semantic-alpha',
      client_name: 'alpha-client',
      model_name: 'alpha-model',
      explanations: [
        {
          address: '0x140081090',
          summary: 'alpha summary',
          behavior: 'alpha_behavior',
          confidence: 0.71,
          evidence_used: ['alpha'],
          rewrite_guidance: ['alpha guidance'],
        },
      ],
    })

    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: '2026-03-11T00:01:00.000Z',
      session_tag: 'semantic-beta',
      client_name: 'beta-client',
      model_name: 'beta-model',
      explanations: [
        {
          address: '0x140081090',
          summary: 'beta summary',
          behavior: 'beta_behavior',
          confidence: 0.89,
          evidence_used: ['beta'],
          rewrite_guidance: ['beta guidance'],
        },
      ],
    })

    const reconstructFunctionsHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          functions: [
            {
              function: 'FUN_140081090',
              address: '0x140081090',
              confidence: 0.94,
              gaps: [],
              suggested_name: 'write_remote_memory',
              suggested_role: 'Writes payload bytes into a remote process region.',
              rename_confidence: 0.91,
              rename_evidence: ['api:WriteProcessMemory'],
              name_resolution: {
                rule_based_name: 'write_remote_memory',
                llm_suggested_name: null,
                llm_confidence: null,
                llm_why: null,
                required_assumptions: [],
                evidence_used: [],
                validated_name: 'write_remote_memory',
                resolution_source: 'rule',
                unresolved_semantic_name: false,
              },
              behavior_tags: ['process_injection'],
              semantic_summary: 'Writes payload bytes into a remote process region.',
              xref_signals: [],
              call_context: { callers: [], callees: [] },
              source_like_snippet: 'int FUN_140081090(void){return 0;}',
              rank_reasons: [],
            },
          ],
        },
      })

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler,
        importsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: { imports: {} },
        }),
        stringsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: { summary: {} },
        }),
        runtimeEvidenceLoader: jest.fn(async () => null),
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'semantic_scope_export',
      semantic_scope: 'session',
      semantic_session_tag: 'semantic-beta',
      min_module_size: 1,
      validate_build: false,
      run_harness: false,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.provenance.semantic_explanations.scope).toBe('session')
    expect(data.provenance.semantic_explanations.artifact_count).toBe(1)
    expect(data.provenance.semantic_explanations.session_tags).toContain('semantic-beta')
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const manifest = JSON.parse(
      fs.readFileSync(path.join(workspace.root, data.manifest_path), 'utf-8')
    )
    expect(manifest.provenance.semantic_explanations.scope).toBe('session')
    expect(manifest.provenance.semantic_explanations.session_tags).toContain('semantic-beta')
    const processModule = data.modules.find((module: any) => module.name === 'process_ops')
    expect(processModule.functions[0].explanation_behavior).toBe('beta_behavior')
    expect(processModule.functions[0].explanation_summary).toContain('beta summary')
  })

  test('should propagate module review artifacts into rewrite headers and manifest output', async () => {
    const sampleId = 'sha256:' + '8'.repeat(64)
    await setupSample(sampleId, '8')

    await persistSemanticModuleReviewsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: new Date().toISOString(),
      session_tag: 'module-review-session',
      client_name: 'claude-desktop',
      model_name: 'generic-tool-calling-llm',
      prepare_artifact_id: 'artifact-module-review-prepare',
      reviews: [
        {
          module_name: 'process_ops',
          refined_name: 'remote_process_operations',
          summary:
            'Groups runtime wrappers, remote process access, and execution-transfer routines.',
          role_hint:
            'Role-aware focus on remote process operations, runtime wrappers, and execution transfer.',
          confidence: 0.88,
          assumptions: ['The grouped helpers all feed a shared remote-operation dispatcher.'],
          evidence_used: ['runtime:prepare_remote_process_access', 'api:WriteProcessMemory'],
          rewrite_guidance: [
            'Split remote handle acquisition from execution-transfer helpers.',
            'Promote runtime wrapper state into an explicit session object.',
          ],
          focus_areas: ['process_ops', 'runtime_wrappers'],
          priority_functions: ['FUN_140081090', 'FUN_14008d790'],
        },
      ],
    })

    const reconstructFunctionsHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          functions: [
            {
              function: 'FUN_140081090',
              address: '0x140081090',
              confidence: 0.94,
              gaps: [],
              suggested_name: 'write_remote_memory',
              suggested_role: 'Writes payload bytes into a remote process region.',
              rename_confidence: 0.91,
              rename_evidence: ['api:WriteProcessMemory'],
              behavior_tags: ['process_injection'],
              semantic_summary: 'Writes payload bytes into a remote process region.',
              xref_signals: [],
              call_context: { callers: [], callees: [] },
              source_like_snippet: 'int FUN_140081090(void){return 0;}',
              rank_reasons: [],
            },
          ],
        },
      })

    const handler = createCodeReconstructExportHandler(workspaceManager, database, cacheManager, {
      reconstructFunctionsHandler,
      importsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: { imports: {} },
      }),
      stringsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: { summary: {} },
      }),
      runtimeEvidenceLoader: jest.fn(async () => null),
      ...buildBinaryMetadataDependencies(),
    })

    const result = await handler({
      sample_id: sampleId,
      export_name: 'module_review_export',
      semantic_scope: 'session',
      semantic_session_tag: 'module-review-session',
      min_module_size: 1,
      validate_build: false,
      run_harness: false,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const processModule = data.modules.find((module: any) => module.name === 'process_ops')
    expect(processModule.refined_name).toBe('remote_process_operations')
    expect(processModule.review_summary).toContain('remote process access')
    expect(processModule.review_confidence).toBeCloseTo(0.88, 2)
    expect(data.provenance.semantic_module_reviews.artifact_count).toBe(1)
    expect(data.provenance.semantic_module_reviews.session_tags).toContain('module-review-session')

    const rewrite = fs.readFileSync(path.join(workspace.root, processModule.rewrite_path), 'utf-8')
    expect(rewrite).toContain('module_review_name: remote_process_operations')
    expect(rewrite).toContain('module_review_summary: Groups runtime wrappers, remote process access')
    expect(rewrite).toContain(
      'module_rewrite_guidance: Split remote handle acquisition from execution-transfer helpers. | Promote runtime wrapper state into an explicit session object.'
    )

    const manifest = JSON.parse(fs.readFileSync(path.join(workspace.root, data.manifest_path), 'utf-8'))
    expect(manifest.provenance.semantic_module_reviews.artifact_count).toBe(1)
    expect(manifest.modules[0].refined_name).toBe('remote_process_operations')
  })

  test('should invalidate export cache when semantic naming artifacts change', async () => {
    const sampleId = 'sha256:' + 'd'.repeat(64)
    await setupSample(sampleId, 'd')

    let validatedName = 'dispatch_shared_routine'
    const reconstructFunctionsHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockImplementation(async () => ({
        ok: true,
        data: {
          functions: [
            {
              function: 'FUN_1401429e0',
              address: '0x1401429e0',
              confidence: 0.89,
              gaps: [],
              behavior_tags: ['file_io'],
              semantic_summary: 'Large packer / section scanning routine.',
              xref_signals: [],
              call_context: {
                callers: [],
                callees: [],
              },
              call_relationships: {
                callers: [],
                callees: [],
              },
              suggested_name: validatedName,
              suggested_role: 'packer scan routine',
              rename_confidence: 0.88,
              rename_evidence: ['cfg_shape', 'string_hints'],
              name_resolution: {
                rule_based_name:
                  validatedName === 'dispatch_shared_routine'
                    ? 'dispatch_shared_routine'
                    : null,
                llm_suggested_name:
                  validatedName === 'dispatch_shared_routine' ? null : validatedName,
                llm_confidence: validatedName === 'dispatch_shared_routine' ? null : 0.74,
                llm_why:
                  validatedName === 'dispatch_shared_routine'
                    ? null
                    : 'External LLM suggested a more specific packer scan label.',
                required_assumptions: [],
                evidence_used: [],
                validated_name: validatedName,
                resolution_source:
                  validatedName === 'dispatch_shared_routine' ? 'rule' : 'llm',
                unresolved_semantic_name: false,
              },
              source_like_snippet: [
                '// function=FUN_1401429e0 confidence=0.89 gaps=none',
                `// name_resolution=source:${validatedName === 'dispatch_shared_routine' ? 'rule' : 'llm'} rule:${validatedName === 'dispatch_shared_routine' ? validatedName : 'none'} llm:${validatedName === 'dispatch_shared_routine' ? 'none' : validatedName} validated:${validatedName} unresolved:no`,
                'int FUN_1401429e0(void){return 0;}',
              ].join('\n'),
              rank_reasons: ['high_callers'],
            },
          ],
        },
      }))

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler,
        importsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: { imports: {} },
        }),
        stringsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: { summary: {} },
        }),
        runtimeEvidenceLoader: jest.fn(async () => null),
        ...buildBinaryMetadataDependencies(),
      }
    )

    const first = await handler({
      sample_id: sampleId,
      export_name: 'semantic_cache_refresh',
      min_module_size: 1,
      validate_build: false,
      run_harness: false,
    })

    expect(first.ok).toBe(true)
    expect((first.data as any).modules[0].functions[0].validated_name).toBe(
      'dispatch_shared_routine'
    )

    await persistSemanticNameSuggestionsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: new Date().toISOString(),
      client_name: 'codex-smoke',
      model_name: 'external-review-simulated',
      suggestions: [
        {
          address: '0x1401429e0',
          candidate_name: 'scan_packer_layout_and_signatures',
          confidence: 0.74,
          why: 'More specific external suggestion',
          evidence_used: ['strings:@Packer/Protector Detection'],
        },
      ],
    })

    validatedName = 'scan_packer_layout_and_signatures'

    const second = await handler({
      sample_id: sampleId,
      export_name: 'semantic_cache_refresh',
      min_module_size: 1,
      validate_build: false,
      run_harness: false,
    })

    expect(second.ok).toBe(true)
    expect((second.data as any).modules[0].functions[0].validated_name).toBe(
      'scan_packer_layout_and_signatures'
    )
    expect(reconstructFunctionsHandler).toHaveBeenCalledTimes(2)
    expect(second.warnings || []).not.toContain('Result from cache')
  })

  test('should recover CLI model from noisy Akasha-like string hints and avoid garbage harness seeds', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)
    await setupSample(sampleId, 'b')

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            functions: [
              {
                function: 'FUN_14009d620',
                address: '0x14009d620',
                confidence: 0.96,
                gaps: [],
                behavior_tags: [],
                semantic_summary:
                  'Coordinates packer/protector detection and PE layout inspection using goblin and iced-x86.',
                xref_signals: [],
                call_context: {
                  callers: [],
                  callees: [],
                },
                source_like_snippet: [
                  '// function=FUN_14009d620 confidence=0.96 gaps=none',
                  '// strings: internal error: entered unreachable codeC:\\Users\\catpoo\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\iced-x86-1.21.0\\src\\format',
                  '// strings: @Packer/Protector Detection',
                  '// strings: Entry point in non-first section: (unusual)',
                  'int FUN_14009d620(void){return 0;}',
                ].join('\n'),
                rank_reasons: ['high_callers'],
              },
            ],
          },
        }),
        importsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: { imports: {} },
        }),
        stringsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            summary: {
              top_high_value: [
                {
                  string:
                    'internal error: entered unreachable codeC:\\Users\\catpoo\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\iced-x86-1.21.0\\src\\format',
                  categories: ['all'],
                },
                {
                  string: 'Akasha Auto Recon',
                  categories: ['all'],
                },
                {
                  string: '@Packer/Protector Detection',
                  categories: ['all'],
                },
                {
                  string: 'Entry point in non-first section: (unusual)',
                  categories: ['all'],
                },
              ],
            },
          },
        }),
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'noisy_cli_export',
      min_module_size: 1,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const cliModel = JSON.parse(
      fs.readFileSync(path.join(workspace.root, data.cli_model_path), 'utf-8')
    )
    const packerModel = cliModel.find((item: any) => item.module === 'packer_analysis')
    expect(packerModel).toBeDefined()
    expect(packerModel.help_banner).toBe('@Packer/Protector Detection')
    expect(packerModel.commands.some((item: any) => item.verb === 'scan')).toBe(true)
    expect(packerModel.commands.some((item: any) => item.verb === 'detect')).toBe(true)

    const packerModule = data.modules.find((module: any) => module.name === 'packer_analysis')
    const rewrite = fs.readFileSync(path.join(workspace.root, packerModule.rewrite_path), 'utf-8')
    expect(rewrite).toContain(' * - recovered_role: Detect packers, protectors, and suspicious PE layout signals.')
    expect(rewrite).toContain('static const char *AK_HELP_BANNER = "@Packer/Protector Detection";')
    expect(rewrite).toContain('static const AkCommandSpec AK_COMMAND_0 = { "scan"')
    expect(rewrite).toContain('static const AkCommandSpec AK_COMMAND_1 = { "detect"')

    const harness = fs.readFileSync(path.join(workspace.root, data.harness_path), 'utf-8')
    expect(harness).toMatch(/"(?:Akasha Auto Recon|Packer\/Protector Detection|Packer Detection) scan"/)
    expect(harness).not.toContain('internal error: entered unreachable code')
    expect(harness).not.toContain('.cargo\\\\registry')

    const reverseNotes = fs.readFileSync(path.join(workspace.root, data.notes_path), 'utf-8')
    expect(reverseNotes).toContain('role=Detect packers, protectors, and suspicious PE layout signals.')
    expect(reverseNotes).not.toContain('internal error: entered unreachable code')
  })

  test('should prefer semantic tool labels for noisy process and file modules', async () => {
    const sampleId = 'sha256:' + 'c'.repeat(64)
    await setupSample(sampleId, 'c')

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            functions: [
              {
                function: 'FUN_140081090',
                address: '0x140081090',
                confidence: 0.98,
                gaps: [],
                behavior_tags: ['process_injection'],
                semantic_summary:
                  'Builds capability dispatch tables and prepares remote-process access via WriteProcessMemory and SetThreadContext.',
                xref_signals: [
                  {
                    api: 'WriteProcessMemory',
                    provenance: 'static_named_call',
                    confidence: 0.95,
                    evidence: ['callee:WriteProcessMemory'],
                  },
                ],
                call_context: { callers: [], callees: [] },
                source_like_snippet: [
                  '// function=FUN_140081090 confidence=0.98 gaps=none',
                  '// strings: exe\\cmd.exe\\\\.\\NULstack backtrace:',
                  '// strings: WriteProcessMemory failed at',
                  'int FUN_140081090(void){return 0;}',
                ].join('\n'),
                rank_reasons: ['calls_sensitive_api:WriteProcessMemory'],
              },
              {
                function: 'memcpy',
                address: '0x140140261',
                confidence: 0.65,
                gaps: [],
                behavior_tags: ['file_io'],
                semantic_summary: 'Prepares file-oriented capability state from recovered helper tables.',
                xref_signals: [],
                call_context: { callers: [], callees: [] },
                source_like_snippet: [
                  '// function=memcpy confidence=0.65 gaps=none',
                  '// strings: assertion failed: actual_state == EMPTY',
                  '// strings: A Tokio 1.x context was found, but it is being shutdown.',
                  'int memcpy(void){return 0;}',
                ].join('\n'),
                rank_reasons: ['high_callers'],
              },
            ],
          },
        }),
        importsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            imports: {
              'kernel32.dll': ['WriteProcessMemory', 'CreateFileW'],
            },
          },
        }),
        stringsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            summary: {
              top_high_value: [
                { string: 'exe\\cmd.exe\\\\.\\NULstack backtrace:', categories: ['command'] },
                { string: 'WriteProcessMemory failed at', categories: ['suspicious_api'] },
                { string: 'assertion failed: actual_state == EMPTY', categories: ['all'] },
              ],
            },
          },
        }),
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'semantic_labels_export',
      min_module_size: 1,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const cliModel = JSON.parse(fs.readFileSync(path.join(workspace.root, data.cli_model_path), 'utf-8'))
    const processModel = cliModel.find((item: any) => item.module === 'process_ops')
    const fileModel = cliModel.find((item: any) => item.module === 'file_ops')
    expect(processModel.tool_name).toBe('Remote Process Operation Dispatcher')
    expect(processModel.help_banner).toBe(
      'Prepare remote-process access, dynamic API resolution, and execution-transfer operations.'
    )
    expect(fileModel.tool_name).toBe('File And Artifact Capability Dispatcher')
    expect(fileModel.help_banner).toBe('Stage file, buffer, and artifact materialization capabilities.')

    const processModule = data.modules.find((module: any) => module.name === 'process_ops')
    const fileModule = data.modules.find((module: any) => module.name === 'file_ops')
    const processRewrite = fs.readFileSync(path.join(workspace.root, processModule.rewrite_path), 'utf-8')
    expect(processRewrite).toContain(' * - recovered_role: Prepare remote-process access, dynamic API resolution, and execution-transfer operations.')
    expect(processRewrite).not.toContain('exe\\\\cmd.exe\\\\\\\\.\\\\NULstack backtrace:')
    const fileRewrite = fs.readFileSync(path.join(workspace.root, fileModule.rewrite_path), 'utf-8')
    expect(fileRewrite).toContain('recovered_status = finalize_capability_dispatch(&runtime_ctx->file_apis, 0);')
    expect(fileRewrite).toContain('const char *capability_observation = ak_select_capability_observation(&runtime_ctx->file_apis, 0);')
    expect(fileRewrite).not.toContain('finalize_process_probe(&runtime_ctx->process_probe);')

    const reverseNotes = fs.readFileSync(path.join(workspace.root, data.notes_path), 'utf-8')
    expect(reverseNotes).toContain('role=Prepare remote-process access, dynamic API resolution, and execution-transfer operations.')
    expect(reverseNotes).not.toContain('assertion failed: actual_state == EMPTY')

    const harness = fs.readFileSync(path.join(workspace.root, data.harness_path), 'utf-8')
    expect(harness).toContain('file_ops_memcpy_wrapper')
  })

  test('should prefer capability-table aliases over generic packer aliases when registry setup is inferred', async () => {
    const sampleId = 'sha256:' + '5'.repeat(64)
    await setupSample(sampleId, '5')

    const reconstructFunctionsHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          functions: [
            {
              function: 'FUN_1401429e0',
              address: '0x1401429e0',
              confidence: 0.9,
              gaps: [],
              behavior_tags: [],
              semantic_summary:
                'Partial semantic recovery for a packer-adjacent routine that prepares capability state.',
              xref_signals: [],
              call_context: {
                callers: ['dispatcher@0x140010100'],
                callees: [],
              },
              source_like_snippet: [
                '// function=FUN_1401429e0 confidence=0.90 gaps=none',
                '// strings: Packer Detection VMProtect Themida RegOpenKeyExW',
                'int FUN_1401429e0(void){return 0;}',
              ].join('\n'),
              rank_reasons: ['high_callers'],
            },
          ],
        },
      })

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler,
        importsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            imports: {
              'advapi32.dll': ['RegOpenKeyExW'],
            },
          },
        }),
        stringsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: {
            summary: {
              top_high_value: [
                { string: '@Packer/Protector Detection', categories: ['command'] },
              ],
            },
          },
        }),
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'capability_alias_export',
      min_module_size: 1,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const ownerModule = data.modules.find((module: any) =>
      module.functions?.some((func: any) => func.address === '0x1401429e0')
    )
    expect(ownerModule).toBeDefined()

    const rewrite = fs.readFileSync(path.join(workspace.root, ownerModule.rewrite_path), 'utf-8')
    expect(rewrite).toContain(
      'int prepare_capability_tables_1401429e0(AkRuntimeContext *runtime_ctx, const AkSemanticInputs *inputs, AkSemanticOutputs *outputs)'
    )
    expect(rewrite).toContain('semantic_alias: prepare_capability_tables_1401429e0')
    expect(rewrite).toContain('AkCapabilityDispatchPlan capability_plan = ak_start_capability_plan(inputs);')
    expect(rewrite).toContain('if (!ak_prepare_runtime_capabilities(runtime_ctx, 0, 0, 1)) {')
    expect(rewrite).toContain(
      'ak_finalize_capability_plan(runtime_ctx, outputs, &capability_plan, recovered_status, AK_STAGE_REGISTRY_OPERATIONS);'
    )
    expect(rewrite).toContain(
      'return prepare_capability_tables_1401429e0(&runtime_ctx, &inputs, &outputs);'
    )
    expect(rewrite).not.toContain('semantic_alias: scan_packer_signatures_1401429e0')
  })

  test('should supplement top-k reconstruction with string-linked functions outside the initial set', async () => {
    const sampleId = 'sha256:' + '8'.repeat(64)
    await setupSample(sampleId, '8')
    database.insertAnalysis({
      id: 'ghidra-ready-export-supplement',
      sample_id: sampleId,
      stage: 'ghidra',
      backend: 'ghidra',
      status: 'done',
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      output_json: JSON.stringify({
        project_path: 'C:/ghidra/project',
        project_key: 'project',
        readiness: {
          function_index: { available: true, status: 'ready' },
          decompile: { available: true, status: 'ready', target: '0x404000' },
          cfg: { available: true, status: 'ready', target: '0x404000' },
        },
      }),
      metrics_json: JSON.stringify({}),
    })

    const reconstructFunctionsHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockImplementation(async (args: ToolArgs) => {
        if ((args as any).address === '0x404000') {
          return {
            ok: true,
            data: {
              functions: [
                {
                  function: 'FUN_14000f8f0',
                  address: '0x404000',
                  confidence: 0.74,
                  gaps: [],
                  behavior_tags: [],
                  semantic_summary: 'Likely handles packer detection via section entropy checks.',
                  xref_signals: [],
                  call_context: {
                    callers: [],
                    callees: [],
                  },
                  source_like_snippet:
                    '// function=FUN_14000f8f0 confidence=0.74 gaps=none\n// summary=Likely handles packer detection via section entropy checks.\nint FUN_14000f8f0(void){return 0;}',
                  rank_reasons: [],
                },
              ],
            },
          }
        }

        return {
          ok: true,
          data: {
            functions: [
              {
                function: 'core_main',
                address: '0x401000',
                confidence: 0.66,
                gaps: [],
                behavior_tags: [],
                semantic_summary: 'Partial semantic recovery for core_main.',
                xref_signals: [],
                call_context: {
                  callers: [],
                  callees: [],
                },
                source_like_snippet:
                  '// function=core_main confidence=0.66 gaps=none\nint core_main(void){return 0;}',
                rank_reasons: [],
              },
            ],
          },
        }
      })

    const stringsExtractHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          summary: {
            top_high_value: [{ string: 'Packer Detection', categories: ['command'] }],
            context_windows: [
              {
                start_offset: 0x1200,
                end_offset: 0x1260,
                score: 8.2,
                categories: ['command'],
                strings: [
                  {
                    offset: 0x1200,
                    string: 'Packer Detection',
                    encoding: 'ascii',
                    categories: ['command'],
                  },
                ],
              },
            ],
          },
        },
      })

    const searchFunctions = jest
      .fn<
        (
          sampleId: string,
          options: {
            apiQuery?: string
            stringQuery?: string
            limit?: number
            timeout?: number
          }
        ) => Promise<any>
      >()
      .mockResolvedValue({
        query: {
          string: 'Packer Detection',
          limit: 6,
        },
        matches: [
          {
            function: 'FUN_14000f8f0',
            address: '0x404000',
            caller_count: 0,
            callee_count: 0,
            string_matches: [
              {
                value: 'Packer Detection',
                data_address: '0x18001200',
                referenced_from: '0x404020',
              },
            ],
            match_types: ['string_reference'],
          },
        ],
        count: 1,
      })

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler,
        importsExtractHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
          ok: true,
          data: { imports: {} },
        }),
        stringsExtractHandler,
        searchFunctions,
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'supplemental_string_linked_export',
      min_module_size: 1,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.modules.some((module: any) => module.name === 'packer_analysis')).toBe(true)
    expect(reconstructFunctionsHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: sampleId,
        address: '0x404000',
        include_xrefs: true,
        evidence_scope: 'all',
        evidence_session_tag: undefined,
      })
    )
  })

  test('should continue export when imports/strings are unavailable', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    await setupSample(sampleId, '2')

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue(buildReconstructResult()),
        importsExtractHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue({
            ok: false,
            errors: ['imports worker unavailable'],
          }),
        stringsExtractHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue({
            ok: false,
            errors: ['strings worker unavailable'],
          }),
        ...buildBinaryMetadataDependencies({ exportsOk: false, packerOk: false }),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'degraded_export',
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    expect(result.warnings?.join(' ')).toContain('imports unavailable')
    expect(result.warnings?.join(' ')).toContain('strings unavailable')
  })

  test('should return error when reconstructed functions are empty', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    await setupSample(sampleId, '3')

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue({
            ok: true,
            data: { functions: [] },
          }),
        ...buildBinaryMetadataDependencies(),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      reuse_cached: false,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('No reconstructed functions available')
  })

  test('should cache export results', async () => {
    const sampleId = 'sha256:' + '4'.repeat(64)
    await setupSample(sampleId, '4')

    const reconstructFunctionsHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue(buildReconstructResult())
    const importsExtractHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          imports: {
            'ws2_32.dll': ['connect'],
          },
        },
      })
    const stringsExtractHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          summary: {
            top_high_value: [],
          },
        },
      })

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler,
        importsExtractHandler,
        stringsExtractHandler,
        ...buildBinaryMetadataDependencies(),
      }
    )

    const first = await handler({
      sample_id: sampleId,
      export_name: 'cached_export',
    })
    const second = await handler({
      sample_id: sampleId,
      export_name: 'cached_export',
    })

    expect(first.ok).toBe(true)
    expect(second.ok).toBe(true)
    expect(reconstructFunctionsHandler).toHaveBeenCalledTimes(1)
    expect(importsExtractHandler).toHaveBeenCalledTimes(1)
    expect(stringsExtractHandler).toHaveBeenCalledTimes(1)
    expect(second.warnings).toContain('Result from cache')
    expect((second.metrics as any)?.cached).toBe(true)
  })

  test('should emit dll-oriented binary profile and reverse notes for exported packed samples', async () => {
    const sampleId = 'sha256:' + '6'.repeat(64)
    await setupSample(sampleId, '6')
    const workspace = await workspaceManager.getWorkspace(sampleId)
    fs.writeFileSync(path.join(workspace.original, 'payload.dll'), Buffer.from('MZ'))

    const metadata = buildBinaryMetadataDependencies({
      exportsData: {
        exports: [
          { ordinal: 1, address: 0x1000, name: 'DllRegisterServer' },
          { ordinal: 2, address: 0x1100, name: 'RunRecon' },
        ],
        forwarders: [],
        total_exports: 2,
        total_forwarders: 0,
      },
      packerData: {
        packed: true,
        confidence: 0.81,
        detected: ['UPX'],
      },
    })

    const handler = createCodeReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructFunctionsHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue(buildReconstructResult()),
        importsExtractHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue({
            ok: true,
            data: { imports: {} },
          }),
        stringsExtractHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue({
            ok: true,
            data: { summary: { top_high_value: [] } },
          }),
        ...metadata,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'dll_profile_export',
      min_module_size: 1,
      reuse_cached: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.binary_profile.binary_role).toBe('dll')
    expect(data.binary_profile.export_count).toBe(2)
    expect(data.binary_profile.packed).toBe(true)
    expect(data.binary_profile.analysis_priorities).toContain(
      'unpack_or_deobfuscate_before_deep_semantics'
    )
    expect(data.binary_profile.analysis_priorities).toContain('trace_export_surface_first')

    const notesPath = path.join(workspace.root, data.notes_path)
    const notesContent = fs.readFileSync(notesPath, 'utf-8')
    expect(notesContent).toContain('trace_export_surface_first')
    expect(notesContent).toContain('DllRegisterServer')
  })
})
