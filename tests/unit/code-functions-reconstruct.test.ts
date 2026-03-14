/**
 * Unit tests for code.functions.reconstruct tool
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import type { RankedFunction, DecompiledFunction, ControlFlowGraph } from '../../src/decompiler-worker.js'
import {
  createCodeFunctionsReconstructHandler,
  CodeFunctionsReconstructInputSchema,
} from '../../src/tools/code-functions-reconstruct.js'
import type { DynamicTraceSummary } from '../../src/dynamic-trace.js'
import { persistSemanticNameSuggestionsArtifact } from '../../src/semantic-name-suggestion-artifacts.js'

describe('code.functions.reconstruct tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-functions-reconstruct')
    testDbPath = path.join(process.cwd(), 'test-functions-reconstruct.db')
    testCachePath = path.join(process.cwd(), 'test-cache-functions-reconstruct')

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

  function insertSample(sampleId: string, hashChar: string) {
    database.insertSample({
      id: sampleId,
      sha256: hashChar.repeat(64),
      md5: hashChar.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })
  }

  test('should apply input defaults', () => {
    const parsed = CodeFunctionsReconstructInputSchema.parse({
      sample_id: 'sha256:' + 'a'.repeat(64),
    })

    expect(parsed.topk).toBe(3)
    expect(parsed.include_xrefs).toBe(false)
    expect(parsed.max_pseudocode_lines).toBe(120)
    expect(parsed.max_assembly_lines).toBe(80)
    expect(parsed.timeout).toBe(30)
    expect(parsed.evidence_scope).toBe('all')
    expect(parsed.semantic_scope).toBe('all')
  })

  test('should require evidence_session_tag when evidence_scope=session', () => {
    expect(() =>
      CodeFunctionsReconstructInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        evidence_scope: 'session',
      })
    ).toThrow('evidence_session_tag')
  })

  test('should require semantic_session_tag when semantic_scope=session', () => {
    expect(() =>
      CodeFunctionsReconstructInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        semantic_scope: 'session',
      })
    ).toThrow('semantic_session_tag')
  })

  test('should return error when sample does not exist', async () => {
    const handler = createCodeFunctionsReconstructHandler(
      workspaceManager,
      database,
      cacheManager
    )

    const result = await handler({
      sample_id: 'sha256:' + 'f'.repeat(64),
      topk: 2,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should reconstruct top-k functions with confidence map', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    insertSample(sampleId, '1')

    const rankedFunctions: RankedFunction[] = [
      {
        address: '0x401000',
        name: 'entry',
        score: 38,
        reasons: ['entry_point', 'calls_sensitive_api:CreateProcessW'],
        xref_summary: [
          {
            api: 'CreateProcessW',
            provenance: 'static_named_call',
            confidence: 0.78,
            evidence: ['callee:CreateProcessW'],
          },
        ],
      },
      {
        address: '0x402000',
        name: 'worker',
        score: 22,
        reasons: ['high_callers'],
      },
    ]

    const rankFunctions = jest
      .fn<(sampleId: string, topK: number) => Promise<RankedFunction[]>>()
      .mockResolvedValue(rankedFunctions)

    const decompileFunction = jest
      .fn<
        (
          sampleId: string,
          addressOrSymbol: string,
          includeXrefs: boolean,
          timeoutMs: number
        ) => Promise<DecompiledFunction>
      >()
      .mockImplementation(async (_sampleId, addressOrSymbol) => {
        if (addressOrSymbol === '0x401000') {
          return {
            function: 'entry',
            address: '0x401000',
            pseudocode: [
              'int entry(void) {',
              '  CreateProcessW(L"cmd.exe", 0, 0, 0, 0, 0, 0, 0, 0, 0);',
              '  return 0;',
              '}',
            ].join('\n'),
            callers: [],
            callees: [{ address: '0x500100', name: 'CreateProcessW' }],
            callee_relationships: [
              {
                address: '0x500100',
                name: 'CreateProcessW',
                relation_types: ['direct_call_body'],
                reference_types: ['UNCONDITIONAL_CALL'],
                reference_addresses: ['0x401020'],
                is_exact: true,
              },
              {
                address: '0x500110',
                name: 'GetProcAddress',
                relation_types: ['body_reference_hint'],
                reference_types: ['DATA'],
                reference_addresses: ['0x401028'],
                resolved_by: 'resolver_stub',
                is_exact: false,
              },
            ],
          }
        }

        return {
          function: 'worker',
          address: '0x402000',
          pseudocode: [
            'int worker(int x) {',
            '  int y = x + 1;',
            '  return y;',
            '}',
          ].join('\n'),
          callers: [{ address: '0x401050', name: 'entry' }],
          callees: [],
        }
      })

    const getFunctionCFG = jest
      .fn<
        (
          sampleId: string,
          addressOrSymbol: string,
          timeoutMs: number
        ) => Promise<ControlFlowGraph>
      >()
      .mockImplementation(async (_sampleId, addressOrSymbol) => ({
        function: addressOrSymbol === '0x401000' ? 'entry' : 'worker',
        address: addressOrSymbol,
        nodes: [
          {
            id: 'n0',
            address: addressOrSymbol,
            instructions: ['push rbp', 'mov rbp, rsp'],
            type: 'entry',
          },
          {
            id: 'n1',
            address: addressOrSymbol,
            instructions: ['call CreateProcessW', 'ret'],
            type: 'basic',
          },
        ],
        edges: [{ from: 'n0', to: 'n1', type: 'fallthrough' }],
      }))

    const handler = createCodeFunctionsReconstructHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        rankFunctions,
        decompileFunction,
        getFunctionCFG,
        runtimeEvidenceLoader: jest.fn(async (): Promise<DynamicTraceSummary> => ({
          artifact_count: 1,
          executed: true,
          executed_artifact_count: 1,
          api_count: 3,
          memory_region_count: 1,
          stage_count: 2,
          observed_apis: ['CreateProcessW', 'GetProcAddress', 'WriteProcessMemory'],
          high_signal_apis: ['CreateProcessW', 'WriteProcessMemory'],
          memory_regions: ['process_operation_plan'],
          region_types: ['process_operation_plan', 'api_resolution_table'],
          protections: ['read_write_plan', 'r-x_image'],
          address_ranges: ['0x1000-0x1200'],
          region_owners: ['akasha.exe', 'kernel32.dll'],
          observed_modules: ['process_ops'],
          segment_names: ['.text', '.pdata'],
          observed_strings: ['Akasha Auto Recon'],
          stages: ['prepare_remote_process_access', 'resolve_dynamic_apis'],
          risk_hints: [],
          source_formats: ['sandbox_trace'],
          evidence_kinds: ['trace'],
          source_modes: ['speakeasy'],
          source_names: ['speakeasy-live'],
          confidence_layers: [
            {
              layer: 'executed_trace' as const,
              artifact_count: 1,
              confidence_band: 'high' as const,
              source_formats: ['sandbox_trace'],
              evidence_kinds: ['trace'],
              source_names: ['speakeasy-live'],
              source_modes: ['speakeasy'],
              latest_imported_at: '2026-03-11T00:00:00.000Z',
              summary: 'Executed trace evidence from 1 artifact(s).',
            },
          ],
          earliest_imported_at: '2026-03-11T00:00:00.000Z',
          latest_imported_at: '2026-03-11T00:00:00.000Z',
          scope_note: 'Runtime evidence currently reflects a single registered artifact.',
          evidence: ['Runtime evidence observed CreateProcessW and GetProcAddress'],
          summary: 'Imported runtime evidence from 1 artifact(s) observed 3 API(s).',
        })),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      topk: 2,
      include_xrefs: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.mode).toBe('topk')
    expect(data.requested_count).toBe(2)
    expect(data.reconstructed_count).toBe(2)
    expect(data.confidence_map.length).toBe(2)
    expect(data.functions[0].source_like_snippet).toContain('confidence=')
    expect(data.functions[0].source_like_snippet).toContain('summary=')
    expect(data.functions[0].source_like_snippet).toContain('xrefs=')
    expect(data.functions[0].source_like_snippet).toContain('relationship_hints=')
    expect(data.functions[0].source_like_snippet).toContain('parameter_roles=')
    expect(data.functions[0].source_like_snippet).toContain('return_role=')
    expect(data.functions[0].source_like_snippet).toContain('state_roles=')
    expect(data.functions[0].source_like_snippet).toContain('struct_inference=')
    expect(data.functions[0].source_like_snippet).toContain('runtime_evidence=')
    expect(data.functions[0].source_like_snippet).toContain('suggested_name=resolve_dynamic_apis')
    expect(data.functions[0].source_like_snippet).toContain('executed:yes')
    expect(data.functions[0].source_like_snippet).toContain('sources:sandbox_trace:trace')
    expect(data.functions[0].source_like_snippet).toContain('layers:executed_trace(1)')
    expect(data.functions[0].source_like_snippet).toContain('latest:2026-03-11T00:00:00.000Z')
    expect(data.functions[0].source_like_snippet).toContain('modules:process_ops')
    expect(data.functions[0].source_like_snippet).toContain('protections:read_write_plan')
    expect(data.functions[0].source_like_snippet).toContain('owners:akasha.exe, kernel32.dll')
    expect(data.functions[0].source_like_snippet).toContain('segments:.text')
    expect(data.functions[0].source_like_snippet).toContain('ranges:0x1000-0x1200')
    expect(data.functions[0].source_like_snippet).toContain(
      'runtime_scope=Runtime evidence currently reflects a single registered artifact.'
    )
    expect(data.functions[0].assembly_excerpt).toContain('block')
    expect(data.functions[0].semantic_summary).toContain('CreateProcessW')
    expect(data.functions[0].semantic_summary).toContain('relationship recovery')
    expect(data.functions[0].semantic_summary).toContain('runtime corroborates')
    expect(data.functions[0].semantic_summary).toContain('executed runtime trace')
    expect(data.functions[0].semantic_summary).toContain('runtime layers=executed_trace(1)')
    expect(data.functions[0].semantic_summary).toContain('protections include read_write_plan')
    expect(data.functions[0].semantic_summary).toContain('region owners include akasha.exe')
    expect(data.functions[0].xref_signals[0].api).toBe('CreateProcessW')
    expect(
      data.functions[0].xref_signals.some((signal: any) => signal.api === 'GetProcAddress')
    ).toBe(true)
    expect(data.functions[0].runtime_context.corroborated_apis).toContain('CreateProcessW')
    expect(data.functions[0].runtime_context.corroborated_stages).toContain(
      'prepare_remote_process_access'
    )
    expect(data.functions[0].parameter_roles.some((item: any) => item.role === 'target_process_selector')).toBe(true)
    expect(data.functions[0].state_roles.some((item: any) => item.state_key === 'dynamic_api_table')).toBe(true)
    expect(data.functions[0].struct_inference.some((item: any) => item.semantic_name === 'remote_process_request')).toBe(true)
    expect(data.functions[0].semantic_evidence.parameter_roles.some((item: any) => item.role === 'target_process_selector')).toBe(true)
    expect(data.functions[0].return_role.role).toBe('resolved_symbol_pointer')
    expect(data.functions[0].semantic_evidence.return_role.role).toBe('resolved_symbol_pointer')
    expect(data.functions[0].semantic_evidence.state_roles.some((item: any) => item.state_key === 'dynamic_api_table')).toBe(true)
    expect(data.functions[0].semantic_evidence.struct_inference.some((item: any) => item.semantic_name === 'remote_process_request')).toBe(true)
    expect(data.functions[0].runtime_context.executed).toBe(true)
    expect(data.functions[0].runtime_context.evidence_sources).toContain('sandbox_trace:trace')
    expect(data.functions[0].runtime_context.matched_memory_regions).toContain('process_operation_plan')
    expect(data.functions[0].runtime_context.matched_protections).toContain('read_write_plan')
    expect(data.functions[0].runtime_context.matched_region_owners).toContain('akasha.exe')
    expect(data.functions[0].runtime_context.matched_segment_names).toContain('.text')
    expect(data.functions[0].runtime_context.matched_address_ranges).toContain('0x1000-0x1200')
    expect(data.functions[0].runtime_context.suggested_modules).toContain('process_ops')
    expect(data.functions[0].runtime_context.provenance_layers).toContain('executed_trace(1)')
    expect(data.functions[0].runtime_context.latest_artifact_at).toBe('2026-03-11T00:00:00.000Z')
    expect(data.functions[0].runtime_context.scope_note).toContain('single registered artifact')
    expect(data.functions[0].suggested_name).toBe('resolve_dynamic_apis')
    expect(data.functions[0].suggested_role).toContain('runtime API resolver')
    expect(data.functions[0].rename_confidence).toBeGreaterThan(0.8)
    expect(data.functions[0].rename_evidence).toContain('api:GetProcAddress')
    expect(data.functions[0].confidence_profile.score_kind).toBe('heuristic_reconstruction')
    expect(data.functions[0].confidence_profile.calibrated).toBe(false)
    expect(data.functions[0].runtime_confidence_profile.score_kind).toBe('runtime_correlation')
    expect(data.functions[0].runtime_confidence_profile.drivers).toContain('executed_trace=yes')
    expect(data.functions[0].naming_confidence_profile.score_kind).toBe('naming_resolution')
    expect(data.functions[0].naming_confidence_profile.acceptance_rule).toContain('llm_confidence >= 0.62')
    expect(data.functions[0].call_context.callees[0]).toContain('CreateProcessW')
    expect(data.functions[0].call_context.callees.join(' ')).toContain('direct_call_body')
    expect(data.functions[0].call_relationships.callees[0].relation_types).toContain(
      'direct_call_body'
    )
    expect(data.functions[0].evidence.callee_count).toBeGreaterThanOrEqual(2)
    expect(data.functions.some((func: any) => func.behavior_tags.includes('process_spawn'))).toBe(
      true
    )
    expect(rankFunctions).toHaveBeenCalledTimes(1)
    expect(decompileFunction).toHaveBeenCalledTimes(2)
    expect(getFunctionCFG).toHaveBeenCalledTimes(2)
  })

  test('should pass evidence scope options to runtimeEvidenceLoader', async () => {
    const sampleId = 'sha256:' + '9'.repeat(64)
    insertSample(sampleId, '9')

    const runtimeEvidenceLoader = jest
      .fn<
        (
          sampleId: string,
          options?: {
            evidenceScope?: 'all' | 'latest' | 'session'
            sessionTag?: string
          }
        ) => Promise<DynamicTraceSummary | null>
      >()
      .mockResolvedValue(null)

    const handler = createCodeFunctionsReconstructHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        rankFunctions: jest.fn(async () => [
          {
            address: '0x401000',
            name: 'entry',
            score: 1,
            reasons: [],
          },
        ]),
        decompileFunction: jest.fn(async () => ({
          function: 'entry',
          address: '0x401000',
          pseudocode: 'int entry(void) { return 0; }',
          callers: [],
          callees: [],
        })),
        getFunctionCFG: jest
          .fn<
            (
              sampleId: string,
              addressOrSymbol: string,
              timeoutMs: number
            ) => Promise<ControlFlowGraph>
          >()
          .mockResolvedValue({
            function: 'entry',
            address: '0x401000',
            nodes: [{ id: 'n0', address: '0x401000', instructions: ['ret'], type: 'entry' }],
            edges: [],
          }),
        runtimeEvidenceLoader,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      topk: 1,
      evidence_scope: 'session',
      evidence_session_tag: 'runtime-alpha',
    })

    expect(result.ok).toBe(true)
    expect(runtimeEvidenceLoader).toHaveBeenCalledWith(sampleId, {
      evidenceScope: 'session',
      sessionTag: 'runtime-alpha',
    })
  })

  test('should infer universal network, service, COM, and DLL roles from semantic evidence', async () => {
    const sampleId = 'sha256:' + 'd'.repeat(64)
    insertSample(sampleId, 'd')

    const handler = createCodeFunctionsReconstructHandler(workspaceManager, database, cacheManager, {
      rankFunctions: jest.fn(async () => [
        {
          address: '0x501000',
          name: 'DllRegisterServer',
          score: 31,
          reasons: ['exported_entrypoint'],
        },
      ]),
      decompileFunction: jest.fn(async () => ({
        function: 'DllRegisterServer',
        address: '0x501000',
        pseudocode: [
          'int DllRegisterServer(HMODULE module) {',
          '  OpenSCManagerA(0, 0, 0);',
          '  CreateServiceA(0, "svc", "svc", 0, 0, 0, 0, "cmd.exe", 0, 0, 0, 0, 0);',
          '  CoCreateInstance(0, 0, 1, 0, 0);',
          '  InternetConnectA(0, "example.org", 443, 0, 0, 0, 0, 0);',
          '  HttpSendRequestA(0, 0, 0, 0, 0);',
          '  DllGetClassObject(0, 0, 0);',
          '  return 0;',
          '}',
        ].join('\n'),
        callers: [],
        callees: [
          { address: '0x700100', name: 'OpenSCManagerA' },
          { address: '0x700120', name: 'CreateServiceA' },
          { address: '0x700140', name: 'CoCreateInstance' },
          { address: '0x700160', name: 'InternetConnectA' },
          { address: '0x700180', name: 'HttpSendRequestA' },
          { address: '0x7001a0', name: 'DllGetClassObject' },
        ],
      })),
      getFunctionCFG: jest
        .fn<
          (
            sampleId: string,
            addressOrSymbol: string,
            timeoutMs: number
          ) => Promise<ControlFlowGraph>
        >()
        .mockResolvedValue({
          function: 'DllRegisterServer',
          address: '0x501000',
          nodes: [
            { id: 'n0', address: '0x501000', instructions: ['push rbp'], type: 'entry' },
            { id: 'n1', address: '0x501040', instructions: ['call InternetConnectA'], type: 'basic' },
            { id: 'n2', address: '0x501080', instructions: ['ret'], type: 'return' },
          ],
          edges: [
            { from: 'n0', to: 'n1', type: 'fallthrough' },
            { from: 'n1', to: 'n2', type: 'fallthrough' },
          ],
        }),
      runtimeEvidenceLoader: jest.fn(async () => null),
    })

    const result = await handler({
      sample_id: sampleId,
      topk: 1,
      include_xrefs: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const func = data.functions[0]

    expect(func.behavior_tags).toContain('networking')
    expect(func.behavior_tags).toContain('service_control')
    expect(func.behavior_tags).toContain('com_activation')
    expect(func.behavior_tags).toContain('dll_lifecycle')
    expect(func.behavior_tags).toContain('export_dispatch')
    expect(func.parameter_roles.some((item: any) => item.role === 'remote_host_or_url')).toBe(true)
    expect(func.return_role.role).toBe('network_operation_status')
    expect(func.parameter_roles.some((item: any) => item.role === 'service_name')).toBe(true)
    expect(func.parameter_roles.some((item: any) => item.role === 'class_or_interface_identifier')).toBe(true)
    expect(func.parameter_roles.some((item: any) => item.role === 'module_instance')).toBe(true)
    expect(func.state_roles.some((item: any) => item.state_key === 'network_session')).toBe(true)
    expect(func.state_roles.some((item: any) => item.state_key === 'service_control_state')).toBe(true)
    expect(func.state_roles.some((item: any) => item.state_key === 'com_class_factory')).toBe(true)
    expect(func.state_roles.some((item: any) => item.state_key === 'dll_entry_state')).toBe(true)
    expect(func.state_roles.some((item: any) => item.state_key === 'export_dispatch_table')).toBe(true)
    expect(func.struct_inference.some((item: any) => item.semantic_name === 'network_request_context')).toBe(true)
    expect(func.struct_inference.some((item: any) => item.semantic_name === 'service_control_context')).toBe(true)
    expect(func.struct_inference.some((item: any) => item.semantic_name === 'com_activation_context')).toBe(true)
    expect(func.struct_inference.some((item: any) => item.semantic_name === 'dll_entry_context')).toBe(true)
    expect(func.struct_inference.some((item: any) => item.semantic_name === 'export_dispatch_table')).toBe(true)
    expect(func.source_like_snippet).toContain('remote_host_or_url')
    expect(func.source_like_snippet).toContain('service_control_state')
    expect(func.source_like_snippet).toContain('AkComActivationContext')
  })

  test('should keep reconstruction result with gaps when cfg fails', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    insertSample(sampleId, '2')

    const handler = createCodeFunctionsReconstructHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        rankFunctions: jest
          .fn<(sampleId: string, topK: number) => Promise<RankedFunction[]>>()
          .mockResolvedValue([
            {
              address: '0x403000',
              name: 'single',
              score: 10,
              reasons: [],
            },
          ]),
        decompileFunction: jest
          .fn<
            (
              sampleId: string,
              addressOrSymbol: string,
              includeXrefs: boolean,
              timeoutMs: number
            ) => Promise<DecompiledFunction>
          >()
          .mockResolvedValue({
            function: 'single',
            address: '0x403000',
            pseudocode: 'int single(void) { return 1; }',
            callers: [],
            callees: [],
          }),
        getFunctionCFG: jest
          .fn<
            (
              sampleId: string,
              addressOrSymbol: string,
              timeoutMs: number
            ) => Promise<ControlFlowGraph>
          >()
          .mockRejectedValue(new Error('cfg unavailable')),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      topk: 1,
    })

    expect(result.ok).toBe(true)
    expect(result.warnings?.join(' ')).toContain('cfg failed')
    const data = result.data as any
    expect(data.functions[0].gaps).toContain('missing_cfg')
  })

  test('should suggest names for tailcall thunks and shared high-fan-in dispatchers', async () => {
    const sampleId = 'sha256:' + '9'.repeat(64)
    insertSample(sampleId, '9')

    const handler = createCodeFunctionsReconstructHandler(workspaceManager, database, cacheManager, {
      rankFunctions: jest
        .fn<(sampleId: string, topK: number) => Promise<RankedFunction[]>>()
        .mockResolvedValue([
          {
            address: '0x409000',
            name: 'thunk_FUN_14010cdb0',
            score: 31,
            reasons: ['high_callers'],
          },
          {
            address: '0x409100',
            name: 'FUN_14009d620',
            score: 30,
            reasons: ['high_callers'],
          },
          {
            address: '0x409200',
            name: 'memcpy',
            score: 20,
            reasons: ['high_callers'],
          },
        ]),
      decompileFunction: jest
        .fn<
          (
            sampleId: string,
            addressOrSymbol: string,
            includeXrefs: boolean,
            timeoutMs: number
          ) => Promise<DecompiledFunction>
        >()
        .mockImplementation(async (_sampleId, addressOrSymbol) => {
          if (addressOrSymbol === '0x409000') {
            return {
              function: 'thunk_FUN_14010cdb0',
              address: '0x409000',
              pseudocode: 'void thunk_FUN_14010cdb0(void) { return; }',
              callers: [
                { address: '0x500000', name: 'FUN_140001060' },
                { address: '0x500010', name: 'FUN_1400010a0' },
              ],
              callees: [],
              callee_relationships: [
                {
                  address: '0x600000',
                  name: 'FUN_14010cdb0',
                  relation_types: ['tail_jump_hint'],
                  reference_types: ['UNCONDITIONAL_JUMP'],
                  reference_addresses: ['0x40900f'],
                  resolved_by: 'function_at',
                  is_exact: true,
                },
              ],
            }
          }

          if (addressOrSymbol === '0x409200') {
            return {
              function: 'memcpy',
              address: '0x409200',
              pseudocode: 'void *memcpy(void *dst, void *src, size_t len) { return dst; }',
              callers: [{ address: '0x520000', name: 'FUN_14008d790' }],
              callees: [],
              callee_relationships: [
                {
                  address: '0x620000',
                  name: 'FUN_140140261',
                  relation_types: ['tail_jump_hint'],
                  reference_types: ['UNCONDITIONAL_JUMP'],
                  reference_addresses: ['0x40920f'],
                  resolved_by: 'function_at',
                  is_exact: true,
                },
              ],
            }
          }

          return {
            function: 'FUN_14009d620',
            address: '0x409100',
            pseudocode: 'void FUN_14009d620(longlong *param_1) { FUN_14009ae70(); thunk_FUN_14010cdb0(); FUN_14009a0b0(); }',
            callers: [
              { address: '0x510000', name: 'FUN_140036480' },
              { address: '0x510010', name: 'FUN_1400364c0' },
              { address: '0x510020', name: 'FUN_140036500' },
              { address: '0x510030', name: 'FUN_140036540' },
              { address: '0x510040', name: 'FUN_140036580' },
            ],
            callees: [],
            callee_relationships: [
              {
                address: '0x610000',
                name: 'FUN_14009ae70',
                relation_types: ['direct_call'],
                reference_types: ['UNCONDITIONAL_CALL'],
                reference_addresses: ['0x409110'],
                resolved_by: 'function_at',
                is_exact: true,
              },
              {
                address: '0x610100',
                name: 'thunk_FUN_14010cdb0',
                relation_types: ['direct_call'],
                reference_types: ['UNCONDITIONAL_CALL'],
                reference_addresses: ['0x409120'],
                resolved_by: 'function_at',
                is_exact: true,
              },
              {
                address: '0x610200',
                name: 'FUN_14009a0b0',
                relation_types: ['direct_call'],
                reference_types: ['UNCONDITIONAL_CALL'],
                reference_addresses: ['0x409130'],
                resolved_by: 'function_at',
                is_exact: true,
              },
            ],
          }
        }),
      getFunctionCFG: jest
        .fn<
          (
            sampleId: string,
            addressOrSymbol: string,
            timeoutMs: number
          ) => Promise<ControlFlowGraph>
        >()
        .mockImplementation(async (_sampleId, addressOrSymbol) => ({
          function: String(addressOrSymbol),
          address: String(addressOrSymbol),
          nodes: [
            {
              id: 'entry',
              address: String(addressOrSymbol),
              instructions: ['jmp 0x600000'],
              type: 'entry',
            },
          ],
          edges: [],
        })),
    })

    const result = await handler({
      sample_id: sampleId,
      topk: 3,
      include_xrefs: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const thunkFunc = data.functions.find((item: any) => item.function === 'thunk_FUN_14010cdb0')
    const dispatchFunc = data.functions.find((item: any) => item.function === 'FUN_14009d620')
    const memcpyFunc = data.functions.find((item: any) => item.function === 'memcpy')

    expect(thunkFunc.suggested_name).toBe('tailcall_dispatch_thunk')
    expect(thunkFunc.rename_evidence).toContain('name:thunk')
    expect(thunkFunc.source_like_snippet).toContain('suggested_name=tailcall_dispatch_thunk')

    expect(dispatchFunc.suggested_name).toBe('dispatch_shared_routine')
    expect(dispatchFunc.rename_evidence).toContain('rank_reason:high_callers')
    expect(dispatchFunc.rename_evidence).toContain('gap:unresolved_function_symbols')
    expect(dispatchFunc.source_like_snippet).toContain('suggested_name=dispatch_shared_routine')

    expect(memcpyFunc.suggested_name).toBeNull()
    expect(memcpyFunc.rename_confidence).toBeNull()
  })

  test('should refine trivial helper and guard names from linked renamed callers', async () => {
    const sampleId = 'sha256:' + '8'.repeat(64)
    insertSample(sampleId, '8')

    const handler = createCodeFunctionsReconstructHandler(workspaceManager, database, cacheManager, {
      rankFunctions: jest
        .fn<(sampleId: string, topK: number) => Promise<RankedFunction[]>>()
        .mockResolvedValue([
          {
            address: '0x408000',
            name: 'FUN_14008d790',
            score: 40,
            reasons: ['calls_sensitive_api:GetProcAddress'],
          },
          {
            address: '0x408080',
            name: 'FUN_140070000',
            score: 30,
            reasons: ['calls_sensitive_api:OpenProcess'],
          },
          {
            address: '0x408100',
            name: 'FUN_1400935d0',
            score: 21,
            reasons: ['high_callers'],
          },
          {
            address: '0x408180',
            name: 'FUN_140093620',
            score: 20,
            reasons: ['high_callers'],
          },
          {
            address: '0x408200',
            name: 'FUN_140093610',
            score: 20,
            reasons: ['high_callers'],
          },
          {
            address: '0x408280',
            name: 'FUN_140093630',
            score: 19,
            reasons: ['high_callers'],
          },
        ]),
      decompileFunction: jest
        .fn<
          (
            sampleId: string,
            addressOrSymbol: string,
            includeXrefs: boolean,
            timeoutMs: number
          ) => Promise<DecompiledFunction>
        >()
        .mockImplementation(async (_sampleId, addressOrSymbol) => {
          if (addressOrSymbol === '0x408000') {
            return {
              function: 'FUN_14008d790',
              address: '0x408000',
              pseudocode: 'void FUN_14008d790(void) { GetProcAddress(0, 0); }',
              callers: [{ address: '0x520100', name: 'main' }],
              callees: [{ address: '0x600100', name: 'GetProcAddress' }],
            }
          }
          if (addressOrSymbol === '0x408080') {
            return {
              function: 'FUN_140070000',
              address: '0x408080',
              pseudocode: 'void FUN_140070000(void) { OpenProcess(0, 0, 0); }',
              callers: [{ address: '0x520101', name: 'main' }],
              callees: [{ address: '0x600101', name: 'OpenProcess' }],
            }
          }
          if (addressOrSymbol === '0x408100') {
            return {
              function: 'FUN_1400935d0',
              address: '0x408100',
              pseudocode: 'void FUN_1400935d0(void) { return; }',
              callers: [
                { address: '0x408000', name: 'FUN_14008d790' },
                { address: '0x520110', name: 'FUN_140045b30' },
                { address: '0x520120', name: 'FUN_140046790' },
                { address: '0x520130', name: 'FUN_140068310' },
              ],
              callees: [],
            }
          }
          if (addressOrSymbol === '0x408180') {
            return {
              function: 'FUN_140093620',
              address: '0x408180',
              pseudocode: 'int FUN_140093620(void) { return 0; }',
              callers: [
                { address: '0x408080', name: 'FUN_140070000' },
                { address: '0x520140', name: 'FUN_140046790' },
                { address: '0x520150', name: 'FUN_140068310' },
              ],
              callees: [],
            }
          }
          return {
            function: addressOrSymbol === '0x408200' ? 'FUN_140093610' : 'FUN_140093630',
            address: String(addressOrSymbol),
            pseudocode:
              addressOrSymbol === '0x408200'
                ? 'void FUN_140093610(void) { return; }'
                : 'int FUN_140093630(void) { return 1; }',
            callers:
              addressOrSymbol === '0x408200'
                ? [
                    { address: '0x530100', name: 'FUN_140001000' },
                    { address: '0x530110', name: 'FUN_140001020' },
                    { address: '0x530120', name: 'FUN_140001040' },
                    { address: '0x530130', name: 'FUN_140001060' },
                  ]
                : [
                    { address: '0x540100', name: 'FUN_140001080' },
                    { address: '0x540110', name: 'FUN_1400010a0' },
                    { address: '0x540120', name: 'FUN_1400010c0' },
                  ],
            callees: [],
          }
        }),
      getFunctionCFG: jest
        .fn<
          (
            sampleId: string,
            addressOrSymbol: string,
            timeoutMs: number
          ) => Promise<ControlFlowGraph>
        >()
        .mockImplementation(async (_sampleId, addressOrSymbol) => ({
          function: String(addressOrSymbol),
          address: String(addressOrSymbol),
          nodes: [
            {
              id: 'entry',
              address: String(addressOrSymbol),
              instructions: ['ret'],
              type: 'entry',
            },
          ],
          edges: [],
        })),
    })

    const result = await handler({
      sample_id: sampleId,
      topk: 6,
      include_xrefs: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const resolver = data.functions.find((item: any) => item.function === 'FUN_14008d790')
    const prepareFunc = data.functions.find((item: any) => item.function === 'FUN_140070000')
    const linkedHelper = data.functions.find((item: any) => item.function === 'FUN_1400935d0')
    const linkedGuard = data.functions.find((item: any) => item.function === 'FUN_140093620')
    const genericHelper = data.functions.find((item: any) => item.function === 'FUN_140093610')
    const genericTrueGuard = data.functions.find((item: any) => item.function === 'FUN_140093630')

    expect(resolver.suggested_name).toBe('resolve_dynamic_apis')
    expect(prepareFunc.suggested_name).toBe('prepare_remote_process_access')
    expect(linkedHelper.suggested_name).toBe('resolve_dynamic_apis_helper')
    expect(linkedHelper.rename_evidence).toContain('linked_caller:resolve_dynamic_apis')
    expect(linkedHelper.source_like_snippet).toContain('suggested_name=resolve_dynamic_apis_helper')

    expect(linkedGuard.suggested_name).toBe('prepare_remote_process_access_guard')
    expect(linkedGuard.rename_evidence).toContain('linked_caller:prepare_remote_process_access')
    expect(linkedGuard.rename_evidence).toContain('body:return_0')
    expect(linkedGuard.source_like_snippet).toContain(
      'suggested_name=prepare_remote_process_access_guard'
    )

    expect(genericHelper.suggested_name).toBe('shared_noop_stub')
    expect(genericHelper.rename_evidence).toContain('body:void_return_stub')
    expect(genericHelper.source_like_snippet).toContain('suggested_name=shared_noop_stub')

    expect(genericTrueGuard.suggested_name).toBe('shared_true_guard')
    expect(genericTrueGuard.rename_evidence).toContain('body:return_1')
    expect(genericTrueGuard.source_like_snippet).toContain('suggested_name=shared_true_guard')
  })

  test('should name short trap-after-call stubs', async () => {
    const sampleId = 'sha256:' + '9'.repeat(64)
    insertSample(sampleId, '9')

    const handler = createCodeFunctionsReconstructHandler(workspaceManager, database, cacheManager, {
      rankFunctions: jest
        .fn<(sampleId: string, topK: number) => Promise<RankedFunction[]>>()
        .mockResolvedValue([
          {
            address: '0x409000',
            name: 'FUN_1401464e3',
            score: 21,
            reasons: ['high_callers'],
          },
        ]),
      decompileFunction: jest
        .fn<
          (
            sampleId: string,
            addressOrSymbol: string,
            includeXrefs: boolean,
            timeoutMs: number
          ) => Promise<DecompiledFunction>
        >()
        .mockResolvedValue({
          function: 'FUN_1401464e3',
          address: '0x409000',
          pseudocode:
            'void FUN_1401464e3(void) { FUN_14010d180(); pcVar1 = (code *)swi(3); (*pcVar1)(); }',
          callers: [
            { address: '0x520200', name: 'FUN_1400549e0' },
            { address: '0x520210', name: 'FUN_14010fb60' },
            { address: '0x520220', name: 'FUN_1401414c0' },
            { address: '0x520230', name: 'FUN_140141710' },
          ],
          callees: [{ address: '0x610200', name: 'FUN_14010d180' }],
        }),
      getFunctionCFG: jest
        .fn<
          (
            sampleId: string,
            addressOrSymbol: string,
            timeoutMs: number
          ) => Promise<ControlFlowGraph>
        >()
        .mockResolvedValue({
          function: 'FUN_1401464e3',
          address: '0x409000',
          nodes: [
            {
              id: 'entry',
              address: '0x409000',
              instructions: ['call 0x610200', 'swi 3'],
              type: 'entry',
            },
          ],
          edges: [],
        }),
    })

    const result = await handler({
      sample_id: sampleId,
      topk: 1,
      include_xrefs: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const trapStub = data.functions.find((item: any) => item.function === 'FUN_1401464e3')

    expect(trapStub.suggested_name).toBe('call_then_trap_stub')
    expect(trapStub.rename_evidence).toContain('body:trap_after_call')
    expect(trapStub.source_like_snippet).toContain('suggested_name=call_then_trap_stub')
  })

  test('should emit layered rule/llm/unresolved naming metadata with semantic evidence packs', async () => {
    const sampleId = 'sha256:' + 'a'.repeat(64)
    insertSample(sampleId, 'a')

    const seenEvidencePacks: any[] = []
    const semanticNameSuggester = jest
      .fn(async (evidencePack: any) => {
        seenEvidencePacks.push(evidencePack)
        if (evidencePack.function_name === 'FUN_1400d0580') {
          return {
            candidate_name: 'scan_pe_layout_or_sections',
            confidence: 0.71,
            why: 'Packer strings and PE-layout hints dominate the evidence pack.',
            required_assumptions: ['Assumes this routine is a scanner, not only a helper wrapper.'],
            evidence_used: ['string_hint:@Packer/Protector Detection', 'cfg_nodes:32'],
          }
        }
        if (evidencePack.function_name === 'FUN_140012340') {
          return {
            candidate_name: 'shared_semantic_candidate',
            confidence: 0.58,
            why: 'Evidence is weak and still ambiguous.',
            required_assumptions: ['Assumes the helper has cross-module reuse.'],
            evidence_used: ['caller_count:2'],
          }
        }
        return null
      })

    const handler = createCodeFunctionsReconstructHandler(workspaceManager, database, cacheManager, {
      rankFunctions: jest
        .fn<(sampleId: string, topK: number) => Promise<RankedFunction[]>>()
        .mockResolvedValue([
          {
            address: '0x40a000',
            name: 'FUN_14008d790',
            score: 40,
            reasons: ['calls_sensitive_api:GetProcAddress'],
          },
          {
            address: '0x40a100',
            name: 'FUN_1400d0580',
            score: 25,
            reasons: ['high_callers'],
          },
          {
            address: '0x40a200',
            name: 'FUN_140012340',
            score: 18,
            reasons: ['high_callers'],
          },
        ]),
      decompileFunction: jest
        .fn<
          (
            sampleId: string,
            addressOrSymbol: string,
            includeXrefs: boolean,
            timeoutMs: number
          ) => Promise<DecompiledFunction>
        >()
        .mockImplementation(async (_sampleId, addressOrSymbol) => {
          if (addressOrSymbol === '0x40a000') {
            return {
              function: 'FUN_14008d790',
              address: '0x40a000',
              pseudocode: 'void FUN_14008d790(void) { GetProcAddress(0, 0); }',
              callers: [{ address: '0x501000', name: 'entry' }],
              callees: [{ address: '0x600100', name: 'GetProcAddress' }],
            }
          }
          if (addressOrSymbol === '0x40a100') {
            return {
              function: 'FUN_1400d0580',
              address: '0x40a100',
              pseudocode: 'int FUN_1400d0580(void) { return 1; }',
              callers: [
                { address: '0x501100', name: 'FUN_1400413a0' },
                { address: '0x501110', name: 'FUN_140052c80' },
                { address: '0x501120', name: 'FUN_140051f20' },
              ],
              callees: [],
            }
          }
          return {
            function: 'FUN_140012340',
            address: '0x40a200',
            pseudocode: 'int FUN_140012340(void) { return local_10; }',
            callers: [
              { address: '0x502100', name: 'FUN_140061000' },
              { address: '0x502110', name: 'FUN_140061020' },
            ],
            callees: [],
          }
        }),
      getFunctionCFG: jest
        .fn<
          (
            sampleId: string,
            addressOrSymbol: string,
            timeoutMs: number
          ) => Promise<ControlFlowGraph>
        >()
        .mockImplementation(async (_sampleId, addressOrSymbol) => ({
          function: String(addressOrSymbol),
          address: String(addressOrSymbol),
          nodes:
            addressOrSymbol === '0x40a100'
              ? Array.from({ length: 32 }, (_, index) => ({
                  id: `n${index}`,
                  address: `0x${(0x40a100 + index).toString(16)}`,
                  instructions: ['mov eax, eax'],
                  type: index === 0 ? 'entry' : 'basic',
                }))
              : [
                  {
                    id: 'entry',
                    address: String(addressOrSymbol),
                    instructions: ['ret'],
                    type: 'entry',
                  },
                ],
          edges:
            addressOrSymbol === '0x40a100'
              ? Array.from({ length: 40 }, (_, index) => ({
                  from: `n${index % 31}`,
                  to: `n${(index + 1) % 31}`,
                  type: 'jump' as const,
                }))
              : [],
        })),
      stringEvidenceLoader: jest.fn(async () => ({
        top_high_value: [
          {
            offset: 4096,
            string: '@Packer/Protector Detection',
            categories: ['command'],
          },
          {
            offset: 4128,
            string: 'Entry point in non-first section: (unusual)',
            categories: ['ioc'],
          },
        ],
        context_windows: [
          {
            start_offset: 4096,
            end_offset: 4200,
            score: 6,
            categories: ['command', 'ioc'],
            strings: [
              {
                offset: 4096,
                string: '@Packer/Protector Detection',
                categories: ['command'],
              },
              {
                offset: 4128,
                string: 'Entry point in non-first section: (unusual)',
                categories: ['ioc'],
              },
            ],
          },
        ],
      })),
      semanticNameSuggester,
    })

    const result = await handler({
      sample_id: sampleId,
      topk: 3,
      include_xrefs: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const ruleNamed = data.functions.find((item: any) => item.function === 'FUN_14008d790')
    const llmNamed = data.functions.find((item: any) => item.function === 'FUN_1400d0580')
    const unresolved = data.functions.find((item: any) => item.function === 'FUN_140012340')

    expect(ruleNamed.name_resolution.rule_based_name).toBe('resolve_dynamic_apis')
    expect(ruleNamed.name_resolution.validated_name).toBe('resolve_dynamic_apis')
    expect(ruleNamed.name_resolution.resolution_source).toBe('rule')
    expect(ruleNamed.name_resolution.unresolved_semantic_name).toBe(false)

    expect(llmNamed.name_resolution.rule_based_name).toBeNull()
    expect(llmNamed.name_resolution.llm_suggested_name).toBe('scan_pe_layout_or_sections')
    expect(llmNamed.name_resolution.validated_name).toBe('scan_pe_layout_or_sections')
    expect(llmNamed.name_resolution.resolution_source).toBe('llm')
    expect(llmNamed.suggested_name).toBe('scan_pe_layout_or_sections')
    expect(llmNamed.semantic_evidence.string_hints).toContain('@Packer/Protector Detection')
    expect(llmNamed.semantic_evidence.cfg_shape.node_count).toBe(32)
    expect(llmNamed.source_like_snippet).toContain('name_resolution=source:llm')

    expect(unresolved.name_resolution.rule_based_name).toBeNull()
    expect(unresolved.name_resolution.llm_suggested_name).toBe('shared_semantic_candidate')
    expect(unresolved.name_resolution.validated_name).toBeNull()
    expect(unresolved.name_resolution.resolution_source).toBe('unresolved')
    expect(unresolved.name_resolution.unresolved_semantic_name).toBe(true)
    expect(unresolved.suggested_name).toBeNull()
    expect(unresolved.source_like_snippet).toContain('validated:none')

    expect(semanticNameSuggester).toHaveBeenCalledTimes(2)
    expect(seenEvidencePacks[0].string_hints.length).toBeGreaterThan(0)
    expect(seenEvidencePacks[0].pseudocode_excerpt.length).toBeGreaterThan(0)
  })

  test('should return degraded fallback when top-k ranking yields no functions', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    insertSample(sampleId, '3')

    const handler = createCodeFunctionsReconstructHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        rankFunctions: jest
          .fn<(sampleId: string, topK: number) => Promise<RankedFunction[]>>()
          .mockResolvedValue([]),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      topk: 5,
    })

    expect(result.ok).toBe(true)
    expect(result.warnings?.join(' ')).toContain('degraded fallback summary')
    const data = result.data as any
    expect(data.reconstructed_count).toBe(1)
    expect(data.functions[0].function).toBe('degraded_static_summary')
    expect(data.functions[0].gaps).toContain('missing_ghidra_analysis')
  })

  test('should cache reconstruction result', async () => {
    const sampleId = 'sha256:' + '4'.repeat(64)
    insertSample(sampleId, '4')

    const decompileFunction = jest
      .fn<
        (
          sampleId: string,
          addressOrSymbol: string,
          includeXrefs: boolean,
          timeoutMs: number
        ) => Promise<DecompiledFunction>
      >()
      .mockResolvedValue({
        function: 'target',
        address: '0x404000',
        pseudocode: 'int target(void) { return 0; }',
        callers: [],
        callees: [],
      })
    const getFunctionCFG = jest
      .fn<
        (
          sampleId: string,
          addressOrSymbol: string,
          timeoutMs: number
        ) => Promise<ControlFlowGraph>
      >()
      .mockResolvedValue({
        function: 'target',
        address: '0x404000',
        nodes: [
          {
            id: 'entry',
            address: '0x404000',
            instructions: ['ret'],
            type: 'entry',
          },
        ],
        edges: [],
      })

    const handler = createCodeFunctionsReconstructHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        decompileFunction,
        getFunctionCFG,
      }
    )

    const first = await handler({
      sample_id: sampleId,
      address: '0x404000',
    })
    const second = await handler({
      sample_id: sampleId,
      address: '0x404000',
    })

    expect(first.ok).toBe(true)
    expect(second.ok).toBe(true)
    expect(decompileFunction).toHaveBeenCalledTimes(1)
    expect(getFunctionCFG).toHaveBeenCalledTimes(1)
    expect(second.warnings).toContain('Result from cache')
    expect((second.metrics as any)?.cached).toBe(true)
  })

  test('should apply default timeout when omitted by caller', async () => {
    const sampleId = 'sha256:' + '7'.repeat(64)
    insertSample(sampleId, '7')

    const decompileFunction = jest
      .fn<
        (
          sampleId: string,
          addressOrSymbol: string,
          includeXrefs: boolean,
          timeoutMs: number
        ) => Promise<DecompiledFunction>
      >()
      .mockResolvedValue({
        function: 'default_timeout_target',
        address: '0x407000',
        pseudocode: 'int default_timeout_target(void) { return 0; }',
        callers: [],
        callees: [],
      })

    const getFunctionCFG = jest
      .fn<
        (
          sampleId: string,
          addressOrSymbol: string,
          timeoutMs: number
        ) => Promise<ControlFlowGraph>
      >()
      .mockResolvedValue({
        function: 'default_timeout_target',
        address: '0x407000',
        nodes: [],
        edges: [],
      })

    const handler = createCodeFunctionsReconstructHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        rankFunctions: jest
          .fn<(sampleId: string, topK: number) => Promise<RankedFunction[]>>()
          .mockResolvedValue([
            {
              address: '0x407000',
              name: 'default_timeout_target',
              score: 10,
              reasons: [],
            },
          ]),
        decompileFunction,
        getFunctionCFG,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      topk: 1,
    })

    expect(result.ok).toBe(true)
    expect(decompileFunction).toHaveBeenCalledWith(sampleId, '0x407000', false, 30000)
    expect(getFunctionCFG).toHaveBeenCalledWith(sampleId, '0x407000', 30000)
  })

  test('should consume externally applied semantic name suggestions from MCP artifacts', async () => {
    const sampleId = 'sha256:' + '4'.repeat(64)
    insertSample(sampleId, '4')
    await workspaceManager.createWorkspace(sampleId)

    await persistSemanticNameSuggestionsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: new Date().toISOString(),
      client_name: 'claude-desktop',
      model_name: 'generic-tool-calling-llm',
      suggestions: [
        {
          address: '0x40a100',
          candidate_name: 'classify_section_layout',
          confidence: 0.84,
          why: 'CFG size and control-flow shape suggest a pure section-layout classification helper.',
          required_assumptions: ['The helper is part of PE section inspection rather than generic dispatch.'],
          evidence_used: ['cfg:32_nodes', 'summary:section_layout_classifier'],
        },
      ],
    })

    const handler = createCodeFunctionsReconstructHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        rankFunctions: jest
          .fn<(sampleId: string, topK: number) => Promise<RankedFunction[]>>()
          .mockResolvedValue([
            {
              address: '0x40a100',
              name: 'FUN_1400d0580',
              score: 19,
              reasons: ['high_callers'],
            },
          ]),
        decompileFunction: jest
          .fn<
            (
              sampleId: string,
              addressOrSymbol: string,
              includeXrefs: boolean,
              timeoutMs: number
            ) => Promise<DecompiledFunction>
          >()
          .mockResolvedValue({
            function: 'FUN_1400d0580',
            address: '0x40a100',
            pseudocode: [
              'int FUN_1400d0580(void) {',
              '  int section_score = 0;',
              '  if (section_score > 4) { return 1; }',
              '  return 0;',
              '}',
            ].join('\n'),
            callers: [],
            callees: [],
          }),
        getFunctionCFG: jest
          .fn<
            (
              sampleId: string,
              addressOrSymbol: string,
              timeoutMs: number
            ) => Promise<ControlFlowGraph>
          >()
          .mockResolvedValue({
            function: 'FUN_1400d0580',
            address: '0x40a100',
            nodes: Array.from({ length: 32 }, (_, index) => ({
              id: `n${index}`,
              address: `0x${(0x40a100 + index).toString(16)}`,
              instructions: ['mov eax, eax'],
              type: index === 0 ? 'entry' : 'basic',
            })),
            edges: Array.from({ length: 36 }, (_, index) => ({
              from: `n${index % 31}`,
              to: `n${(index + 1) % 31}`,
              type: 'jump' as const,
            })),
          }),
        stringEvidenceLoader: jest.fn(async () => ({
          top_high_value: [],
          context_windows: [],
        })),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      topk: 1,
      include_xrefs: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const func = data.functions[0]
    expect(func.name_resolution.rule_based_name).toBeNull()
    expect(func.name_resolution.llm_suggested_name).toBe('classify_section_layout')
    expect(func.name_resolution.validated_name).toBe('classify_section_layout')
    expect(func.name_resolution.resolution_source).toBe('llm')
    expect(
      func.name_resolution.evidence_used.some((item: string) => item.startsWith('artifact:'))
    ).toBe(true)
    expect(func.suggested_name).toBe('classify_section_layout')
    expect(func.source_like_snippet).toContain('name_resolution=source:llm')
  })

  test('should scope externally applied semantic name suggestions by semantic session selector', async () => {
    const sampleId = 'sha256:' + '8'.repeat(64)
    insertSample(sampleId, '8')
    await workspaceManager.createWorkspace(sampleId)

    await persistSemanticNameSuggestionsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: '2026-03-11T00:00:00.000Z',
      session_tag: 'semantic-alpha',
      client_name: 'alpha-client',
      model_name: 'alpha-model',
      suggestions: [
        {
          address: '0x40b200',
          candidate_name: 'alpha_name',
          confidence: 0.88,
          why: 'alpha suggestion',
          evidence_used: ['alpha'],
        },
      ],
    })

    await persistSemanticNameSuggestionsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: '2026-03-11T00:01:00.000Z',
      session_tag: 'semantic-beta',
      client_name: 'beta-client',
      model_name: 'beta-model',
      suggestions: [
        {
          address: '0x40b200',
          candidate_name: 'beta_name',
          confidence: 0.9,
          why: 'beta suggestion',
          evidence_used: ['beta'],
        },
      ],
    })

    const handler = createCodeFunctionsReconstructHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        rankFunctions: jest
          .fn<(sampleId: string, topK: number) => Promise<RankedFunction[]>>()
          .mockResolvedValue([
            {
              address: '0x40b200',
              name: 'FUN_1400b200',
              score: 15,
              reasons: ['high_callers'],
            },
          ]),
        decompileFunction: jest
          .fn<(
            sampleId: string,
            addressOrSymbol: string,
            includeXrefs: boolean,
            timeoutMs: number
          ) => Promise<DecompiledFunction>>()
          .mockResolvedValue({
            function: 'FUN_1400b200',
            address: '0x40b200',
            pseudocode: 'int FUN_1400b200(void){return 1;}',
            callers: [],
            callees: [],
          }),
        getFunctionCFG: jest
          .fn<(sampleId: string, addressOrSymbol: string, timeoutMs: number) => Promise<ControlFlowGraph>>()
          .mockResolvedValue({
            function: 'FUN_1400b200',
            address: '0x40b200',
            nodes: [{ id: 'n0', address: '0x40b200', instructions: ['ret'], type: 'entry' }],
            edges: [],
          }),
        stringEvidenceLoader: jest.fn(async () => ({
          top_high_value: [],
          context_windows: [],
        })),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      topk: 1,
      semantic_scope: 'session',
      semantic_session_tag: 'semantic-beta',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.provenance.semantic_names.scope).toBe('session')
    expect(data.provenance.semantic_names.artifact_count).toBe(1)
    expect(data.provenance.semantic_names.session_tags).toContain('semantic-beta')
    expect(data.functions[0].name_resolution.validated_name).toBe('beta_name')
    expect(data.functions[0].name_resolution.llm_suggested_name).toBe('beta_name')
  })
})
