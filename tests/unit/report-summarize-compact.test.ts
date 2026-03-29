import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createReportSummarizeHandler } from '../../src/tools/report-summarize.js'
import { persistSemanticFunctionExplanationsArtifact } from '../../src/semantic-name-suggestion-artifacts.js'
import {
  persistStaticAnalysisJsonArtifact,
  STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
  PE_STRUCTURE_ANALYSIS_ARTIFACT_TYPE,
  COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE,
} from '../../src/static-analysis-artifacts.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'

describe('report.summarize compact mode', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-report-compact')
    testDbPath = path.join(process.cwd(), 'test-report-compact.db')
    testCachePath = path.join(process.cwd(), 'test-cache-report-compact')

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

  test('should default to compact output, emit artifact refs, and bound payload size', async () => {
    const sampleId = 'sha256:' + 'e'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'e'.repeat(64),
      md5: 'e'.repeat(32),
      size: 8192,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    await workspaceManager.createWorkspace(sampleId)

    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      sampleId,
      STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
      'static_capability',
      {
        sample_id: sampleId,
        status: 'ready',
        capability_count: 20,
        capability_groups: { network: 8, execution: 6, persistence: 3 },
        capabilities: Array.from({ length: 20 }, (_, index) => ({
          rule_id: `cap/${index}`,
          name: `capability-${index}`,
          namespace: 'execution/process',
          scopes: ['file'],
          group: 'execution',
          confidence: 0.7,
          match_count: 1,
          evidence_summary: `capability-${index}`,
        })),
        summary: 'Recovered capability findings.',
        backend: {
          available: true,
          engine: 'capa',
          source: 'python_module',
          version: '9.3.1',
          rules: {
            available: true,
            path: 'C:/rules/capa',
            source: 'env',
            error: null,
          },
          error: null,
        },
        confidence_semantics: null,
      },
      'summary-alpha'
    )

    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      sampleId,
      PE_STRUCTURE_ANALYSIS_ARTIFACT_TYPE,
      'pe_structure',
      {
        sample_id: sampleId,
        status: 'ready',
        summary: {
          section_count: 6,
          import_dll_count: 8,
          import_function_count: 148,
          export_count: 0,
          forwarder_count: 0,
          resource_count: 2,
          overlay_present: true,
          parser_preference: 'lief',
        },
        headers: {},
        entry_point: {},
        sections: [],
        imports: {},
        exports: {},
        resources: {},
        overlay: {},
        backend_details: {
          lief: {
            sections: Array.from({ length: 64 }, (_, index) => `section-${index}`),
          },
        },
        confidence_semantics: null,
      },
      'summary-alpha'
    )

    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      sampleId,
      COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE,
      'compiler_packer',
      {
        sample_id: sampleId,
        status: 'ready',
        compiler_findings: [{ name: 'MSVC', category: 'compiler', confidence: 0.81, evidence_summary: 'compiler', source: 'die-json' }],
        packer_findings: [{ name: 'UPX', category: 'packer', confidence: 0.79, evidence_summary: 'packer', source: 'die-json' }],
        protector_findings: [],
        file_type_findings: [],
        summary: {
          compiler_count: 1,
          packer_count: 1,
          protector_count: 0,
          file_type_count: 0,
          likely_primary_file_type: 'PE32 executable',
        },
        backend: {
          available: true,
          source: 'config',
          path: 'C:/tools/diec.exe',
          version: '3.10',
          checked_candidates: ['C:/tools/diec.exe'],
          error: null,
        },
        raw_backend: {
          stdout: 'x'.repeat(16000),
        },
        confidence_semantics: null,
      },
      'summary-alpha'
    )

    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: new Date().toISOString(),
      session_tag: 'summary-alpha',
      explanations: Array.from({ length: 5 }, (_, index) => ({
        address: `0x4010${index}`,
        function: `FUN_${index}`,
        summary: `semantic summary ${index} ` + 'z'.repeat(240),
        behavior: `behavior_${index}`,
        confidence: 0.7,
        rewrite_guidance: ['split init from dispatch', 'name helper tables clearly', 'remove dead stores'],
      })),
    })

    const triageHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        summary: 'Static triage suggests a multi-stage process manipulation utility.',
        confidence: 0.83,
        threat_level: 'suspicious',
        iocs: {
          suspicious_imports: Array.from({ length: 20 }, (_, index) => `kernel32!Api${index}`),
          suspicious_strings: Array.from({ length: 30 }, (_, index) => `string_${index}`),
          yara_matches: Array.from({ length: 12 }, (_, index) => `rule_${index}`),
        },
        evidence: Array.from({ length: 28 }, (_, index) => `evidence line ${index}`),
        recommendation: 'Review staged digests before requesting a final analyst narrative.',
      },
    })

    const handler = createReportSummarizeHandler(workspaceManager, database, cacheManager, {
      triageHandler,
    })
    const result = await handler({
      sample_id: sampleId,
      mode: 'triage',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.detail_level).toBe('compact')
    expect(data.tool_surface_role).toBe('compatibility')
    expect(data.preferred_primary_tools).toContain('workflow.summarize')
    expect(data.coverage_level).toBe('static_core')
    expect(data.completion_state).toBe('bounded')
    expect(Array.isArray(data.known_findings)).toBe(true)
    expect(Array.isArray(data.suspected_findings)).toBe(true)
    expect(Array.isArray(data.unverified_areas)).toBe(true)
    expect(data.upgrade_paths.some((item: any) => item.tool === 'workflow.summarize')).toBe(true)
    expect(data.static_capabilities).toBeUndefined()
    expect(data.compiler_packer).toBeUndefined()
    expect(data.function_explanations).toBeUndefined()
    expect(data.static_capability_summary.capability_count).toBe(20)
    expect(data.compiler_packer_summary.packer_names).toContain('UPX')
    expect(data.semantic_explanation_summary.count).toBe(5)
    expect(data.artifact_refs.supporting.length).toBeGreaterThanOrEqual(4)
    expect(data.artifact_refs.static_capabilities.length).toBe(1)
    expect(data.artifact_refs.compiler_packer.length).toBe(1)
    expect(Array.isArray(data.explanation_graphs)).toBe(true)
    expect(data.explanation_graphs.some((item: any) => item.graph_type === 'runtime_stage')).toBe(true)
    expect(data.artifact_refs.explanation_graphs.length).toBeGreaterThanOrEqual(1)
    expect(data.truncation.evidence.truncated).toBe(true)
    expect(data.truncation.suspicious_imports.truncated).toBe(true)
    expect(data.truncation.suspicious_strings.truncated).toBe(true)
    expect(data.recommended_next_tools).toContain('workflow.summarize')
    expect(JSON.stringify(data).length).toBeLessThan(50000)
  })

  test('should bound full output and omit heavyweight inline fields when payload grows too large', async () => {
    const sampleId = 'sha256:' + 'f'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'f'.repeat(64),
      md5: 'f'.repeat(32),
      size: 1024 * 1024,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    await workspaceManager.createWorkspace(sampleId)

    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      sampleId,
      STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
      'static_capability',
      {
        sample_id: sampleId,
        status: 'ready',
        capability_count: 320,
        capability_groups: { network: 120, execution: 110, persistence: 90 },
        capabilities: Array.from({ length: 320 }, (_, index) => ({
          rule_id: `cap/${index}`,
          name: `capability-${index}`,
          namespace: 'execution/process',
          scopes: ['file'],
          group: 'execution',
          confidence: 0.82,
          match_count: 3,
          evidence_summary: `capability-${index}-` + 'x'.repeat(512),
        })),
        summary: 'Recovered a large capability corpus.',
        backend: {
          available: true,
          engine: 'capa',
          source: 'python_module',
          version: '9.3.1',
          rules: {
            available: true,
            path: 'C:/rules/capa',
            source: 'env',
            error: null,
          },
          error: null,
        },
        confidence_semantics: null,
        raw_backend: {
          payload: 'y'.repeat(60_000),
        },
      },
      'summary-full'
    )

    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      sampleId,
      PE_STRUCTURE_ANALYSIS_ARTIFACT_TYPE,
      'pe_structure',
      {
        sample_id: sampleId,
        status: 'ready',
        summary: {
          section_count: 24,
          import_dll_count: 32,
          import_function_count: 640,
          export_count: 12,
          forwarder_count: 0,
          resource_count: 8,
          overlay_present: true,
          parser_preference: 'lief',
        },
        headers: { rich_header: 'z'.repeat(20_000) },
        entry_point: { thunk: 'z'.repeat(8_000) },
        sections: Array.from({ length: 128 }, (_, index) => ({ name: `.text${index}`, raw_size: 4096 })),
        imports: {
          kernel32: Array.from({ length: 256 }, (_, index) => `Api${index}`),
        },
        exports: Array.from({ length: 64 }, (_, index) => ({ name: `Export${index}`, ordinal: index })),
        resources: Array.from({ length: 64 }, (_, index) => ({ type: `R${index}`, size: 2048 })),
        overlay: { bytes_preview: 'o'.repeat(24_000) },
        backend_details: {
          lief: {
            sections: Array.from({ length: 128 }, (_, index) => `section-${index}-${'q'.repeat(256)}`),
          },
        },
        confidence_semantics: null,
      },
      'summary-full'
    )

    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      sampleId,
      COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE,
      'compiler_packer',
      {
        sample_id: sampleId,
        status: 'ready',
        compiler_findings: [{ name: 'MSVC', category: 'compiler', confidence: 0.81, evidence_summary: 'compiler', source: 'die-json' }],
        packer_findings: [{ name: 'UPX', category: 'packer', confidence: 0.79, evidence_summary: 'packer', source: 'die-json' }],
        protector_findings: [],
        file_type_findings: [],
        summary: {
          compiler_count: 1,
          packer_count: 1,
          protector_count: 0,
          file_type_count: 0,
          likely_primary_file_type: 'PE32 executable',
        },
        backend: {
          available: true,
          source: 'config',
          path: 'C:/tools/diec.exe',
          version: '3.10',
          checked_candidates: ['C:/tools/diec.exe'],
          error: null,
        },
        raw_backend: {
          stdout: 'p'.repeat(80_000),
        },
        confidence_semantics: null,
      },
      'summary-full'
    )

    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: new Date().toISOString(),
      session_tag: 'summary-full',
      explanations: Array.from({ length: 48 }, (_, index) => ({
        address: `0x402${index.toString(16).padStart(3, '0')}`,
        function: `FUN_${index}`,
        summary: `semantic summary ${index} ` + 'n'.repeat(1200),
        behavior: `behavior_${index}`,
        confidence: 0.7,
        rewrite_guidance: ['split init from dispatch', 'name helper tables clearly', 'remove dead stores'],
      })),
    })

    const triageHandler = async (_args: ToolArgs): Promise<WorkerResult> => ({
      ok: true,
      data: {
        summary: 'Static triage suggests a multi-stage process manipulation utility.',
        confidence: 0.88,
        threat_level: 'suspicious',
        iocs: {
          suspicious_imports: Array.from({ length: 600 }, (_, index) => `kernel32!Api${index}`),
          suspicious_strings: Array.from({ length: 900 }, (_, index) => `string_${index}_${'m'.repeat(48)}`),
          yara_matches: Array.from({ length: 160 }, (_, index) => `rule_${index}`),
        },
        evidence: Array.from({ length: 1200 }, (_, index) => `evidence line ${index} ${'e'.repeat(120)}`),
        recommendation: 'Review staged digests before requesting a final analyst narrative.',
      },
    })

    const handler = createReportSummarizeHandler(workspaceManager, database, cacheManager, {
      triageHandler,
    })
    const result = await handler({
      sample_id: sampleId,
      mode: 'triage',
      detail_level: 'full',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.detail_level).toBe('full')
    expect(data.tool_surface_role).toBe('compatibility')
    expect(data.preferred_primary_tools).toContain('workflow.summarize')
    expect(JSON.stringify(data).length).toBeLessThan(180000)
    expect(result.warnings?.some((item) => item.includes('Inline report payload was bounded'))).toBe(true)
    expect(data.truncation.inline_payload_budget.truncated).toBe(true)
    expect(data.static_capabilities).toBeUndefined()
    expect(data.pe_structure).toBeUndefined()
    expect(data.compiler_packer).toBeUndefined()
    expect(data.artifact_refs.supporting.length).toBeLessThanOrEqual(4)
    expect(data.artifact_refs.explanation_graphs.length).toBeGreaterThanOrEqual(1)
  })
})
