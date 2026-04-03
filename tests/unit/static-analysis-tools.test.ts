import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createStaticCapabilityTriageHandler } from '../../src/tools/static-capability-triage.js'
import { createPEStructureAnalyzeHandler } from '../../src/plugins/pe-analysis/tools/pe-structure-analyze.js'
import { createCompilerPackerDetectHandler } from '../../src/tools/compiler-packer-detect.js'

describe('static analysis tools', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string

  beforeEach(async () => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-static-analysis-tools')
    testDbPath = path.join(process.cwd(), 'test-static-analysis-tools.db')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)

    const sampleId = 'sha256:' + 'e'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'e'.repeat(64),
      md5: 'e'.repeat(32),
      size: 4096,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const workspace = await workspaceManager.createWorkspace(sampleId)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), 'MZ', 'utf-8')
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

  test('static.capability.triage should normalize capability findings and persist artifact', async () => {
    const sampleId = 'sha256:' + 'e'.repeat(64)
    const handler = createStaticCapabilityTriageHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'worker-job-capability',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          status: 'ready',
          capability_count: 3,
          behavior_namespaces: ['host-interaction/process', 'communication/http'],
          capability_groups: {
            service: 1,
            network: 2,
          },
          capabilities: [
            {
              rule_id: 'service/install',
              name: 'install service',
              namespace: 'host-interaction/service',
              scopes: ['file'],
              group: 'service',
              confidence: 0.82,
              match_count: 1,
              evidence_summary: 'CreateServiceW import',
            },
            {
              rule_id: 'http/client',
              name: 'send HTTP request',
              namespace: 'communication/http',
              scopes: ['file'],
              group: 'network',
              confidence: 0.76,
              match_count: 2,
              evidence_summary: 'WinHTTP strings',
            },
          ],
          summary: 'Recovered static capabilities.',
          backend: {
            available: true,
            engine: 'capa',
            source: 'python_module',
            version: '9.3.1',
            rules: {
              available: true,
              path: 'C:/rules/capa',
              source: 'env',
            },
          },
        },
        artifacts: [],
        metrics: {
          elapsed_ms: 12,
        },
      }),
    })

    const result = await handler({ sample_id: sampleId, session_tag: 'static-session' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('ready')
    expect(data.capability_count).toBe(2)
    expect(data.capability_groups.network).toBe(2)
    expect(data.capabilities[0].name).toBe('install service')
    expect(data.artifact.type).toBe('static_capability_triage')
    expect(data.analysis_id).toBeDefined()

    const artifacts = database.findArtifactsByType(sampleId, 'static_capability_triage')
    expect(artifacts).toHaveLength(1)
    const analyses = database.findAnalysesBySample(sampleId)
    expect(analyses.some((item) => item.stage === 'static_capability_triage')).toBe(true)
  })

  test('pe.structure.analyze should merge backend detail and persist canonical PE structure output', async () => {
    const sampleId = 'sha256:' + 'e'.repeat(64)
    const handler = createPEStructureAnalyzeHandler({ workspaceManager, database } as any)
    // callWorker DI removed in plugin migration; test uses default worker path
    void ({
        job_id: 'worker-job-pe-structure',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          summary: {
            section_count: 5,
            import_dll_count: 3,
            import_function_count: 12,
            export_count: 1,
            forwarder_count: 0,
            resource_count: 2,
            overlay_present: true,
            parser_preference: 'lief',
          },
          headers: {
            machine: 'AMD64',
          },
          entry_point: {
            rva: 4096,
          },
          sections: [
            { name: '.text', size: 1024 },
          ],
          imports: {
            kernel32: ['CreateFileW'],
          },
          exports: {
            symbols: ['RunPlugin'],
          },
          resources: {
            count: 2,
          },
          overlay: {
            present: true,
          },
          backend_details: {
            pefile: { available: true },
            lief: { available: true },
          },
        },
        artifacts: [],
        metrics: {
          elapsed_ms: 15,
        },
      }),
    })

    const result = await handler({ sample_id: sampleId, session_tag: 'pe-structure-session' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('ready')
    expect(data.summary.overlay_present).toBe(true)
    expect(data.backend_details.lief.available).toBe(true)
    expect(data.analysis_id).toBeDefined()

    const artifacts = database.findArtifactsByType(sampleId, 'pe_structure_analysis')
    expect(artifacts).toHaveLength(1)
    const analyses = database.findAnalysesBySample(sampleId)
    expect(analyses.some((item) => item.stage === 'pe_structure_analysis')).toBe(true)
  })

  test('compiler.packer.detect should normalize Detect It Easy findings and persist attribution output', async () => {
    const sampleId = 'sha256:' + 'e'.repeat(64)
    const handler = createCompilerPackerDetectHandler(workspaceManager, database, {
      resolveBackend: () => ({
        available: true,
        source: 'config',
        path: 'C:/tools/diec.exe',
        version: '3.10',
        checked_candidates: ['C:/tools/diec.exe'],
        error: null,
      }),
      executeBackend: async () => ({
        format: 'json',
        command: ['C:/tools/diec.exe', '-j', 'sample.exe'],
        stdout: JSON.stringify({
          detects: [
            { name: 'PE32 executable', category: 'file_type' },
            { name: 'Microsoft Visual C++', category: 'compiler' },
            { name: 'UPX', category: 'packer' },
          ],
        }),
        stderr: '',
      }),
    })

    const result = await handler({ sample_id: sampleId, session_tag: 'compiler-session' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('ready')
    expect(data.summary.compiler_count).toBe(1)
    expect(data.summary.packer_count).toBe(1)
    expect(data.summary.likely_primary_file_type).toBe('PE32 executable')
    expect(data.compiler_findings[0].name).toBe('Microsoft Visual C++')
    expect(data.packer_findings[0].name).toBe('UPX')
    expect(data.artifact.type).toBe('compiler_packer_attribution')

    const artifacts = database.findArtifactsByType(sampleId, 'compiler_packer_attribution')
    expect(artifacts).toHaveLength(1)
    const analyses = database.findAnalysesBySample(sampleId)
    expect(analyses.some((item) => item.stage === 'compiler_packer_detection')).toBe(true)
  })

  test('compiler.packer.detect should return setup guidance when Detect It Easy is unavailable', async () => {
    const sampleId = 'sha256:' + 'e'.repeat(64)
    const handler = createCompilerPackerDetectHandler(workspaceManager, database, {
      resolveBackend: () => ({
        available: false,
        source: 'path',
        path: null,
        version: null,
        checked_candidates: ['diec.exe'],
        error: 'Detect It Easy not found',
      }),
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('setup_required')
    expect(result.setup_actions?.length).toBeGreaterThan(0)
    expect(result.required_user_inputs?.some((item: any) => item.key === 'die_path')).toBe(true)
  })
})
