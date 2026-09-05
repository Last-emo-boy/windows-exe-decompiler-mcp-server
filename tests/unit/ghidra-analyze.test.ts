import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createGhidraAnalyzeHandler, ghidraAnalyzeOutputSchema } from '../../src/plugins/ghidra/tools/ghidra-analyze.js'
import { DecompilerWorker, getGhidraDiagnostics, normalizeGhidraError } from '../../src/worker/decompiler-worker.js'

// Helper deps factory for ghidra analyze handler
function makeGhidraDeps(overrides: Record<string, any> = {}) {
  return {
    getGhidraDiagnostics,
    normalizeGhidraError,
    DecompilerWorker,
    findBestGhidraAnalysis: () => null,
    getGhidraReadiness: () => ({}),
    parseGhidraAnalysisMetadata: (output: any) => output,
    buildPollingGuidance: () => ({ prefer_sleep: true, recommended_wait_seconds: 30 }),
    logger: { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} },
    ...overrides,
  }
}

describe('ghidra.analyze tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-ghidra-analyze')
    testDbPath = path.join(process.cwd(), 'test-ghidra-analyze.db')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
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

  function insertSample(sampleId: string, hashChar: string) {
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: sampleId,
      sha256: hashChar.repeat(64),
      md5: hashChar.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })
  }

  test('should reuse completed analysis instead of queueing a new job', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    insertSample(sampleId, '1')
    for (const projectKey of ['reuse_key', 'unrelated_project']) {
      database.insertArtifact({
        id: `artifact-${projectKey}`, sample_id: sampleId, type: 'ghidra_functions',
        path: `ghidra/functions_${projectKey}.json`, sha256: 'a'.repeat(64),
        mime: 'application/json', created_at: new Date().toISOString(),
      })
    }

    database.insertAnalysis({
      id: 'analysis-reuse-1',
      sample_id: sampleId,
      stage: 'ghidra',
      backend: 'ghidra',
      status: 'done',
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      output_json: JSON.stringify({
        function_count: 42,
        project_path: 'workspaces/sample/ghidra/project_reuse',
        project_key: 'reuse_key',
        readiness: {
          function_index: { available: true, status: 'ready' },
          decompile: { available: true, status: 'ready' },
          cfg: { available: true, status: 'ready' },
        },
      }),
      metrics_json: null,
    })

    const enqueue = jest.fn(async () => 'job-should-not-be-used')
    const handler = createGhidraAnalyzeHandler({ workspaceManager, database, jobQueue: { enqueue }, ...makeGhidraDeps({
      findBestGhidraAnalysis: (analyses: any[]) => analyses.find((a: any) => a.backend === 'ghidra'),
      parseGhidraAnalysisMetadata: (outputJson: any) => {
        try { return typeof outputJson === 'string' ? JSON.parse(outputJson) : outputJson || {} } catch { return {} }
      },
      getGhidraReadiness: () => ({
        function_index: { available: true, status: 'ready' },
        decompile: { available: true, status: 'ready' },
        cfg: { available: true, status: 'ready' },
      }),
    }) } as any)

    const result = await handler({ sample_id: sampleId })
    const payload = JSON.parse(String(result.content[0]?.text || '{}'))

    expect(payload.ok).toBe(true)
    expect(payload.data.analysis_id).toBe('analysis-reuse-1')
    expect(payload.data.status).toBe('reused')
    expect(payload.data.result_mode).toBe('reused')
    expect(payload.data.recommended_next_tools).toContain('workflow.reconstruct')
    expect(payload.data.function_count).toBe(42)
    expect(payload.data.artifact_refs).toEqual([{
      id: 'artifact-reuse_key', type: 'ghidra_functions',
      path: 'ghidra/functions_reuse_key.json', sha256: 'a'.repeat(64), mime: 'application/json',
    }])
    expect(ghidraAnalyzeOutputSchema.parse(payload).data?.artifact_refs).toEqual(payload.data.artifact_refs)
    expect(enqueue).not.toHaveBeenCalled()
    expect((result as any).structuredContent.data.result_mode).toBe('reused')
  })

  test.each(['done', 'partial_success'] as const)('exposes persisted artifact selectors after %s analysis', async (status) => {
    const sampleId = 'sha256:' + '4'.repeat(64)
    insertSample(sampleId, '4')
    const type = status === 'done' ? 'ghidra_functions' : 'function_recovery'
    database.insertAnalysis({
      id: 'analysis-artifacts', sample_id: sampleId, stage: 'ghidra', backend: 'ghidra',
      status, started_at: new Date().toISOString(), finished_at: new Date().toISOString(),
      output_json: JSON.stringify({ project_key: 'selected' }), metrics_json: null,
    })
    database.insertArtifact({
      id: 'artifact-selected', sample_id: sampleId, type,
      path: 'ghidra/functions_selected.json', sha256: 'b'.repeat(64),
      mime: 'application/json', created_at: new Date().toISOString(),
    })
    const analyzeSpy = jest.spyOn(DecompilerWorker.prototype, 'analyze').mockResolvedValue({
      analysisId: 'analysis-artifacts', backend: 'ghidra', functionCount: 2,
      projectPath: 'ghidra/selected', status,
    })
    try {
      const handler = createGhidraAnalyzeHandler({ workspaceManager, database, ...makeGhidraDeps({
        parseGhidraAnalysisMetadata: (value: string) => JSON.parse(value || '{}'),
      }) } as any)
      const result = await handler({ sample_id: sampleId })
      const payload = ghidraAnalyzeOutputSchema.parse(result.structuredContent)
      expect(payload.ok).toBe(true)
      expect(payload.data?.artifact_refs).toEqual([{
        id: 'artifact-selected', type, path: 'ghidra/functions_selected.json',
        sha256: 'b'.repeat(64), mime: 'application/json',
      }])
    } finally {
      analyzeSpy.mockRestore()
    }
  })

  test('should return matching job_id when queueing a fresh analysis', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    insertSample(sampleId, '2')

    const enqueue = jest.fn(async () => 'job-123')
    const handler = createGhidraAnalyzeHandler({ workspaceManager, database, jobQueue: { enqueue }, ...makeGhidraDeps() } as any)

    const result = await handler({
      sample_id: sampleId,
      options: { timeout: 60, max_cpu: '2' },
    })
    const payload = JSON.parse(String(result.content[0]?.text || '{}'))

    expect(payload.ok).toBe(true)
    expect(payload.data.analysis_id).toBe('job-123')
    expect(payload.data.job_id).toBe('job-123')
    expect(payload.data.status).toBe('queued')
    expect(payload.data.result_mode).toBe('queued')
    expect(payload.data.polling_guidance.prefer_sleep).toBe(true)
    expect(payload.data.polling_guidance.recommended_wait_seconds).toBeGreaterThan(0)
    expect(payload.data.next_actions[0]).toContain('recommended polling interval')
    expect(enqueue).toHaveBeenCalledTimes(1)
  })

  test('should accept and forward Rust-oriented Ghidra analysis options', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    insertSample(sampleId, '3')

    const analyzeSpy = jest
      .spyOn(DecompilerWorker.prototype, 'analyze')
      .mockResolvedValue({
        analysisId: 'analysis-rust-1',
        backend: 'ghidra',
        functionCount: 7,
        projectPath: 'workspaces/sample/ghidra/project_rust',
        status: 'partial_success',
        warnings: ['Recovered 7 function candidates from PE exception metadata after Ghidra post-script extraction failed.'],
        readiness: {
          function_index: { available: true, status: 'degraded' },
          decompile: { available: false, status: 'missing' },
          cfg: { available: false, status: 'missing' },
        },
      })

    try {
      const handler = createGhidraAnalyzeHandler({ workspaceManager, database, ...makeGhidraDeps() } as any)
      const result = await handler({
        sample_id: sampleId,
        options: {
          timeout: 90,
          max_cpu: '2',
          project_key: 'rust_project',
          processor: 'x86:LE:64:default',
          language_id: 'x86:LE:64:default',
          cspec: 'windows',
          script_paths: ['C:\\custom-ghidra-scripts', 'D:\\alt-scripts'],
        },
      })
      const payload = JSON.parse(String(result.content[0]?.text || '{}'))

      expect(payload.ok).toBe(true)
      expect(payload.data.analysis_id).toBe('analysis-rust-1')
      expect(payload.data.function_count).toBe(7)
      expect(payload.data.result_mode).toBe('partial_success')
      expect(analyzeSpy).toHaveBeenCalledWith(
        sampleId,
        expect.objectContaining({
          timeout: 90000,
          maxCpu: '2',
          projectKey: 'rust_project',
          processor: 'x86:LE:64:default',
          languageId: 'x86:LE:64:default',
          cspec: 'windows',
          scriptPaths: ['C:\\custom-ghidra-scripts', 'D:\\alt-scripts'],
        })
      )
    } finally {
      analyzeSpy.mockRestore()
    }
  })
})
