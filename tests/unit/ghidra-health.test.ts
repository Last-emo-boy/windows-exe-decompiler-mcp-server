import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createGhidraHealthHandler } from '../../src/tools/ghidra-health.js'

function parseToolText(result: { content: Array<{ text?: string }> }): any {
  return JSON.parse(result.content[0]?.text || '{}')
}

describe('ghidra.health tool', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghidra-health-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('should report downstream live probe status using a reusable analysis', async () => {
    const sampleId = 'sha256:' + 'a'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'a'.repeat(64),
      md5: 'b'.repeat(32),
      size: 128,
      file_type: 'PE32',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(path.join(workspace.original, 'sample.exe'), Buffer.from('MZ'))
    database.insertFunction({
      sample_id: sampleId,
      address: '0x401000',
      name: 'entry',
      size: 32,
      score: 0,
      tags: '[]',
      summary: null,
      caller_count: 0,
      callee_count: 0,
      is_entry_point: 1,
      is_exported: 0,
      callees: '[]',
    })
    database.insertAnalysis({
      id: 'analysis-1',
      sample_id: sampleId,
      stage: 'ghidra',
      backend: 'ghidra',
      status: 'done',
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      output_json: JSON.stringify({
        project_path: path.join(workspace.ghidra, 'project'),
        project_key: 'project',
        function_count: 1,
        readiness: {
          function_index: { available: true, status: 'ready' },
          decompile: { available: true, status: 'ready', target: '0x401000' },
          cfg: { available: true, status: 'ready', target: '0x401000' },
        },
      }),
      metrics_json: JSON.stringify({}),
    })

    const handler = createGhidraHealthHandler(workspaceManager, database, {
      checkGhidra: () => ({
        ok: true,
        checked_at: new Date().toISOString(),
        install_dir: 'C:/ghidra',
        analyze_headless_path: 'C:/ghidra/support/analyzeHeadless.bat',
        scripts_dir: path.join(process.cwd(), 'ghidra_scripts'),
        checks: {
          install_dir_exists: true,
          analyze_headless_exists: true,
          scripts_dir_exists: true,
          launch_ok: true,
          pyghidra_available: false,
        },
        errors: [],
        warnings: [],
      }),
      decompilerWorker: {
        async decompileFunction() {
          return {
            function: 'entry',
            address: '0x401000',
            pseudocode: 'return 0;',
            callers: [],
            callees: [],
          }
        },
        async getFunctionCFG() {
          return {
            function: 'entry',
            address: '0x401000',
            nodes: [{ id: 'n1', address: '0x401000', instructions: ['ret'], type: 'entry' as const }],
            edges: [],
          }
        },
      },
    })

    const payload = parseToolText(await handler({ sample_id: sampleId, include_end_to_end: true }))

    expect(payload.ok).toBe(true)
    expect(payload.data.downstream.sample_id).toBe(sampleId)
    expect(payload.data.downstream.live_probe.decompile.ok).toBe(true)
    expect(payload.data.downstream.live_probe.cfg.ok).toBe(true)
    expect(payload.data.setup_actions.map((item: any) => item.id)).toContain('install_pyghidra')
  })

  test('should report setup guidance when the Ghidra environment is not ready', async () => {
    const handler = createGhidraHealthHandler(workspaceManager, database, {
      checkGhidra: () => ({
        ok: false,
        checked_at: new Date().toISOString(),
        install_dir: '',
        analyze_headless_path: '',
        scripts_dir: path.join(process.cwd(), 'ghidra_scripts'),
        checks: {
          install_dir_exists: false,
          analyze_headless_exists: false,
          scripts_dir_exists: true,
          launch_ok: false,
          pyghidra_available: false,
        },
        errors: ['install dir not found'],
        warnings: [],
      }),
    })

    const payload = parseToolText(await handler({ include_end_to_end: false }))

    expect(payload.ok).toBe(false)
    expect(payload.data.setup_actions.map((item: any) => item.id)).toContain('set_ghidra_path')
    expect(payload.data.required_user_inputs.map((item: any) => item.key)).toContain(
      'ghidra_install_dir'
    )
  })
})
