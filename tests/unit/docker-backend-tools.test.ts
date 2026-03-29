import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import {
  createGraphvizRenderHandler,
  createRizinAnalyzeHandler,
  createWineRunHandler,
} from '../../src/tools/docker-backend-tools.js'

describe('docker backend MCP tools', () => {
  const testRoot = path.join(process.cwd(), 'test-docker-backend-tools')
  const workspaceRoot = path.join(testRoot, 'workspaces')
  const dbPath = path.join(testRoot, 'test.db')
  const sampleSha = 'c'.repeat(64)
  const sampleId = `sha256:${sampleSha}`

  let database: DatabaseManager
  let workspaceManager: WorkspaceManager

  beforeEach(async () => {
    if (fs.existsSync(testRoot)) {
      fs.rmSync(testRoot, { recursive: true, force: true })
    }
    fs.mkdirSync(testRoot, { recursive: true })

    database = new DatabaseManager(dbPath)
    workspaceManager = new WorkspaceManager(workspaceRoot)

    database.insertSample({
      id: sampleId,
      sha256: sampleSha,
      md5: 'd'.repeat(32),
      size: 32,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const workspace = await workspaceManager.createWorkspace(sampleId)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), Buffer.from('MZtest'))
  })

  afterEach(() => {
    database.close()
    if (fs.existsSync(testRoot)) {
      fs.rmSync(testRoot, { recursive: true, force: true })
    }
  })

  test('graphviz.render should report setup_required when graphviz is unavailable', async () => {
    const handler = createGraphvizRenderHandler(workspaceManager, database, {
      resolveBackends: () => ({
        capa_cli: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        capa_rules: { available: false, source: 'none', path: null, error: null },
        die: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        graphviz: {
          available: false,
          source: 'none',
          path: null,
          version: null,
          checked_candidates: ['dot'],
          error: 'dot not found',
        },
        rizin: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        upx: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        wine: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        winedbg: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        frida_cli: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        yara_x: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        qiling: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        angr: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        panda: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        retdec: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      graph_text: 'digraph G { a -> b }',
    })

    expect(result.ok).toBe(true)
    expect((result.data as any).status).toBe('setup_required')
    expect((result.data as any).backend.error).toContain('dot not found')
  })

  test('rizin.analyze should return bounded previews from JSON output', async () => {
    const handler = createRizinAnalyzeHandler(workspaceManager, database, {
      resolveBackends: () => ({
        capa_cli: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        capa_rules: { available: false, source: 'none', path: null, error: null },
        die: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        graphviz: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        rizin: {
          available: true,
          source: 'config',
          path: '/opt/rizin/bin/rizin',
          version: '0.8.2',
          checked_candidates: ['rizin'],
          error: null,
        },
        upx: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        wine: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        winedbg: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        frida_cli: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        yara_x: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        qiling: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        angr: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        panda: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        retdec: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
      }),
      executeCommand: async () => ({
        stdout: JSON.stringify([
          { name: 'CreateFileW', ordinal: 1 },
          { name: 'WriteFile', ordinal: 2 },
          { name: 'ReadFile', ordinal: 3 },
        ]),
        stderr: '',
        exitCode: 0,
        timedOut: false,
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      operation: 'imports',
      max_items: 2,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    expect((result.data as any).status).toBe('ready')
    expect((result.data as any).item_count).toBe(3)
    expect((result.data as any).preview).toHaveLength(2)
  })

  test('wine.run should deny execution without approved=true', async () => {
    const handler = createWineRunHandler(workspaceManager, database, {
      resolveBackends: () => ({
        capa_cli: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        capa_rules: { available: false, source: 'none', path: null, error: null },
        die: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        graphviz: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        rizin: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        upx: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        wine: {
          available: true,
          source: 'config',
          path: '/usr/bin/wine',
          version: 'wine-9.0',
          checked_candidates: ['wine'],
          error: null,
        },
        winedbg: {
          available: true,
          source: 'config',
          path: '/usr/bin/winedbg',
          version: 'wine-9.0',
          checked_candidates: ['winedbg'],
          error: null,
        },
        frida_cli: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        yara_x: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        qiling: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        angr: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        panda: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        retdec: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      mode: 'run',
      approved: false,
    })

    expect(result.ok).toBe(true)
    expect((result.data as any).status).toBe('denied')
    expect(result.warnings).toContain('Wine execution requires approved=true.')
  })
})
