import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { createCompilerPackerDetectHandler } from '../../src/tools/compiler-packer-detect.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'

describe('compiler.packer.detect noisy backend output', () => {
  const testRoot = path.join(process.cwd(), 'test-compiler-packer-detect')
  const workspaceRoot = path.join(testRoot, 'workspaces')
  const dbPath = path.join(testRoot, 'test.db')
  const sampleSha = 'a'.repeat(64)
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
      md5: 'b'.repeat(32),
      size: 16,
      file_type: 'PE',
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

  test('should recover findings from JSON mode output with a noisy preamble', async () => {
    const handler = createCompilerPackerDetectHandler(workspaceManager, database, {
      resolveBackend: () => ({
        available: true,
        source: 'config',
        path: '/usr/bin/diec',
        version: '3.10',
        checked_candidates: ['diec'],
        error: null,
      }),
      executeBackend: async () => ({
        stdout: [
          '[!] Heuristic mode enabled',
          '{"name":"Microsoft Visual C/C++","category":"compiler"}',
        ].join('\n'),
        stderr: '',
        format: 'json',
        command: ['/usr/bin/diec', '-j', '/tmp/sample.exe'],
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      persist_artifact: false,
      register_analysis: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('ready')
    expect(data.compiler_findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: 'Microsoft Visual C/C++',
          category: 'compiler',
        }),
      ])
    )
  })
})
