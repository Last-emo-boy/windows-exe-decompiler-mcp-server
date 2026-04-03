import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import crypto from 'crypto'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createIOCExportHandler } from '../../src/plugins/threat-intel/tools/ioc-export.js'

jest.setTimeout(15000)

describe('ioc.export tool', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let handler: ReturnType<typeof createIOCExportHandler>

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ioc-export-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    cacheManager = new CacheManager(path.join(tempDir, 'cache'), database)
    handler = createIOCExportHandler({ workspaceManager, database, cacheManager } as any)
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('should return error for unknown sample', async () => {
    const result = await handler({
      sample_id: `sha256:${'a'.repeat(64)}`,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should export IOC bundle in JSON and persist artifact', async () => {
    const sample = Buffer.concat([
      Buffer.from('MZ', 'ascii'),
      Buffer.from('\x00'.repeat(128), 'binary'),
      Buffer.from(
        'http://download.example/payload powershell.exe HKEY_CURRENT_USER\\Software\\Run',
        'utf-8'
      ),
    ])
    const sampleId = await ingestSample(workspaceManager, database, sample)

    const result = await handler({
      sample_id: sampleId,
      format: 'json',
      include_attack_map: true,
      persist_artifact: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      format: string
      ioc_count: number
      content: string
      attack_technique_count: number
      artifact?: { id: string; type: string }
    }
    expect(data.format).toBe('json')
    expect(data.ioc_count).toBeGreaterThan(0)
    expect(data.content).toContain('"sample_id"')
    expect(data.attack_technique_count).toBeGreaterThanOrEqual(0)
    expect(data.artifact?.type).toBe('ioc_export_json')
  })

  test('should export IOC bundle in CSV without persistence', async () => {
    const sampleId = await ingestSample(
      workspaceManager,
      database,
      Buffer.concat([
        Buffer.from('MZ', 'ascii'),
        Buffer.from('\x00'.repeat(128), 'binary'),
        Buffer.from('cmd.exe /c whoami http://example.org', 'utf-8'),
      ])
    )

    const result = await handler({
      sample_id: sampleId,
      format: 'csv',
      include_attack_map: false,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as { content: string; artifact?: unknown }
    expect(data.content.split('\n')[0]).toBe('type,value,confidence,source,tags')
    expect(data.artifact).toBeUndefined()
  })
})

async function ingestSample(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  data: Buffer
): Promise<string> {
  const sha256 = crypto.createHash('sha256').update(data).digest('hex')
  const md5 = crypto.createHash('md5').update(data).digest('hex')
  const sampleId = `sha256:${sha256}`

  database.insertSample({
    id: sampleId,
    sha256,
    md5,
    size: data.length,
    file_type: 'PE32',
    created_at: new Date().toISOString(),
    source: 'test',
  })

  const workspace = await workspaceManager.createWorkspace(sampleId)
  await fs.writeFile(path.join(workspace.original, 'sample.exe'), data)
  return sampleId
}
