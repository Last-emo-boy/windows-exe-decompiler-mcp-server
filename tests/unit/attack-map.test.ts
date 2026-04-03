import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import crypto from 'crypto'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createAttackMapHandler, mapIndicatorsToAttack } from '../../src/plugins/threat-intel/tools/attack-map.js'

jest.setTimeout(15000)

describe('attack.map tool', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let handler: ReturnType<typeof createAttackMapHandler>

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attack-map-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    cacheManager = new CacheManager(path.join(tempDir, 'cache'), database)
    handler = createAttackMapHandler({ workspaceManager, database, cacheManager } as any)
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

  test('should map ATT&CK techniques from string and IOC evidence', async () => {
    const sample = Buffer.concat([
      Buffer.from('MZ', 'ascii'),
      Buffer.from('\x00'.repeat(256), 'binary'),
      Buffer.from(
        'powershell.exe -enc AAAA http://c2.example/a HKEY_CURRENT_USER\\Software\\Run',
        'utf-8'
      ),
    ])
    const sampleId = await ingestSample(workspaceManager, database, sample)

    const result = await handler({
      sample_id: sampleId,
      include_low_confidence: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      techniques: Array<{ technique_id: string }>
      capability_clusters: Array<{ capability: string }>
      tactic_summary: Record<string, number>
    }
    expect(data.techniques.length).toBeGreaterThan(0)
    const techniqueIds = data.techniques.map((item) => item.technique_id)
    expect(
      techniqueIds.includes('T1059.001') ||
        techniqueIds.includes('T1059.003') ||
        techniqueIds.includes('T1071.001')
    ).toBe(true)
    expect(data.capability_clusters.length).toBeGreaterThan(0)
    expect(Object.keys(data.tactic_summary).length).toBeGreaterThan(0)
  })

  test('should suppress weak ransomware mapping by default for dual-use tooling', () => {
    const indicators = {
      suspiciousImports: ['kernel32.dll!WriteProcessMemory', 'kernel32.dll!CreateProcessW'],
      suspiciousStrings: ['usage: akasha --pid 123', 'dump process memory'],
      commands: ['akasha --pid 123 dump'],
      urls: [],
      ips: [],
      registryKeys: [],
      yaraMatches: [],
      yaraLowConfidence: ['Ransomware_Indicators'],
      packed: false,
      packerConfidence: 0,
      intentLabel: 'dual_use_tool' as const,
      intentConfidence: 0.78,
    }

    const withoutLowConfidence = mapIndicatorsToAttack(indicators, {
      includeLowConfidence: false,
      maxTechniques: 20,
    })
    expect(withoutLowConfidence.techniques.some((item) => item.technique_id === 'T1486')).toBe(false)

    const withLowConfidence = mapIndicatorsToAttack(indicators, {
      includeLowConfidence: true,
      maxTechniques: 20,
    })
    const ransomwareTechnique = withLowConfidence.techniques.find(
      (item) => item.technique_id === 'T1486'
    )

    expect(ransomwareTechnique).toBeDefined()
    expect(ransomwareTechnique?.confidence_level).toBe('low')
    expect(ransomwareTechnique?.confidence).toBeLessThan(0.2)
    expect(ransomwareTechnique?.counter_evidence).toEqual(
      expect.arrayContaining([
        expect.stringContaining('low-confidence/string-heavy ransomware YARA hints'),
        expect.stringContaining('dual-use operator tool'),
      ])
    )
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
