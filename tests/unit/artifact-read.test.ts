import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import crypto from 'crypto'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createArtifactReadHandler, ArtifactReadOutputSchema } from '../../src/tools/artifact-read.js'

describe('artifact.read tool', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let handler: ReturnType<typeof createArtifactReadHandler>

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'artifact-read-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    handler = createArtifactReadHandler(workspaceManager, database)
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('should return error for unknown sample', async () => {
    const result = await handler({
      sample_id: 'sha256:' + 'a'.repeat(64),
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should read latest artifact content by type', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-manifest-1',
        type: 'reconstruct_manifest',
        path: 'reports/reconstruct/demo/manifest.json',
        mime: 'application/json',
        content: JSON.stringify({ module_count: 2, modules: ['core', 'net'] }),
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_type: 'reconstruct_manifest',
    })

    expect(result.ok).toBe(true)
    expect(result.data).toBeDefined()
    const data = result.data as {
      artifact: { type: string }
      content?: string
      content_encoding?: string
    }
    expect(data.artifact.type).toBe('reconstruct_manifest')
    expect(data.content_encoding).toBe('utf8')
    expect(data.content).toContain('"module_count":2')
    expect(ArtifactReadOutputSchema.parse(result).data?.artifact.sample_id).toBe(setup.sampleId)
  })

  test('should support metadata-only mode via artifact_id selector', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-gaps-1',
        type: 'reconstruct_gaps',
        path: 'reports/reconstruct/demo/gaps.md',
        mime: 'text/markdown',
        content: '# gaps\n- unresolved symbol',
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_id: 'artifact-gaps-1',
      include_content: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      artifact: { id: string }
      content?: string
      bytes_read: number
      truncated: boolean
    }
    expect(data.artifact.id).toBe('artifact-gaps-1')
    expect(data.content).toBeUndefined()
    expect(data.bytes_read).toBe(0)
    expect(data.truncated).toBe(false)
  })

  test('should return a low-context profile without reading payload content', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-manifest-1',
        type: 'reconstruct_manifest',
        path: 'reports/reconstruct/demo/manifest.json',
        mime: 'application/json',
        content: JSON.stringify({ module_count: 2, modules: ['core', 'net'] }),
      },
      {
        id: 'artifact-gaps-1',
        type: 'reconstruct_gaps',
        path: 'reports/reconstruct/demo/gaps.md',
        mime: 'text/markdown',
        content: '# gaps\n- unresolved symbol',
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_id: 'artifact-manifest-1',
      read_mode: 'profile',
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      read_mode: string
      content?: string
      bytes_read: number
      artifact_profile?: {
        schema: string
        payload_kind: string
        suggested_read_mode: string
        read_args: { sample_id: string; artifact_id: string; read_mode: string }
      }
      related_artifacts?: Array<{
        artifact_id: string
        path: string
        suggested_read_mode: string
        read_args: { sample_id: string; artifact_id: string; read_mode: string }
      }>
    }
    expect(data.read_mode).toBe('profile')
    expect(data.content).toBeUndefined()
    expect(data.bytes_read).toBe(0)
    expect(data.artifact_profile).toEqual(
      expect.objectContaining({
        schema: 'rikune.artifact_profile.v1',
        payload_kind: 'json',
        suggested_read_mode: 'content',
        read_args: {
          sample_id: setup.sampleId,
          artifact_id: 'artifact-manifest-1',
          read_mode: 'content',
        },
      })
    )
    expect(data.related_artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          artifact_id: 'artifact-gaps-1',
          path: 'reports/reconstruct/demo/gaps.md',
          suggested_read_mode: 'summary',
          read_args: expect.objectContaining({
            sample_id: setup.sampleId,
            artifact_id: 'artifact-gaps-1',
            read_mode: 'summary',
          }),
        }),
      ])
    )
  })

  test('should return profile metadata for missing artifacts without reading payload', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [])
    database.insertArtifact({
      id: 'artifact-missing-1',
      sample_id: setup.sampleId,
      type: 'analysis_summary',
      path: 'reports/missing/summary.json',
      sha256: '0'.repeat(64),
      mime: 'application/json',
      created_at: new Date().toISOString(),
    })

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_id: 'artifact-missing-1',
      read_mode: 'profile',
    })

    expect(result.ok).toBe(true)
    expect(result.warnings?.some((item) => item.includes('file is missing'))).toBe(true)
    const data = result.data as {
      bytes_read: number
      total_size: number
      artifact_profile?: { exists: boolean; size_bytes: number }
    }
    expect(data.bytes_read).toBe(0)
    expect(data.total_size).toBe(0)
    expect(data.artifact_profile).toEqual(
      expect.objectContaining({
        exists: false,
        size_bytes: 0,
      })
    )
  })

  test('should return a bounded summary without full content', async () => {
    const content = [
      'cmd.exe /c whoami',
      'https://evil.example/a',
      'HKEY_CURRENT_USER\\Software\\Run',
      '\\\\.\\pipe\\demo',
      'A'.repeat(1024),
    ].join('\n')
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-log-1',
        type: 'sandbox_trace_json',
        path: 'reports/dynamic/run.log',
        mime: 'text/plain',
        content,
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_id: 'artifact-log-1',
      read_mode: 'summary',
      max_bytes: 512,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      read_mode: string
      content?: string
      content_encoding?: string
      bytes_read: number
      total_size: number
      truncated: boolean
      summary?: {
        schema: string
        preview?: string
        bytes_sampled: number
        total_size: number
        truncated: boolean
        highlights?: { urls?: string[]; registry_keys?: string[]; pipes?: string[] }
      }
    }
    expect(data.read_mode).toBe('summary')
    expect(data.content).toBeUndefined()
    expect(data.content_encoding).toBeUndefined()
    expect(data.bytes_read).toBe(512)
    expect(data.total_size).toBe(Buffer.byteLength(content))
    expect(data.truncated).toBe(true)
    expect(data.summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.artifact_summary.v1',
        bytes_sampled: 512,
        total_size: Buffer.byteLength(content),
        truncated: true,
      })
    )
    expect(data.summary?.preview).toContain('cmd.exe')
    expect(data.summary?.highlights?.urls?.[0]).toContain('https://evil.example/a')
    expect(data.summary?.highlights?.registry_keys?.[0]).toContain('HKEY_CURRENT_USER')
    expect(data.summary?.highlights?.pipes?.[0]).toContain('\\\\.\\pipe\\demo')
    expect(result.warnings?.some((item) => item.includes('truncated'))).toBe(true)
  })

  test('should summarize binary artifacts without misclassifying base64 as text', async () => {
    const binaryContent = Buffer.from([0x00, 0x01, 0x02, 0x03, 0xff, 0x00, 0xfe, 0x10])
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-binary-1',
        type: 'memory_dump',
        path: 'reports/dynamic/memory.bin',
        mime: 'application/octet-stream',
        content: binaryContent,
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_id: 'artifact-binary-1',
      read_mode: 'summary',
      max_bytes: 256,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      content?: string
      content_encoding?: string
      summary?: {
        payload_kind: string
        content_encoding: string
        preview?: string
        bytes_sampled: number
      }
    }
    expect(data.content).toBeUndefined()
    expect(data.content_encoding).toBeUndefined()
    expect(data.summary).toEqual(
      expect.objectContaining({
        payload_kind: 'binary',
        content_encoding: 'base64',
        bytes_sampled: binaryContent.length,
      })
    )
    expect(data.summary?.preview).toBeUndefined()
  })

  test('should truncate oversized artifact content', async () => {
    const largeContent = 'A'.repeat(4096)
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-large-1',
        type: 'reconstruct_manifest',
        path: 'reports/reconstruct/demo/manifest.json',
        mime: 'application/json',
        content: largeContent,
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_id: 'artifact-large-1',
      max_bytes: 512,
    })

    expect(result.ok).toBe(true)
    expect(result.warnings?.some((item) => item.includes('truncated'))).toBe(true)
    const data = result.data as {
      bytes_read: number
      total_size: number
      truncated: boolean
      content?: string
    }
    expect(data.bytes_read).toBe(512)
    expect(data.total_size).toBe(4096)
    expect(data.truncated).toBe(true)
    expect(data.content?.length).toBe(512)
  })

  test('should parse JSON content when parse_json=true', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-json-1',
        type: 'reconstruct_manifest',
        path: 'reports/reconstruct/demo/manifest.json',
        mime: 'application/json',
        content: '{"name":"demo","count":2}',
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_type: 'reconstruct_manifest',
      parse_json: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as { parsed_json?: { name: string; count: number } }
    expect(data.parsed_json?.name).toBe('demo')
    expect(data.parsed_json?.count).toBe(2)
  })

  test('should summarize truncated JSON using full-file shape without parse warnings', async () => {
    const content = JSON.stringify({
      schema: 'demo.large.v1',
      functions: Array.from({ length: 120 }, (_, index) => ({
        name: `FUN_${index.toString(16).padStart(8, '0')}`,
        address: `0040${index.toString(16).padStart(4, '0')}`,
        callees: ['puts', 'strcmp'],
      })),
    })
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-functions-1',
        type: 'ghidra_functions',
        path: 'ghidra/functions.json',
        mime: 'application/json',
        content,
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_id: 'artifact-functions-1',
      read_mode: 'summary',
      max_bytes: 512,
      parse_json: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      summary?: {
        truncated: boolean
        json_shape?: { top_level?: string; keys?: string[] }
        json_parse_warning?: string
      }
    }
    expect(data.summary?.truncated).toBe(true)
    expect(data.summary?.json_shape).toEqual(
      expect.objectContaining({
        top_level: 'object',
        keys: expect.arrayContaining(['schema', 'functions']),
      })
    )
    expect(data.summary?.json_parse_warning).toBeUndefined()
  })

  test('should include analyst-focused summary for enriched string artifacts', async () => {
    const content = JSON.stringify({
      sample_id: 'sha256:test',
      data: {
        strings: [
          { offset: 100, string: 'H嬅H兡 [锰烫烫烫烫烫烫H婹', encoding: 'gbk' },
          { offset: 200, string: 'Enter password:', encoding: 'ascii' },
          { offset: 220, string: 'Correct password, access granted', encoding: 'ascii' },
          { offset: 300, string: 'KERNEL32.dll', encoding: 'ascii' },
        ],
      },
    })
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-strings-1',
        type: 'enriched_string_analysis',
        path: 'reports/strings/default/enriched_strings.json',
        mime: 'application/json',
        content,
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_id: 'artifact-strings-1',
      read_mode: 'summary',
      max_bytes: 256,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      summary?: {
        domain_summary?: {
          high_signal_strings?: Array<{ string: string; reasons: string[] }>
          noise_filtered_count?: number
        }
      }
    }
    const highSignal = data.summary?.domain_summary?.high_signal_strings || []
    expect(highSignal.map((item) => item.string)).toEqual(
      expect.arrayContaining(['Enter password:', 'Correct password, access granted'])
    )
    expect(highSignal.some((item) => item.string.includes('烫'))).toBe(false)
    expect(data.summary?.domain_summary?.noise_filtered_count).toBeGreaterThan(0)
  })

  test('should extract IOC highlights from UTF-8 content', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-log-1',
        type: 'sandbox_trace_json',
        path: 'reports/dynamic/run.log',
        mime: 'text/plain',
        content:
          'cmd.exe /c whoami\nhttps://evil.example/a\nHKEY_CURRENT_USER\\Software\\Run\n\\\\.\\pipe\\demo',
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_id: 'artifact-log-1',
      ioc_highlights: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      highlights?: {
        urls?: string[]
        commands?: string[]
        registry_keys?: string[]
        pipes?: string[]
      }
    }
    expect(data.highlights?.urls?.[0]).toContain('https://evil.example/a')
    expect(data.highlights?.commands?.[0]).toContain('cmd.exe')
    expect(data.highlights?.registry_keys?.[0]).toContain('HKEY_CURRENT_USER')
    expect(data.highlights?.pipes?.[0]).toContain('\\\\.\\pipe\\demo')
  })

  test('should read untracked filesystem artifacts by path', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [])
    const workspace = await workspaceManager.getWorkspace(setup.sampleId)
    const relativePath = 'reports/triage/untracked-help.txt'
    await fs.mkdir(path.join(workspace.root, 'reports', 'triage'), { recursive: true })
    await fs.writeFile(
      path.join(workspace.root, relativePath),
      'usage: akasha --pid 123 --inject',
      'utf-8'
    )

    const result = await handler({
      sample_id: setup.sampleId,
      path: relativePath,
    })

    expect(result.ok).toBe(true)
    expect(result.warnings?.some((item) => item.includes('untracked filesystem artifact'))).toBe(
      true
    )
    const data = result.data as {
      artifact: { id: string; path: string }
      content?: string
    }
    expect(data.artifact.id.startsWith('fs:')).toBe(true)
    expect(data.artifact.path).toBe(relativePath)
    expect(data.content).toContain('usage: akasha')
  })
})

interface ArtifactFixture {
  id: string
  type: string
  path: string
  mime: string
  content: string | Buffer
}

async function setupSampleWithArtifacts(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  artifacts: ArtifactFixture[]
): Promise<{ sampleId: string }> {
  const binary = Buffer.from('MZ test sample')
  const sha256 = crypto.createHash('sha256').update(binary).digest('hex')
  const md5 = crypto.createHash('md5').update(binary).digest('hex')
  const sampleId = `sha256:${sha256}`

  database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
    id: sampleId,
    sha256,
    md5,
    size: binary.length,
    file_type: 'PE32',
    created_at: new Date().toISOString(),
    source: 'test',
  })

  const workspace = await workspaceManager.createWorkspace(sampleId)
  await fs.writeFile(path.join(workspace.original, 'sample.exe'), binary)

  for (const artifact of artifacts) {
    const absPath = path.join(workspace.root, artifact.path)
    await fs.mkdir(path.dirname(absPath), { recursive: true })
    await fs.writeFile(absPath, artifact.content)

    const fileSha256 = crypto.createHash('sha256').update(artifact.content).digest('hex')
    database.insertArtifact({
      id: artifact.id,
      sample_id: sampleId,
      type: artifact.type,
      path: artifact.path,
      sha256: fileSha256,
      mime: artifact.mime,
      created_at: new Date().toISOString(),
    })
  }

  return { sampleId }
}
