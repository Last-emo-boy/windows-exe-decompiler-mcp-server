import { beforeEach, afterEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import http from 'http'
import { DatabaseManager } from '../../src/database.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { StorageManager } from '../../src/storage/storage-manager.js'
import { FileServer } from '../../src/api/file-server.js'
import { createSampleFinalizationService } from '../../src/sample-finalization.js'

function httpRequest(
  url: string,
  options: {
    method?: string
    headers?: Record<string, string>
    body?: Buffer
  } = {}
): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    const target = new URL(url)
    const req = http.request(
      {
        method: options.method || 'GET',
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        headers: options.headers,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 0,
            body: Buffer.concat(chunks).toString('utf8'),
          })
        })
      }
    )

    req.on('error', reject)
    if (options.body) {
      req.write(options.body)
    }
    req.end()
  })
}

describe('file server API hardening', () => {
  let testDir: string
  let dbPath: string
  let auditLogPath: string
  let workspaceRoot: string
  let storageRoot: string
  let database: DatabaseManager
  let fileServer: FileServer
  let port: number

  beforeEach(async () => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'file-server-api-'))
    dbPath = path.join(testDir, 'test.db')
    auditLogPath = path.join(testDir, 'audit.log')
    workspaceRoot = path.join(testDir, 'workspaces')
    storageRoot = path.join(testDir, 'storage')
    port = 20080 + Math.floor(Math.random() * 1000)

    database = new DatabaseManager(dbPath)

    const workspaceManager = new WorkspaceManager(workspaceRoot)
    const policyGuard = new PolicyGuard(auditLogPath)
    const storageManager = new StorageManager({
      root: storageRoot,
      maxFileSize: 32,
      retentionDays: 30,
    })
    await storageManager.initialize()

    fileServer = new FileServer(
      {
        port,
        apiKey: 'secret-key',
        maxFileSize: 32,
        storageRoot,
      },
      {
        storageManager,
        database,
        finalizationService: createSampleFinalizationService(
          workspaceManager,
          database,
          policyGuard
        ),
      }
    )
    await fileServer.start()
  })

  afterEach(async () => {
    await fileServer.stop()
    database.close()
    fs.rmSync(testDir, { recursive: true, force: true })
  })

  test('should return 413 for oversized upload-session payloads', async () => {
    const session = database.createUploadSession({
      filename: 'oversized.bin',
      source: 'test',
      expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    })

    const response = await httpRequest(`http://localhost:${port}/api/v1/uploads/${session.token}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
      },
      body: Buffer.alloc(64, 0x41),
    })

    expect(response.statusCode).toBe(413)
    const payload = JSON.parse(response.body)
    expect(payload.error).toBe('Payload Too Large')
    expect(payload.message).toContain('exceeds limit')
  })

  test('should return 400 for malformed direct uploads', async () => {
    const response = await httpRequest(`http://localhost:${port}/api/v1/samples`, {
      method: 'POST',
      headers: {
        'Content-Type': 'multipart/form-data',
        'X-API-Key': 'secret-key',
      },
      body: Buffer.from('not-a-valid-multipart-body', 'utf8'),
    })

    expect(response.statusCode).toBe(400)
    const payload = JSON.parse(response.body)
    expect(payload.error).toBe('Bad Request')
    expect(payload.message).toContain('missing boundary')
  })

  test('should enforce API key policy on sample metadata reads', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'b'.repeat(64),
      md5: 'b'.repeat(32),
      size: 128,
      file_type: 'PE32',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const withoutKey = await httpRequest(
      `http://localhost:${port}/api/v1/samples/${encodeURIComponent(sampleId)}`
    )
    expect(withoutKey.statusCode).toBe(401)

    const wrongKey = await httpRequest(
      `http://localhost:${port}/api/v1/samples/${encodeURIComponent(sampleId)}`,
      {
        headers: {
          'X-API-Key': 'wrong-key',
        },
      }
    )
    expect(wrongKey.statusCode).toBe(403)

    const success = await httpRequest(
      `http://localhost:${port}/api/v1/samples/${encodeURIComponent(sampleId)}`,
      {
        headers: {
          'X-API-Key': 'secret-key',
        },
      }
    )
    expect(success.statusCode).toBe(200)
    const payload = JSON.parse(success.body)
    expect(payload.ok).toBe(true)
    expect(payload.data.sample_id).toBe(sampleId)
  })
})
