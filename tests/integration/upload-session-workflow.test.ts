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
import { createSampleRequestUploadHandler } from '../../src/tools/sample-request-upload.js'
import { createSampleIngestHandler } from '../../src/tools/sample-ingest.js'

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

describe('upload session workflow', () => {
  let testDir: string
  let dbPath: string
  let auditLogPath: string
  let workspaceRoot: string
  let storageRoot: string
  let workerDatabase: DatabaseManager
  let daemonDatabase: DatabaseManager
  let fileServer: FileServer
  let port: number

  beforeEach(async () => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'upload-session-workflow-'))
    dbPath = path.join(testDir, 'test.db')
    auditLogPath = path.join(testDir, 'audit.log')
    workspaceRoot = path.join(testDir, 'workspaces')
    storageRoot = path.join(testDir, 'storage')
    port = 19080 + Math.floor(Math.random() * 1000)

    workerDatabase = new DatabaseManager(dbPath)
    daemonDatabase = new DatabaseManager(dbPath)

    const daemonWorkspaceManager = new WorkspaceManager(workspaceRoot)
    const daemonPolicyGuard = new PolicyGuard(auditLogPath)
    const storageManager = new StorageManager({
      root: storageRoot,
      maxFileSize: 500 * 1024 * 1024,
      retentionDays: 30,
    })
    await storageManager.initialize()

    fileServer = new FileServer(
      {
        port,
        maxFileSize: 500 * 1024 * 1024,
        storageRoot,
      },
      {
        storageManager,
        database: daemonDatabase,
        finalizationService: createSampleFinalizationService(
          daemonWorkspaceManager,
          daemonDatabase,
          daemonPolicyGuard
        ),
      }
    )
    await fileServer.start()
  })

  afterEach(async () => {
    await fileServer.stop()
    workerDatabase.close()
    daemonDatabase.close()
    fs.rmSync(testDir, { recursive: true, force: true })
  })

  test('should support cross-process upload and compatibility lookup', async () => {
    const requestUpload = createSampleRequestUploadHandler(workerDatabase, { apiPort: port })
    const workerWorkspaceManager = new WorkspaceManager(workspaceRoot)
    const workerPolicyGuard = new PolicyGuard(auditLogPath)
    const ingest = createSampleIngestHandler(
      workerWorkspaceManager,
      workerDatabase,
      workerPolicyGuard
    )

    const tokenResult = await requestUpload({
      filename: 'Weixin.dll',
      ttl_seconds: 300,
    })
    expect(tokenResult.ok).toBe(true)

    const tokenData = tokenResult.data as {
      upload_url: string
      status_url: string
      token: string
    }

    const uploadBody = Buffer.from('MZ\x90\x00\x03\x00\x00\x00')
    const uploadResponse = await httpRequest(tokenData.upload_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(uploadBody.length),
      },
      body: uploadBody,
    })

    expect(uploadResponse.statusCode).toBe(201)
    const uploadPayload = JSON.parse(uploadResponse.body)
    expect(uploadPayload.ok).toBe(true)
    expect(uploadPayload.data.sample_id).toMatch(/^sha256:[a-f0-9]{64}$/)

    const statusResponse = await httpRequest(tokenData.status_url)
    expect(statusResponse.statusCode).toBe(200)
    const statusPayload = JSON.parse(statusResponse.body)
    expect(statusPayload.data.status).toBe('registered')
    expect(statusPayload.data.sample_id).toBe(uploadPayload.data.sample_id)

    const compatibilityResult = await ingest({
      upload_url: tokenData.upload_url,
    })
    expect(compatibilityResult.ok).toBe(true)
    expect((compatibilityResult.data as { sample_id: string }).sample_id).toBe(
      uploadPayload.data.sample_id
    )
  })
})
