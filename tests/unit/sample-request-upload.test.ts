import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { createSampleRequestUploadHandler } from '../../src/tools/sample-request-upload.js'

describe('sample.request_upload tool', () => {
  let testDir: string
  let database: DatabaseManager

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sample-request-upload-'))
    database = new DatabaseManager(path.join(testDir, 'test.db'))
  })

  afterEach(() => {
    database.close()
    fs.rmSync(testDir, { recursive: true, force: true })
  })

  test('should create a persisted upload session with daemon-backed URLs', async () => {
    const handler = createSampleRequestUploadHandler(database, { apiPort: 19080 })
    const result = await handler({
      filename: 'Weixin.dll',
      ttl_seconds: 300,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      upload_url: string
      status_url: string
      token: string
      expires_at: string
      ttl_seconds: number
      result_mode: string
      tool_surface_role: string
      preferred_primary_tools: string[]
      recommended_next_tools: string[]
      next_actions: string[]
    }

    expect(data.upload_url).toBe(`http://localhost:19080/api/v1/uploads/${data.token}`)
    expect(data.status_url).toBe(
      `http://localhost:19080/api/v1/uploads/${data.token}/status`
    )
    expect(data.ttl_seconds).toBe(300)
    expect(data.result_mode).toBe('upload_session')
    expect(data.tool_surface_role).toBe('primary')
    expect(data.preferred_primary_tools).toContain('workflow.analyze.start')
    expect(data.recommended_next_tools).toContain('workflow.analyze.start')
    expect(data.next_actions[0]).toContain('POST the file bytes')

    const session = database.findUploadSessionByToken(data.token)
    expect(session).toBeDefined()
    expect(session?.status).toBe('pending')
    expect(session?.filename).toBe('Weixin.dll')
  })
})
