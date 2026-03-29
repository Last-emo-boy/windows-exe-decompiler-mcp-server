/**
 * Unit tests for sample.ingest tool
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { createSampleIngestHandler, SampleIngestOutput } from '../../src/tools/sample-ingest.js'

describe('sample.ingest tool', () => {
  const testDir = './test-data-sample-ingest'
  const workspaceRoot = path.join(testDir, 'workspaces')
  const dbPath = path.join(testDir, 'test.db')
  const auditLogPath = path.join(testDir, 'audit.log')

  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let policyGuard: PolicyGuard
  let handler: ReturnType<typeof createSampleIngestHandler>

  beforeEach(() => {
    // Clean up test directory
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true })
    }
    fs.mkdirSync(testDir, { recursive: true })

    // Initialize components
    workspaceManager = new WorkspaceManager(workspaceRoot)
    database = new DatabaseManager(dbPath)
    policyGuard = new PolicyGuard(auditLogPath)
    handler = createSampleIngestHandler(workspaceManager, database, policyGuard)
  })

  afterEach(() => {
    // Clean up
    database.close()
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true })
    }
  })

  describe('Basic ingestion', () => {
    test('should ingest sample from file path', async () => {
      // Create test file
      const testFilePath = path.join(testDir, 'test-sample.exe')
      const testData = Buffer.from('MZ\x90\x00\x03\x00\x00\x00') // PE header
      fs.writeFileSync(testFilePath, testData)

      // Ingest sample
      const result = await handler({ path: testFilePath })
      const data = result.data as SampleIngestOutput['data']

      // Verify result
      expect(result.ok).toBe(true)
      expect(data).toBeDefined()
      expect(data?.sample_id).toMatch(/^sha256:[a-f0-9]{64}$/)
      expect(data?.size).toBe(testData.length)
      expect(data?.file_type).toBe('PE')
      expect(data?.existed).toBeUndefined()

      // Verify database record
      const sample = database.findSample(data?.sample_id as string)
      expect(sample).toBeDefined()
      expect(sample?.sha256).toBe(crypto.createHash('sha256').update(testData).digest('hex'))
      expect(sample?.md5).toBe(crypto.createHash('md5').update(testData).digest('hex'))
    })

    test('should ingest sample from Base64 encoded data', async () => {
      // Create test data
      const testData = Buffer.from('MZ\x90\x00\x03\x00\x00\x00') // PE header
      const base64Data = testData.toString('base64')

      // Ingest sample
      const result = await handler({ 
        bytes_b64: base64Data,
        filename: 'test.exe',
      })
      const data = result.data as SampleIngestOutput['data']

      // Verify result
      expect(result.ok).toBe(true)
      expect(data).toBeDefined()
      expect(data?.sample_id).toMatch(/^sha256:[a-f0-9]{64}$/)
      expect(data?.size).toBe(testData.length)
    })

    test('should use custom filename when provided', async () => {
      const testData = Buffer.from('MZ\x90\x00\x03\x00\x00\x00')
      const base64Data = testData.toString('base64')
      const customFilename = 'custom-sample.exe'

      const result = await handler({ 
        bytes_b64: base64Data,
        filename: customFilename,
      })
      const data = result.data as SampleIngestOutput['data']

      expect(result.ok).toBe(true)
      
      // Verify file was stored with custom filename
      const workspace = await workspaceManager.getWorkspace(data?.sample_id as string)
      const storedFilePath = path.join(workspace.original, customFilename)
      expect(fs.existsSync(storedFilePath)).toBe(true)
    })

    test('should prefer path when both path and bytes_b64 are provided', async () => {
      const testFilePath = path.join(testDir, 'path-wins.exe')
      const pathData = Buffer.from('MZ\x90\x00\x03\x00\x00\x00')
      fs.writeFileSync(testFilePath, pathData)

      const result = await handler({
        path: testFilePath,
        bytes_b64: 'invalid-base64!!!',
        filename: 'ignored.bin',
      })
      const data = result.data as SampleIngestOutput['data']

      expect(result.ok).toBe(true)
      expect(data?.size).toBe(pathData.length)

      const sample = database.findSample(data?.sample_id as string)
      expect(sample?.sha256).toBe(crypto.createHash('sha256').update(pathData).digest('hex'))
    })
  })

  describe('SHA256 deduplication (Requirement 1.2)', () => {
    test('should return existing sample_id for duplicate SHA256', async () => {
      const testData = Buffer.from('MZ\x90\x00\x03\x00\x00\x00')
      const base64Data = testData.toString('base64')

      // First ingestion
      const result1 = await handler({ bytes_b64: base64Data })
      const data1 = result1.data as SampleIngestOutput['data']
      expect(result1.ok).toBe(true)
      const sampleId1 = data1?.sample_id

      // Second ingestion with same data
      const result2 = await handler({ bytes_b64: base64Data })
      const data2 = result2.data as SampleIngestOutput['data']
      expect(result2.ok).toBe(true)
      expect(data2?.sample_id).toBe(sampleId1)
      expect(data2?.existed).toBe(true)

      // Verify only one database record exists
      const samples = database.getDatabase().prepare('SELECT COUNT(*) as count FROM samples').get() as { count: number }
      expect(samples.count).toBe(1)
    })
  })

  describe('File size limit (Requirement 1.3)', () => {
    test('should reject samples exceeding 500MB', async () => {
      // Create large file (simulate 501MB)
      const largeSize = 501 * 1024 * 1024
      const largeFilePath = path.join(testDir, 'large-sample.bin')
      
      // Write in chunks to avoid memory issues
      const fd = fs.openSync(largeFilePath, 'w')
      const chunkSize = 10 * 1024 * 1024 // 10MB chunks
      const chunk = Buffer.alloc(chunkSize, 0)
      for (let i = 0; i < Math.ceil(largeSize / chunkSize); i++) {
        fs.writeSync(fd, chunk)
      }
      fs.closeSync(fd)

      const result = await handler({ 
        path: largeFilePath,
      })

      expect(result.ok).toBe(false)
      expect(result.errors).toBeDefined()
      expect(result.errors?.[0]).toContain('exceeds maximum limit')
      expect(result.errors?.[0]).toContain('500MB')
      
      // Cleanup
      fs.unlinkSync(largeFilePath)
    })

    test('should accept samples at exactly 500MB', async () => {
      // Create file at exactly 500MB
      const maxSize = 500 * 1024 * 1024
      const maxFilePath = path.join(testDir, 'max-sample.bin')
      
      // Write in chunks to avoid memory issues
      const fd = fs.openSync(maxFilePath, 'w')
      const chunkSize = 10 * 1024 * 1024 // 10MB chunks
      const chunk = Buffer.alloc(chunkSize, 0)
      for (let i = 0; i < maxSize / chunkSize; i++) {
        fs.writeSync(fd, chunk)
      }
      fs.closeSync(fd)

      const result = await handler({ 
        path: maxFilePath,
      })
      const data = result.data as SampleIngestOutput['data']

      expect(result.ok).toBe(true)
      expect(data?.size).toBe(maxSize)
      
      // Cleanup
      fs.unlinkSync(maxFilePath)
    })
  })

  describe('Workspace creation (Requirement 1.4)', () => {
    test('should create workspace with correct structure', async () => {
      const testData = Buffer.from('MZ\x90\x00\x03\x00\x00\x00')
      const base64Data = testData.toString('base64')

      const result = await handler({ bytes_b64: base64Data })
      const data = result.data as SampleIngestOutput['data']
      expect(result.ok).toBe(true)

      const sampleId = data?.sample_id as string
      const workspace = await workspaceManager.getWorkspace(sampleId)

      // Verify workspace directories exist
      expect(fs.existsSync(workspace.root)).toBe(true)
      expect(fs.existsSync(workspace.original)).toBe(true)
      expect(fs.existsSync(workspace.cache)).toBe(true)
      expect(fs.existsSync(workspace.ghidra)).toBe(true)
      expect(fs.existsSync(workspace.reports)).toBe(true)

      // Verify sample file exists
      const files = fs.readdirSync(workspace.original)
      expect(files.length).toBeGreaterThan(0)
    })
  })

  describe('Hash computation (Requirement 1.1)', () => {
    test('should compute correct SHA256 and MD5 hashes', async () => {
      const testData = Buffer.from('test data for hashing')
      const expectedSha256 = crypto.createHash('sha256').update(testData).digest('hex')
      const expectedMd5 = crypto.createHash('md5').update(testData).digest('hex')

      const result = await handler({ 
        bytes_b64: testData.toString('base64'),
      })
      const data = result.data as SampleIngestOutput['data']

      expect(result.ok).toBe(true)
      
      const sample = database.findSample(data?.sample_id as string)
      expect(sample?.sha256).toBe(expectedSha256)
      expect(sample?.md5).toBe(expectedMd5)
      expect(data?.sample_id).toBe(`sha256:${expectedSha256}`)
    })
  })

  describe('Audit logging (Requirement 1.6)', () => {
    test('should record audit log for successful ingestion', async () => {
      const testData = Buffer.from('MZ\x90\x00\x03\x00\x00\x00')
      const base64Data = testData.toString('base64')

      await handler({ 
        bytes_b64: base64Data,
        source: 'test-source',
      })

      // Read audit log
      const auditLog = fs.readFileSync(auditLogPath, 'utf-8')
      const logLines = auditLog.trim().split('\n')
      
      expect(logLines.length).toBeGreaterThan(0)
      
      const lastLog = JSON.parse(logLines[logLines.length - 1])
      expect(lastLog.operation).toBe('sample.ingest')
      expect(lastLog.decision).toBe('allow')
      expect(lastLog.metadata.source).toBe('test-source')
      expect(lastLog.metadata.size).toBe(testData.length)
    })

    test('should record audit log for duplicate sample', async () => {
      const testData = Buffer.from('test data')
      const base64Data = testData.toString('base64')

      // First ingestion
      await handler({ bytes_b64: base64Data })
      
      // Second ingestion (duplicate)
      await handler({ bytes_b64: base64Data })

      // Read audit log
      const auditLog = fs.readFileSync(auditLogPath, 'utf-8')
      const logLines = auditLog.trim().split('\n')
      
      expect(logLines.length).toBe(2)
      
      const secondLog = JSON.parse(logLines[1])
      expect(secondLog.reason).toContain('already exists')
      expect(secondLog.metadata.existed).toBe(true)
    })
  })

  describe('Error handling', () => {
    test('should return error for non-existent file path', async () => {
      const result = await handler({ 
        path: '/non/existent/file.exe',
      })

      expect(result.ok).toBe(false)
      expect(result.errors).toBeDefined()
      expect(result.errors?.[0]).toContain('File not found')
    })

    test('should return error for invalid Base64', async () => {
      const result = await handler({ 
        bytes_b64: 'invalid-base64!!!',
      })

      expect(result.ok).toBe(false)
      expect(result.errors).toBeDefined()
      expect(result.errors?.[0]).toContain('Invalid Base64')
    })

    test('should return error when neither path nor bytes_b64 provided', async () => {
      const result = await handler({})

      expect(result.ok).toBe(false)
      expect(result.errors).toBeDefined()
      expect(result.errors?.[0]).toContain('provide `path`')
    })
  })

  describe('Upload URL compatibility', () => {
    test('should finalize an uploaded session from upload_url', async () => {
      const stagedData = Buffer.from('MZ\x90\x00\x03\x00\x00\x00')
      const stagedPath = path.join(testDir, 'staged-Weixin.dll')
      fs.writeFileSync(stagedPath, stagedData)

      const session = database.createUploadSession({
        filename: 'Weixin.dll',
        source: 'mcp_upload',
        expires_at: '2099-01-01T00:00:00.000Z',
      })
      database.markUploadSessionUploaded(session.token, {
        staged_path: stagedPath,
        size: stagedData.length,
        filename: 'Weixin.dll',
      })

      const result = await handler({
        upload_url: `http://localhost:18080/api/v1/uploads/${session.token}`,
      })
      const data = result.data as SampleIngestOutput['data']

      expect(result.ok).toBe(true)
      expect(data?.sample_id).toMatch(/^sha256:[a-f0-9]{64}$/)
      expect(data?.file_type).toBe('PE')
      expect(fs.existsSync(stagedPath)).toBe(false)

      const refreshed = database.findUploadSessionByToken(session.token)
      expect(refreshed?.status).toBe('registered')
      expect(refreshed?.sample_id).toBe(data?.sample_id)
    })

    test('should return existing sample for a registered upload session', async () => {
      const ingestResult = await handler({
        bytes_b64: Buffer.from('MZ\x90\x00\x03\x00\x00\x00').toString('base64'),
        filename: 'existing.exe',
      })
      const ingestData = ingestResult.data as SampleIngestOutput['data']

      const session = database.createUploadSession({
        filename: 'existing.exe',
        source: 'mcp_upload',
        expires_at: '2099-01-01T00:00:00.000Z',
      })
      database.markUploadSessionRegistered(session.token, {
        sample_id: ingestData?.sample_id as string,
        size: ingestData?.size,
        sha256: (ingestData?.sample_id as string).slice(7),
        md5: 'ignored',
      })

      const result = await handler({
        upload_url: `http://localhost:18080/api/v1/uploads/${session.token}`,
      })
      const data = result.data as SampleIngestOutput['data']

      expect(result.ok).toBe(true)
      expect(data?.sample_id).toBe(ingestData?.sample_id)
      expect(data?.existed).toBe(true)
    })

    test('should reject pending upload sessions that have no uploaded bytes', async () => {
      const session = database.createUploadSession({
        filename: 'pending.dll',
        source: 'mcp_upload',
        expires_at: '2099-01-01T00:00:00.000Z',
      })

      const result = await handler({
        upload_url: `http://localhost:18080/api/v1/uploads/${session.token}`,
      })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toContain('File not yet uploaded')
    })
  })

  describe('File type detection', () => {
    test('should detect PE file type', async () => {
      const peData = Buffer.from('MZ\x90\x00\x03\x00\x00\x00')
      const result = await handler({ 
        bytes_b64: peData.toString('base64'),
      })
      const data = result.data as SampleIngestOutput['data']

      expect(result.ok).toBe(true)
      expect(data?.file_type).toBe('PE')
    })

    test('should detect ELF file type', async () => {
      const elfData = Buffer.from('\x7FELF\x02\x01\x01\x00')
      const result = await handler({ 
        bytes_b64: elfData.toString('base64'),
      })
      const data = result.data as SampleIngestOutput['data']

      expect(result.ok).toBe(true)
      expect(data?.file_type).toBe('ELF')
    })

    test('should return unknown for unrecognized file type', async () => {
      const unknownData = Buffer.from('random data')
      const result = await handler({ 
        bytes_b64: unknownData.toString('base64'),
      })
      const data = result.data as SampleIngestOutput['data']

      expect(result.ok).toBe(true)
      expect(data?.file_type).toBe('unknown')
    })
  })
})
