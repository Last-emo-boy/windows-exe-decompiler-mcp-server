/**
 * Sample Upload API tests
 * Tasks: api-file-server 7.2
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import { StorageManager } from '../../src/storage/storage-manager.js'
import { DatabaseManager } from '../../src/database.js'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

describe('api-file-server - Sample Upload', () => {
  let storageManager: StorageManager
  let database: DatabaseManager
  let testDir: string

  beforeEach(async () => {
    testDir = path.join(__dirname, '..', 'temp', `upload-test-${Date.now()}`)
    fs.mkdirSync(testDir, { recursive: true })

    storageManager = new StorageManager({
      root: testDir,
      maxFileSize: 10 * 1024 * 1024,
      retentionDays: 30,
    })
    await storageManager.initialize()

    database = new DatabaseManager(':memory:')
    database.initialize()
  })

  afterEach(() => {
    database.close()
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true })
    }
  })

  describe('storeSample', () => {
    test('should store small sample successfully', async () => {
      const testData = Buffer.from('test sample content')
      const result = await storageManager.storeSample(testData, 'test.exe')

      expect(result.sha256).toBeDefined()
      expect(result.size).toBe(testData.length)
      expect(result.path).toContain('samples')
      expect(fs.existsSync(result.path)).toBe(true)
    })

    test('should store sample with date partitioning', async () => {
      const testData = Buffer.from('test')
      const result = await storageManager.storeSample(testData, 'test.exe')

      const today = new Date().toISOString().split('T')[0]
      expect(result.path).toContain(today)
    })

    test('should hash sample correctly', async () => {
      const testData = Buffer.from('test hash')
      const result = await storageManager.storeSample(testData, 'test.exe')

      // Verify hash is valid SHA256 (64 hex chars)
      expect(result.sha256).toMatch(/^[a-f0-9]{64}$/)
    })
  })

  describe('retrieveSample', () => {
    test('should retrieve stored sample', async () => {
      const testData = Buffer.from('test retrieve content')
      const stored = await storageManager.storeSample(testData, 'test.exe')
      const retrieved = await storageManager.retrieveSample(stored.sha256)

      expect(retrieved).not.toBeNull()
      expect(retrieved?.equals(testData)).toBe(true)
    })

    test('should handle concurrent retrievals', async () => {
      const testData = Buffer.from('test concurrent')
      const stored = await storageManager.storeSample(testData, 'test.exe')

      const [r1, r2, r3] = await Promise.all([
        storageManager.retrieveSample(stored.sha256),
        storageManager.retrieveSample(stored.sha256),
        storageManager.retrieveSample(stored.sha256),
      ])

      expect(r1?.equals(testData)).toBe(true)
      expect(r2?.equals(testData)).toBe(true)
      expect(r3?.equals(testData)).toBe(true)
    })
  })

  describe('upload session workflow', () => {
    test('should support complete upload workflow', async () => {
      // Step 1: Store sample
      const testData = Buffer.from('workflow test')
      const stored = await storageManager.storeSample(testData, 'workflow.exe')

      // Step 2: Create database record
      const sampleId = `sha256:${stored.sha256}`
      database.createSample({
        id: sampleId,
        sha256: stored.sha256,
        size: stored.size,
        created_at: new Date().toISOString(),
        source: 'api_upload',
      })

      // Step 3: Verify sample exists
      const sample = database.findSample(sampleId)
      expect(sample).toBeDefined()
      expect(sample?.sha256).toBe(stored.sha256)

      // Step 4: Verify file can be retrieved
      const retrieved = await storageManager.retrieveSample(stored.sha256)
      expect(retrieved).not.toBeNull()
    })
  })

  describe('error handling', () => {
    test('should reject oversized files', async () => {
      const testData = Buffer.alloc(11 * 1024 * 1024) // 11MB > 10MB limit
      await expect(storageManager.storeSample(testData, 'large.exe'))
        .rejects.toThrow('exceeds limit')
    })

    test('should return null for missing sample', async () => {
      const result = await storageManager.retrieveSample('sha256:nonexistent')
      expect(result).toBeNull()
    })
  })
})
