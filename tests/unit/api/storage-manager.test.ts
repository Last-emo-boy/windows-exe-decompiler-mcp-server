/**
 * Storage Manager tests
 * Tasks: api-file-server 7.3
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import { StorageManager } from '../../src/storage/storage-manager.js'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

describe('api-file-server - Storage Manager', () => {
  let storageManager: StorageManager
  let testDir: string

  beforeEach(async () => {
    testDir = path.join(__dirname, '..', 'temp', `storage-test-${Date.now()}`)
    fs.mkdirSync(testDir, { recursive: true })

    storageManager = new StorageManager({
      root: testDir,
      maxFileSize: 10 * 1024 * 1024,
      retentionDays: 30,
    })
    await storageManager.initialize()
  })

  afterEach(() => {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true })
    }
  })

  describe('storeSample', () => {
    test('should store sample and return metadata', async () => {
      const testData = Buffer.from('test sample data')
      const result = await storageManager.storeSample(testData, 'test.exe')

      expect(result.sha256).toBeDefined()
      expect(result.size).toBe(testData.length)
      expect(result.path).toContain('samples')
    })

    test('should reject oversized files', async () => {
      const testData = Buffer.alloc(11 * 1024 * 1024) // 11MB
      await expect(storageManager.storeSample(testData, 'large.exe'))
        .rejects.toThrow('exceeds limit')
    })
  })

  describe('retrieveSample', () => {
    test('should retrieve stored sample', async () => {
      const testData = Buffer.from('test retrieve')
      const stored = await storageManager.storeSample(testData, 'test.exe')
      const retrieved = await storageManager.retrieveSample(stored.sha256)

      expect(retrieved).not.toBeNull()
      expect(retrieved?.equals(testData)).toBe(true)
    })

    test('should return null for missing sample', async () => {
      const result = await storageManager.retrieveSample('nonexistent')
      expect(result).toBeNull()
    })
  })

  describe('deleteSample', () => {
    test('should delete sample', async () => {
      const testData = Buffer.from('test delete')
      const stored = await storageManager.storeSample(testData, 'test.exe')
      
      const deleted = await storageManager.deleteSample(stored.sha256)
      expect(deleted).toBe(true)

      const retrieved = await storageManager.retrieveSample(stored.sha256)
      expect(retrieved).toBeNull()
    })
  })

  describe('getRetentionReport', () => {
    test('should generate report with buckets', async () => {
      await storageManager.storeSample(Buffer.from('test1'), 'test1.exe')
      const report = await storageManager.getRetentionReport()

      expect(report.buckets).toHaveLength(3)
      expect(report.buckets.map(b => b.name)).toEqual(['active', 'recent', 'archive'])
    })
  })

  describe('applyRetention', () => {
    test('should perform dry-run cleanup', async () => {
      await storageManager.storeSample(Buffer.from('test'), 'test.exe')
      const result = await storageManager.applyRetention({
        dryRun: true,
        maxAgeDays: 0,
      })

      expect(result.status).toBeDefined()
      expect(result.errors).toHaveLength(0)
    })
  })
})
