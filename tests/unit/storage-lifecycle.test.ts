/**
 * Storage lifecycle tests - simplified
 * Tasks: storage-lifecycle-and-batch-foundation 4.1, 4.2
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import { StorageManager } from '../../src/storage/storage-manager.js'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

describe('storage-lifecycle primitives', () => {
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

  describe('retrieveSample', () => {
    test('should retrieve stored sample by SHA256', async () => {
      const testData = Buffer.from('test sample data')
      const stored = await storageManager.storeSample(testData, 'test.exe')
      const retrieved = await storageManager.retrieveSample(stored.sha256)
      expect(retrieved).not.toBeNull()
      expect(retrieved?.equals(testData)).toBe(true)
    })

    test('should return null for non-existent sample', async () => {
      const result = await storageManager.retrieveSample('nonexistent')
      expect(result).toBeNull()
    })
  })

  describe('deleteSample', () => {
    test('should delete sample and return true', async () => {
      const testData = Buffer.from('test delete')
      const stored = await storageManager.storeSample(testData, 'delete.exe')
      const deleted = await storageManager.deleteSample(stored.sha256)
      expect(deleted).toBe(true)
      const retrieved = await storageManager.retrieveSample(stored.sha256)
      expect(retrieved).toBeNull()
    })

    test('should return false for non-existent sample', async () => {
      const result = await storageManager.deleteSample('nonexistent')
      expect(result).toBe(false)
    })
  })

  describe('deleteArtifact', () => {
    test('should delete artifact by path', async () => {
      const sampleId = 'test123'  // Use simple ID without sha256: prefix
      const artifactDir = path.join(testDir, 'artifacts', sampleId)
      fs.mkdirSync(artifactDir, { recursive: true })
      const artifactPath = path.join(artifactDir, 'test_artifact.json')
      fs.writeFileSync(artifactPath, JSON.stringify({ test: 'data' }))
      const deleted = await storageManager.deleteArtifact(artifactPath)
      expect(deleted).toBe(true)
      expect(fs.existsSync(artifactPath)).toBe(false)
    })

    test('should return false for non-existent artifact', async () => {
      const result = await storageManager.deleteArtifact('/nonexistent/path')
      expect(result).toBe(false)
    })
  })

  describe('getRetentionReport', () => {
    test('should generate retention report with buckets', async () => {
      await storageManager.storeSample(Buffer.from('test1'), 'test1.exe')
      await storageManager.storeSample(Buffer.from('test2'), 'test2.exe')
      const report = await storageManager.getRetentionReport()
      expect(report.buckets).toBeDefined()
      expect(report.buckets.length).toBe(3)
      expect(report.buckets.map(b => b.name)).toEqual(['active', 'recent', 'archive'])
    })
  })

  describe('applyRetention', () => {
    test('should perform dry-run cleanup', async () => {
      await storageManager.storeSample(Buffer.from('test'), 'test.exe')
      const result = await storageManager.applyRetention({ dryRun: true, maxAgeDays: 0 })
      expect(result.status).toBeDefined()
      expect(result.errors).toHaveLength(0)
    })
  })
})
